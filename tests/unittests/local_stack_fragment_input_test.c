#if TEST_PACKETS_TO_CONNECTION
#include "PacketsToConnection/structure.h"
typedef ptc_tstate_t test_state_t;
#else
#include "ConnectionToPackets/structure.h"
typedef ctp_tstate_t test_state_t;
#endif

static const bool ptc = TEST_PACKETS_TO_CONNECTION != 0;

#include "loggers/internal_logger.h"
#include "loggers/network_logger.h"
#include "lwip_test_runtime.h"
#include "wchecksum.h"
#include "worker_registry_fixture.h"

#include "lwip/tcpip.h"

#include <sys/wait.h>

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "local_stack_fragment_input_test: %s\n", message);
        exit(2);
    }
}

static atomic_bool lwip_ready;

static void lwipReady(void *arg)
{
    discard arg;
    frandInit();
    atomicStoreExplicit(&lwip_ready, true, memory_order_release);
}

/* Each child owns a fresh runtime; no live lwIP thread is inherited by fork. */
static void runInput(uint16_t fragments, uint8_t protocol, bool shifted, uint32_t length)
{
    require(createNetworkLogger(NULL, true) != NULL, "logger creation failed");
    require(createInternalLogger(NULL, true) != NULL, "internal logger creation failed");
    require(lwipTestRuntimeInitialize(), "lwIP random runtime initialization failed");
    checkSumInit();
    atomic_init(&lwip_ready, false);
    tcpip_init(lwipReady, NULL);
    while (! atomicLoadExplicit(&lwip_ready, memory_order_acquire))
        YIELD_THREAD();

    master_pool_t *large  = masterpoolCreateWithCapacity(8);
    master_pool_t *medium = masterpoolCreateWithCapacity(8);
    master_pool_t *small  = masterpoolCreateWithCapacity(8);
    master_pool_t *splice = masterpoolCreateWithCapacity(8);
    buffer_pool_t *pool   = bufferpoolCreate(large, medium, small, splice, 8, 4096, 2048, 1024, 4096, 4096);
    require(pool != NULL, "buffer pool creation failed");
    buffer_pool_t *pools[]          = {pool};
    GSTATE.workers_count            = 2;
    GSTATE.shortcut_buffer_pools    = pools;
    test_worker_registry_t registry = {0};
    testWorkerRegistryInstall(&registry);
    testWorkerBindWID(0);

    line_t         line           = {.wid = 0, .alive = true, .recalculate_checksum = true};
    line_t        *packet_lines[] = {&line};
    tunnel_chain_t chain          = {.workers_count = 1, .contains_packet_node = true, .packet_lines = packet_lines};
    tunnel_t      *t              = tunnelCreate(NULL, sizeof(test_state_t), 0);
    require(t != NULL, "tunnel creation failed");
    t->chain            = &chain;
    test_state_t *state = tunnelGetState(t);
    atomic_init(&state->stopping, false);
#if ! TEST_PACKETS_TO_CONNECTION
    quiescenceGateInit(&state->packet_ingress_gate);
    require(quiescenceGateOpen(&state->packet_ingress_gate), "input gate did not open");
#endif

    sbuf_t *buf = bufferpoolGetSmallBuffer(pool);
    sbufSetLength(buf, 28U + (shifted ? 1U : 0U));
    if (shifted)
        sbufShiftRight(buf, 1);
    uint8_t *packet = sbufGetMutablePtr(buf);
    memoryZero(packet, 28);
    packet[0] = 0x45;
    packet[8] = 64;
    packet[9] = protocol;
    PUT_BE16(packet + 2, 28);
    PUT_BE16(packet + 6, fragments);
    PUT_BE32(packet + 12, UINT32_C(0x0a000001));
    PUT_BE32(packet + 16, UINT32_C(0x0a000002));
    sbufSetLength(buf, length);

#if TEST_PACKETS_TO_CONNECTION
    ptcTunnelUpStreamPayload(t, &line, buf);
#else
    ctpTunnelDownStreamPayload(t, &line, buf);
#endif

    require(! line.recalculate_checksum && lineIsAlive(&line), "packet-line state was not preserved");
    tunnelDestroy(t);
    testWorkerUnbindWID();
    testWorkerRegistryRestore(&registry);
    GSTATE.shortcut_buffer_pools = NULL;
    GSTATE.workers_count         = 0;
    bufferpoolDestroy(pool);
    master_pool_t *masters[] = {large, medium, small, splice};
    for (size_t i = 0; i < ARRAY_SIZE(masters); ++i)
    {
        masterpoolMakeEmpty(masters[i]);
        masterpoolDestroy(masters[i]);
    }
    require(wwLwipShutdown(), "lwIP shutdown failed");
    lwipTestRuntimeCleanup();
    networkloggerDestroy();
    internaloggerDestroy();
}

static void checkInput(uint16_t fragments, uint8_t protocol, bool shifted, uint32_t length, bool fatal)
{
    int logs[2];
    require(pipe(logs) == 0, "log pipe creation failed");
    pid_t child = fork();
    require(child >= 0, "fork failed");
    if (child == 0)
    {
        close(logs[0]);
        require(dup2(logs[1], STDERR_FILENO) >= 0, "stderr redirection failed");
        close(logs[1]);
        runInput(fragments, protocol, shifted, length);
        _Exit(0);
    }
    close(logs[1]);
    char    output[8192];
    size_t  used = 0;
    ssize_t received;
    while ((received = read(logs[0], output + used, sizeof(output) - 1U - used)) > 0)
        used += (size_t) received;
    output[used] = '\0';
    close(logs[0]);
    int status;
    require(waitpid(child, &status, 0) == child, "waitpid failed");
    if (! WIFEXITED(status) || WEXITSTATUS(status) != (fatal ? 1 : 0))
    {
        fprintf(stderr,
                "%s input flags=%04x protocol=%u length=%u: %s\n",
                ptc ? "PTC" : "CTP",
                fragments,
                protocol,
                length,
                output);
        require(false, "unexpected packet-input exit status");
    }
    if (fatal)
    {
        require(strstr(output, ptc ? "PacketsToConnection:" : "ConnectionToPackets:") != NULL,
                "fatal diagnostic did not name the consumer");
        require(strstr(output, "received an IPv4 fragment") != NULL &&
                    strstr(output, "enable reassembly at packet ingress") != NULL,
                "fragment rejection did not explain the input contract and remedy");
    }
}

int main(void)
{
    const uint16_t fragments[] = {IP_MF, 1, IP_MF | 1, IP_DF | IP_MF};
    for (size_t i = 0; i < ARRAY_SIZE(fragments); ++i)
    {
        checkInput(fragments[i], IP_PROTO_TCP, false, 28, true);
        checkInput(fragments[i], IP_PROTO_UDP, true, 28, true);
    }
    // Unsupported protocols cannot bypass the fragment-input contract.
    checkInput(IP_MF, IP_PROTO_ICMP, false, 28, true);
    // Ordinary/DF-only ICMP takes the existing unsupported-protocol drop.
    checkInput(0, IP_PROTO_ICMP, false, 28, false);
    checkInput(IP_DF, IP_PROTO_ICMP, true, 28, false);
    checkInput(IP_MF, IP_PROTO_UDP, true, 19, false);
    checkInput(IP_MF, IP_PROTO_UDP, false, 0, false);
    puts("Local-stack fragment-input tests passed");
    return 0;
}

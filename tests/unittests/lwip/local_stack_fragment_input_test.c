/*
 * Covers: local stack fragment input; the explicit inputs, callbacks and expected results below define
 * this suite.
 * Setup: Real runtime/component code with the explicit worker/line/neighbour fixture and any linker
 * seams shown below. Line and buffer settlement remains the scenario owner's responsibility.
 * Cases: checkInput
 * Checks: Assertion labels include: logger creation failed; internal logger creation failed; lwIP random
 * runtime initialization failed; buffer pool creation failed
 * Limits: Platform/feature branches remain conditional. Component fixtures do not establish host-network
 * or application-throughput behavior.
 * CTest: waterwall.connectiontopackets_fragment_input_unit;
 * waterwall.packetstoconnection_fragment_input_unit
 */
#if TEST_PACKETS_TO_CONNECTION
#include "PacketsToConnection/structure.h"
typedef ptc_tstate_t test_state_t;
#else
#include "ConnectionToPackets/structure.h"
typedef ctp_tstate_t test_state_t;
#endif

static const bool ptc = TEST_PACKETS_TO_CONNECTION != 0;

static unsigned recycled;
static unsigned recycled_with_request;
void            __real_bufferpoolReuseBuffer(buffer_pool_t *pool, sbuf_t *buf);
void            __wrap_bufferpoolReuseBuffer(buffer_pool_t *pool, sbuf_t *buf);
void            __wrap_bufferpoolReuseBuffer(buffer_pool_t *pool, sbuf_t *buf)
{
    ++recycled;
    recycled_with_request += sbufGetRecalculateChecksum(buf);
    __real_bufferpoolReuseBuffer(pool, buf);
}

#include "fixtures/lwip/lwip_test_runtime.h"
#include "fixtures/worker_registry_fixture.h"
#include "loggers/internal_logger.h"
#include "loggers/network_logger.h"
#include "wchecksum.h"

#include "lwip/tcpip.h"

#include <sys/wait.h>

/* This child uses status 2 to distinguish a fixture failure from product exit 1. */

#include "test_assert.h"

#define require(condition, message)                                                                                    \
    do                                                                                                                 \
    {                                                                                                                  \
        if (! TEST_CHECK(condition, message))                                                                          \
            exit(2);                                                                                                   \
    } while (0)

/* Each child owns a fresh runtime; no live worker thread is inherited by fork. */
static void runInput(uint16_t fragments, uint8_t protocol, bool shifted, uint32_t length)
{
    require(createNetworkLogger(NULL, true) != NULL, "logger creation failed");
    require(createInternalLogger(NULL, true) != NULL, "internal logger creation failed");
    require(lwipTestRuntimeInitialize(), "lwIP random runtime initialization failed");
    checkSumInit();
    master_pool_t *large  = masterpoolCreateWithCapacity(8);
    master_pool_t *medium = masterpoolCreateWithCapacity(8);
    master_pool_t *small  = masterpoolCreateWithCapacity(8);
    master_pool_t *splice = masterpoolCreateWithCapacity(8);
    buffer_pool_t *pool   = bufferpoolCreate(large, medium, small, 8, 4096, 2048, 1024, 4096, 4096);
    require(pool != NULL, "buffer pool creation failed");
    buffer_pool_t *pools[]          = {pool};
    GSTATE.workers_count            = 1;
    GSTATE.shortcut_buffer_pools    = pools;
    test_worker_registry_t registry = {0};
    testWorkerRegistryInstall(&registry);
    testWorkerBindWID(0);

    line_t         line           = {.wid = 0, .alive = true};
    line_t        *packet_lines[] = {&line};
    tunnel_chain_t chain          = {.workers_count = 1, .contains_packet_node = true, .packet_lines = packet_lines};
    tunnel_t      *t              = tunnelCreate(NULL, sizeof(test_state_t), 0);
    require(t != NULL, "tunnel creation failed");
    t->chain            = &chain;
    test_state_t *state = tunnelGetState(t);
    atomic_init(&state->stopping, false);
    atomic_init(&state->fragment_drops, 0);
#if ! TEST_PACKETS_TO_CONNECTION
    state->handoff_budget = ctpHandoffBudgetCreate(kCtpHandoffMaxBytes, kCtpHandoffMaxEntries);
    require(state->handoff_budget != NULL, "budget creation failed");
    IP4_ADDR(&state->source_ip, 10, 0, 0, 2);
    quiescenceGateInit(&state->packet_ingress_gate);
    require(quiescenceGateOpen(&state->packet_ingress_gate), "input gate did not open");
#endif

    recycled = 0;
    recycled_with_request = 0;
    for (unsigned repeat = 0; repeat < 2; ++repeat)
    {
        sbuf_t *buf = bufferpoolGetSmallBuffer(pool);
        sbufSetRecalculateChecksum(buf, repeat == 0);
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

    require(lineIsAlive(&line), "packet-line state was not preserved");
    }
    require(recycled >= 2, "rejected packets retained their input buffers");
    require(recycled_with_request == 0, "rejected packets retained checksum requests at recycling");
#if ! TEST_PACKETS_TO_CONNECTION
    require(state->handoff_budget->bytes == 0 && state->handoff_budget->entries == 0,
            "rejected input retained its copy");
    quiescenceGateClose(&state->packet_ingress_gate);
    require(quiescenceGateIsClosedAndQuiesced(&state->packet_ingress_gate), "input gate was not settled");
    ctpHandoffBudgetDetach(state->handoff_budget);
#endif
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

static void checkInput(uint16_t fragments, uint8_t protocol, bool shifted, uint32_t length)
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
    if (! WIFEXITED(status) || WEXITSTATUS(status) != 0)
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
    const char *first = strstr(output, "dropping unsupported IPv4 fragments");
    require(first == NULL || strstr(first + 1, "dropping unsupported IPv4 fragments") == NULL,
            "fragment diagnostics were not limited to the first drop");
}

int main(void)
{
    testCaseSet("local_stack_fragment_input_test");
    const uint16_t fragments[] = {IP_MF, 1, IP_MF | 1, IP_DF | IP_MF};
    for (size_t i = 0; i < ARRAY_SIZE(fragments); ++i)
    {
        checkInput(fragments[i], IP_PROTO_TCP, false, 28);
        checkInput(fragments[i], IP_PROTO_UDP, true, 28);
    }
    // Unsupported protocols and irrelevant destinations must also be harmless.
    checkInput(IP_MF, IP_PROTO_ICMP, false, 28);
    // Ordinary/DF-only ICMP takes the existing unsupported-protocol drop.
    checkInput(0, IP_PROTO_ICMP, false, 28);
    checkInput(IP_DF, IP_PROTO_ICMP, true, 28);
    checkInput(IP_MF, IP_PROTO_UDP, true, 19);
    checkInput(IP_MF, IP_PROTO_UDP, false, 0);
    puts("Local-stack fragment-input tests passed");
    return 0;
}

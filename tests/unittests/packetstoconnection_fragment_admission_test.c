#include "PacketsToConnection/structure.h"

#include "devices/device_reader_session.h"
#include "lwip_test_runtime.h"
#include "worker_registry_fixture.h"

#include "lwip/tcpip.h"

#include <pthread.h>

typedef struct test_env_s
{
    master_pool_t         *large_master;
    master_pool_t         *small_master;
    master_pool_t         *medium_master;
    master_pool_t         *splice_master;
    buffer_pool_t         *worker_pool;
    buffer_pool_t         *buffer_pools[1];
    wloop_t               *loops[1];
    test_worker_registry_t worker_registry;
} test_env_t;

typedef struct input_probe_s
{
    unsigned int input_calls;
} input_probe_t;

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "%s\n", message);
        exit(1);
    }
}
static unsigned recycled;
void            __real_bufferpoolReuseBuffer(buffer_pool_t *pool, sbuf_t *buf);
void            __wrap_bufferpoolReuseBuffer(buffer_pool_t *pool, sbuf_t *buf);
void __wrap_bufferpoolReuseBuffer(buffer_pool_t *pool, sbuf_t *buf)
{
    ++recycled;
    __real_bufferpoolReuseBuffer(pool, buf);
}
static struct pbuf *retained;
static err_t        captureInput(struct pbuf *p, struct netif *inp)
{
    input_probe_t *probe = inp->state;
    ++probe->input_calls;
    require(((uintptr_t) p->payload % MEM_ALIGNMENT) == 0, "stack payload not aligned");
    retained = p;
    return ERR_OK;
}
static void writeIpv4Checksum(uint8_t *packet)
{
    uint32_t sum = 0;
    PUT_BE16(packet + 10, 0);
    for (uint32_t offset = 0; offset < 20; offset += 2)
    {
        sum += GET_BE16(packet + offset);
    }
    while ((sum >> 16U) != 0)
    {
        sum = (sum & UINT32_C(0xFFFF)) + (sum >> 16U);
    }
    PUT_BE16(packet + 10, (uint16_t) ~sum);
}

static void fillFragment(sbuf_t *buf, uint16_t identification, bool shifted)
{
    enum
    {
        kPayloadBytes = 64,
        kPacketBytes  = 20 + kPayloadBytes,
    };

    sbufSetLength(buf, kPacketBytes + (shifted ? 1U : 0U));
    if (shifted)
    {
        sbufShiftRight(buf, 1);
    }

    uint8_t *packet = sbufGetMutablePtr(buf);
    memoryZero(packet, kPacketBytes);
    packet[0] = 0x45;
    packet[8] = 64;
    packet[9] = IP_PROTO_UDP;
    PUT_BE16(packet + 2, kPacketBytes);
    PUT_BE16(packet + 4, identification);
    PUT_BE16(packet + 6, UINT16_C(0x2000));
    PUT_BE32(packet + 12, UINT32_C(0x0A000001));
    PUT_BE32(packet + 16, UINT32_C(0xC0000201));
    PUT_BE16(packet + 20, 5900);
    PUT_BE16(packet + 22, 53);
    writeIpv4Checksum(packet);
}

static void testStorage(test_env_t *env, bool shifted, bool fail_copy, bool fail_wrapper)
{
    input_probe_t probe = {0};
    struct netif  netif = {.input = captureInput, .state = &probe};
    sbuf_t       *buf   = bufferpoolGetSmallBuffer(env->worker_pool);
    fillFragment(buf, 42, shifted);
    ptc_fragment_admission_test_hooks_t hooks = {.fail_aligned_copy          = fail_copy,
                                                 .fail_rx_wrapper_allocation = fail_wrapper};
    ptcFragmentAdmissionTestInstallHooks(&hooks);
    recycled = 0;
    retained = NULL;
    LOCK_TCPIP_CORE();
    ptcFragmentAdmissionTestSubmitPacketToStack(buf, &netif);
    if (fail_copy || fail_wrapper)
        require(probe.input_calls == 0 && recycled == 1, "refusal leaked or delivered");
    else
    {
        require(probe.input_calls == 1 && retained != NULL, "packet not retained by stack");
        require(recycled == (unsigned) shifted, "storage freed before pbuf release");
        pbuf_free(retained);
        retained = NULL;
        require(recycled == 1U + (unsigned) shifted, "pbuf failed exactly-once storage release");
    }
    UNLOCK_TCPIP_CORE();
    ptcFragmentAdmissionTestInstallHooks(NULL);
}
static void envSetup(test_env_t *env)
{
    memoryZero(env, sizeof(*env));
    env->large_master = masterpoolCreateWithCapacity(16);
    env->small_master = masterpoolCreateWithCapacity(16);
    env->medium_master = masterpoolCreateWithCapacity(16);
    env->splice_master = masterpoolCreateWithCapacity(16);
    env->worker_pool   = bufferpoolCreate(env->large_master,
                                        env->medium_master,
                                        env->small_master,
                                        env->splice_master,
                                        16,
                                        4096,
                                        MEDIUM_BUFFER_SIZE_RAM_HIGH,
                                        1024);
    require(env->large_master != NULL && env->small_master != NULL && env->worker_pool != NULL,
            "failed to create fragment-admission test pools");

    env->buffer_pools[0]                 = env->worker_pool;
    env->loops[0]                        = (wloop_t *) (void *) env;
    GSTATE.workers_count                 = 2;
    GSTATE.shortcut_buffer_pools         = env->buffer_pools;
    GSTATE.shortcut_loops                = env->loops;
    GSTATE.masterpool_buffer_pools_large = env->large_master;
    GSTATE.masterpool_buffer_pools_small = env->small_master;
    GSTATE.masterpool_buffer_pools_medium = env->medium_master;
    GSTATE.masterpool_buffer_pools_splice = env->splice_master;
    testWorkerRegistryInstall(&env->worker_registry);
    testWorkerBindWID(0);
}

static void envTeardown(test_env_t *env)
{
    testWorkerUnbindWID();
    GSTATE.shortcut_buffer_pools         = NULL;
    GSTATE.shortcut_loops                = NULL;
    GSTATE.masterpool_buffer_pools_large = NULL;
    GSTATE.masterpool_buffer_pools_small = NULL;
    GSTATE.masterpool_buffer_pools_medium = NULL;
    GSTATE.masterpool_buffer_pools_splice = NULL;
    GSTATE.workers_count                 = 0;
    testWorkerRegistryRestore(&env->worker_registry);

    bufferpoolDestroy(env->worker_pool);
    masterpoolMakeEmpty(env->large_master);
    masterpoolMakeEmpty(env->small_master);
    masterpoolMakeEmpty(env->medium_master);
    masterpoolMakeEmpty(env->splice_master);
    masterpoolDestroy(env->large_master);
    masterpoolDestroy(env->small_master);
    masterpoolDestroy(env->medium_master);
    masterpoolDestroy(env->splice_master);
}

static atomic_bool lwip_initialized;

static void lwipInitialized(void *argument)
{
    discard argument;
    frandInit();
    atomicStoreExplicit(&lwip_initialized, true, memory_order_release);
}

int main(void)
{
    require(lwipTestRuntimeInitialize(), "failed to initialize the lwIP random runtime");
    atomic_init(&lwip_initialized, false);
    tcpip_init(lwipInitialized, NULL);
    while (! atomicLoadExplicit(&lwip_initialized, memory_order_acquire))
    {
        YIELD_THREAD();
    }
    ptcRxWrapperPoolInitializeOnce();

    test_env_t env;
    envSetup(&env);
    testStorage(&env, false, false, false);
    testStorage(&env, true, false, false);
    testStorage(&env, true, true, false);
    testStorage(&env, false, false, true);
    envTeardown(&env);

    require(wwLwipShutdown(), "failed to shut down the fragment-admission lwIP thread");
    lwipTestRuntimeCleanup();
    puts("PacketsToConnection fragment-admission tests passed");
    return 0;
}

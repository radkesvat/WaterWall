/*
 * Covers: tundevice writer refusal log; the explicit inputs, callbacks and expected results below define
 * this suite.
 * Setup: Real runtime/component code with the explicit worker/line/neighbour fixture and any linker
 * seams shown below. Line and buffer settlement remains the scenario owner's responsibility.
 * Cases: envSetup, fillValidIpv4, countLogSubstring, envTeardown
 * Checks: Assertion labels include: TunDevice: lower write refusal; TunDevice: Write failed! worker;
 * TunDevice wrapper did not recycle the refused buffer exactly once
 * Limits: Platform/feature branches remain conditional. Component fixtures do not establish host-network
 * or application-throughput behavior.
 * CTest: waterwall.tundevice_writer_refusal_log_unit
 */
#include "TunDevice/structure.h"

#include "test_assert.h"

#define require(condition, message) TEST_REQUIRE(TEST_FAILURE_EXIT, condition, message)

#include "devices/tun/tun.h"
#include "fixtures/worker_registry_fixture.h"
#include "loggers/network_logger.h"

enum
{
    kLogCaptureCapacity = 4096
};

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

static char           log_capture[kLogCaptureCapacity];
static size_t         log_capture_len;
static buffer_pool_t *tracked_pool;
static sbuf_t        *tracked_buffer;
static unsigned int   tracked_reuse_count;

void __real_bufferpoolReuseBuffer(buffer_pool_t *pool, sbuf_t *buf);
void __wrap_bufferpoolReuseBuffer(buffer_pool_t *pool, sbuf_t *buf);


static void captureLog(int log_level, const char *buf, int len)
{
    discard log_level;
    if (buf == NULL || len <= 0 || log_capture_len >= sizeof(log_capture) - 1U)
    {
        return;
    }

    const size_t copy_len = min((size_t) len, sizeof(log_capture) - log_capture_len - 1U);
    memoryCopy(log_capture + log_capture_len, buf, copy_len);
    log_capture_len += copy_len;
    log_capture[log_capture_len] = '\0';
}

static unsigned int countLogSubstring(const char *needle)
{
    unsigned int count  = 0;
    const char  *match  = log_capture;
    const size_t length = strlen(needle);

    while ((match = strstr(match, needle)) != NULL)
    {
        ++count;
        match += length;
    }
    return count;
}

void __wrap_bufferpoolReuseBuffer(buffer_pool_t *pool, sbuf_t *buf)
{
    if (pool == tracked_pool && buf == tracked_buffer)
    {
        ++tracked_reuse_count;
    }
    __real_bufferpoolReuseBuffer(pool, buf);
}

/* Lower-layer stand-ins: this test is about the tunnel wrapper's ownership and
 * logging contract, not an OS-specific TUN implementation. */
bool tundeviceIsUp(const tun_device_t *tdev)
{
    return tdev != NULL;
}

bool tundeviceWrite(tun_device_t *tdev, sbuf_t *buf)
{
    discard tdev;
    discard buf;
    LOGW("TunDevice: lower write refusal");
    return false;
}

static void fillValidIpv4(sbuf_t *buf)
{
    enum
    {
        kPacketBytes = 28
    };

    sbufSetLength(buf, kPacketBytes);
    uint8_t *packet = sbufGetMutablePtr(buf);
    memoryZero(packet, kPacketBytes);
    packet[0] = 0x45;
    packet[8] = 64;
    packet[9] = IP_PROTO_UDP;
    PUT_BE16(packet + 2, kPacketBytes);
    PUT_BE32(packet + 12, UINT32_C(0x0A000001));
    PUT_BE32(packet + 16, UINT32_C(0xC0000201));
    PUT_BE16(packet + 20, 5900);
    PUT_BE16(packet + 22, 53);
    PUT_BE16(packet + 24, 8);
}

static void envSetup(test_env_t *env)
{
    memoryZero(env, sizeof(*env));
    env->large_master = masterpoolCreateWithCapacity(8);
    env->small_master = masterpoolCreateWithCapacity(8);
    env->medium_master = masterpoolCreateWithCapacity(8);
    env->splice_master = masterpoolCreateWithCapacity(8);
    env->worker_pool   = bufferpoolCreate(env->large_master,
                                        env->medium_master,
                                        env->small_master,
                                        env->splice_master,
                                        8,
                                        1024,
                                        MEDIUM_BUFFER_SIZE_RAM_HIGH,
                                        256,
                                        1024,
                                        1024);
    require(env->large_master != NULL && env->small_master != NULL && env->worker_pool != NULL,
            "failed to create test pools");

    env->buffer_pools[0]                 = env->worker_pool;
    env->loops[0]                        = (wloop_t *) (void *) env;
    GSTATE.workers_count                  = 1;
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

int main(void)
{
    testCaseSet("tundevice_writer_refusal_log_test");
    test_env_t env;
    envSetup(&env);

    logger_t *logger = loggerCreate();
    require(logger != NULL, "failed to create network logger");
    loggerSetHandler(logger, captureLog);
    setNetworkLogger(logger);

    tunnel_t *tunnel = tunnelCreate(NULL, sizeof(tundevice_tstate_t), 0);
    line_t   *line   = memoryAllocateZero(sizeof(*line));
    require(tunnel != NULL && line != NULL, "failed to allocate tunnel wrapper fixture");
    line->wid = 0;

    int                 dummy_tun_device;
    tundevice_tstate_t *state = tunnelGetState(tunnel);
    state->tdev               = (tun_device_t *) &dummy_tun_device;

    sbuf_t *buf = bufferpoolGetSmallBuffer(env.worker_pool);
    fillValidIpv4(buf);
    tracked_pool        = env.worker_pool;
    tracked_buffer      = buf;
    tracked_reuse_count = 0;

    tundeviceTunnelWritePayload(tunnel, line, buf);

    require(countLogSubstring("TunDevice: lower write refusal") == 1,
            "lower-layer refusal diagnostic was not emitted exactly once");
    require(countLogSubstring("TunDevice: Write failed! worker") == 0,
            "TunDevice wrapper duplicated a lower-layer refusal diagnostic");
    require(tracked_reuse_count == 1, "TunDevice wrapper did not recycle the refused buffer exactly once");

    tracked_pool   = NULL;
    tracked_buffer = NULL;
    memoryFree(line);
    tunnelDestroy(tunnel);
    networkloggerDestroy();
    envTeardown(&env);
    puts("TunDevice writer refusal logging tests passed");
    return 0;
}

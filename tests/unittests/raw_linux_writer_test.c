#include "wwapi.h"

#include "devices/raw/raw.h"
#include "devices/raw/raw_linux_internal.h"
#include "devices/raw/raw_linux_send_policy.h"

#include "worker_registry_fixture.h"
#include <netinet/ip.h>
#include <poll.h>
#include <pthread.h>
#include <sys/socket.h>
#include <unistd.h>

/*
 * Fake worker table for the stubbed GSTATE below. Without it the identity
 * predicates correctly report "not an event worker" and the checked
 * current-worker accessors reject this test.
 */
static test_worker_registry_t g_test_worker_registry;

typedef struct test_env_s
{
    master_pool_t *large_master;
    master_pool_t *small_master;
    buffer_pool_t *worker_buffer_pool;
    buffer_pool_t *buffer_pools[1];
} test_env_t;

typedef struct writer_probe_s
{
    raw_device_t *rdev;
    sbuf_t      **buffers;
    unsigned int  buffer_count;
    atomic_bool   start;
    atomic_bool   running;
    atomic_uint   next_buffer;
    atomic_uint   started;
    atomic_uint   attempts;
} writer_probe_t;

typedef struct consumer_probe_s
{
    sbuf_t     **buffers;
    unsigned int buffer_capacity;
    atomic_uint  buffer_count;
} consumer_probe_t;

typedef struct recycling_probe_s
{
    atomic_uint consumed;
} recycling_probe_t;

static bool fail_next_thread_join;

int __real_pthread_join(pthread_t thread, void **retval);
int __wrap_pthread_join(pthread_t thread, void **retval);
int __wrap_pthread_join(pthread_t thread, void **retval)
{
    if (fail_next_thread_join)
    {
        fail_next_thread_join = false;
        return EBUSY;
    }
    return __real_pthread_join(thread, retval);
}

int            __real_sendmmsg(int socket_fd, struct mmsghdr *messages, unsigned int message_count, int flags);
int            __wrap_sendmmsg(int socket_fd, struct mmsghdr *messages, unsigned int message_count, int flags);
int            __real_poll(struct pollfd *fds, nfds_t count, int timeout_ms);
int            __wrap_poll(struct pollfd *fds, nfds_t count, int timeout_ms);
bool           __wrap_requestProgramShutdown(int exit_code);
_Noreturn void __wrap_abortProgramNow(int exit_code);

enum
{
    kInjectedRawSocketFd = 7001,
    kMaxInjectedSends    = 16,
    kUnexpectedAbortExit = 77
};

typedef struct injected_send_result_s
{
    int result;
    int error;
} injected_send_result_t;

typedef enum injected_poll_result_e
{
    kInjectedPollReady = 0,
    kInjectedPollInvalid
} injected_poll_result_t;

static injected_send_result_t injected_sends[kMaxInjectedSends];
static unsigned int           injected_send_count;
static atomic_uint            observed_send_calls;
static injected_poll_result_t injected_poll_result;
static atomic_bool            allow_injected_send;
static atomic_uint            shutdown_request_calls;
static atomic_int             shutdown_request_last_code;

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "FAIL: %s\n", message);
        exit(1);
    }
}

int __wrap_sendmmsg(int socket_fd, struct mmsghdr *messages, unsigned int message_count, int flags)
{
    if (socket_fd != kInjectedRawSocketFd)
    {
        return __real_sendmmsg(socket_fd, messages, message_count, flags);
    }

    discard messages;
    discard flags;

    while (! atomicLoadExplicit(&allow_injected_send, memory_order_acquire))
    {
        YIELD_THREAD();
    }

    unsigned int call = atomicAddExplicit(&observed_send_calls, 1, memory_order_relaxed);
    require(call < injected_send_count, "raw writer made an unarmed sendmmsg() call");

    const injected_send_result_t entry = injected_sends[call];
    if (entry.result < 0)
    {
        errno = entry.error;
        return -1;
    }

    require((unsigned int) entry.result <= message_count, "injected sendmmsg() result exceeded its batch");
    return entry.result;
}

int __wrap_poll(struct pollfd *fds, nfds_t count, int timeout_ms)
{
    if (count != 1 || fds[0].fd != kInjectedRawSocketFd)
    {
        return __real_poll(fds, count, timeout_ms);
    }

    discard timeout_ms;
    if (injected_poll_result == kInjectedPollInvalid)
    {
        fds[0].revents = POLLNVAL;
        return 1;
    }

    fds[0].revents = POLLOUT;
    return 1;
}

bool __wrap_requestProgramShutdown(int exit_code)
{
    atomicAddExplicit(&shutdown_request_calls, 1, memory_order_relaxed);
    atomicStoreRelaxed(&shutdown_request_last_code, exit_code);
    return true;
}

_Noreturn void __wrap_abortProgramNow(int exit_code)
{
    fprintf(stderr, "FAIL: raw writer reached abortProgramNow(%d)\n", exit_code);
    _Exit(kUnexpectedAbortExit);
}

static void resetFailureInjection(void)
{
    memoryZero(injected_sends, sizeof(injected_sends));
    injected_send_count  = 0;
    injected_poll_result = kInjectedPollReady;
    atomicStoreRelaxed(&allow_injected_send, false);
    atomicStoreRelaxed(&observed_send_calls, 0);
    atomicStoreRelaxed(&shutdown_request_calls, 0);
    atomicStoreRelaxed(&shutdown_request_last_code, 0);
}

static void armInjectedSends(const injected_send_result_t *results, unsigned int count)
{
    require(count <= ARRAY_SIZE(injected_sends), "too many injected raw send results");
    memoryCopy(injected_sends, results, count * sizeof(results[0]));
    injected_send_count = count;
}

static void envSetup(test_env_t *env)
{
    env->large_master       = masterpoolCreateWithCapacity(16);
    env->small_master       = masterpoolCreateWithCapacity(16);
    env->worker_buffer_pool = bufferpoolCreate(env->large_master, env->small_master, 16, 8192, 4096);
    env->buffer_pools[0]    = env->worker_buffer_pool;

    GSTATE.flag_initialized = true;
    GSTATE.workers_count    = 2;
    testWorkerRegistryInstall(&g_test_worker_registry);
    GSTATE.shortcut_buffer_pools = env->buffer_pools;
    GSTATE.ram_profile           = 1;
    testWorkerBindWID(0);
}

static void envTeardown(test_env_t *env)
{
    testWorkerUnbindWID();
    GSTATE.flag_initialized = false;
    GSTATE.workers_count    = 0;
    testWorkerRegistryRestore(&g_test_worker_registry);
    GSTATE.shortcut_buffer_pools = NULL;
    bufferpoolDestroy(env->worker_buffer_pool);
    masterpoolMakeEmpty(env->large_master);
    masterpoolMakeEmpty(env->small_master);
    masterpoolDestroy(env->large_master);
    masterpoolDestroy(env->small_master);
}

static WTHREAD_ROUTINE(testWriterRoutine)
{
    raw_device_t     *rdev  = userdata;
    consumer_probe_t *probe = rdev->userdata;
    sbuf_t           *buf;
    struct wchan_s   *writer_channel = deviceWriterChannelGetConsumerChannel(&rdev->writer_channel);

    while (rawLifecycleIsActive(rawLifecycleLoad(&rdev->lifecycle)))
    {
        if (! chanRecv(writer_channel, &buf))
        {
            break;
        }
        const unsigned int index = atomicAddExplicit(&probe->buffer_count, 1, memory_order_relaxed);
        require(index < probe->buffer_capacity, "raw writer consumed more buffers than the test allocated");
        probe->buffers[index] = buf;
    }
    return 0;
}

static WTHREAD_ROUTINE(recyclingWriterRoutine)
{
    raw_device_t      *rdev           = userdata;
    recycling_probe_t *probe          = rdev->userdata;
    struct wchan_s    *writer_channel = deviceWriterChannelGetConsumerChannel(&rdev->writer_channel);
    sbuf_t            *buf;

    while (rawLifecycleIsActive(rawLifecycleLoad(&rdev->lifecycle)))
    {
        if (! chanRecv(writer_channel, &buf))
        {
            break;
        }

        /*
         * The queued buffer proves the write reached this generation. Probe the
         * writer-owned pool separately so its debug accounting remains paired.
         */
        sbufDestroy(buf);
        sbuf_t *pool_probe = bufferpoolGetSmallBuffer(rdev->writer_buffer_pool);
        bufferpoolReuseBuffer(rdev->writer_buffer_pool, pool_probe);
        atomicAddExplicit(&probe->consumed, 1, memory_order_release);
    }
    return 0;
}

static void *senderRoutine(void *userdata)
{
    writer_probe_t *probe = userdata;
    atomicAddExplicit(&probe->started, 1, memory_order_release);

    while (! atomicLoadExplicit(&probe->start, memory_order_acquire))
    {
        YIELD_THREAD();
    }

    while (atomicLoadExplicit(&probe->running, memory_order_acquire))
    {
        const unsigned int index = atomicAddExplicit(&probe->next_buffer, 1, memory_order_relaxed);
        if (index >= probe->buffer_count)
        {
            break;
        }

        sbuf_t *buf = probe->buffers[index];
        if (rawdeviceWrite(probe->rdev, buf))
        {
            probe->buffers[index] = NULL;
        }
        atomicAddExplicit(&probe->attempts, 1, memory_order_release);
    }
    return NULL;
}

static void testRawBringDownQuiescesConcurrentWriters(test_env_t *env)
{
    resetFailureInjection();

    enum
    {
        kWriterThreads = 4,
        kWriterBuffers = 2048
    };

    raw_device_t rdev;
    memoryZero(&rdev, sizeof(rdev));
    sbuf_t          *consumed_buffers[kWriterBuffers];
    consumer_probe_t consumer = {
        .buffers         = consumed_buffers,
        .buffer_capacity = ARRAY_SIZE(consumed_buffers),
    };
    rdev.name               = stringDuplicate("raw-writer-test");
    rdev.writer_buffer_pool = bufferpoolCreate(env->large_master, env->small_master, 16, 8192, 4096);
    rdev.routine_writer     = testWriterRoutine;
    rdev.userdata           = &consumer;
    atomic_init(&rdev.lifecycle, kRawLifecycleDown);
    deviceWriterChannelInit(&rdev.writer_channel);

    require(rawdeviceBringUp(&rdev), "production rawdeviceBringUp failed");

    sbuf_t *buffers[kWriterBuffers];
    for (unsigned int i = 0; i < ARRAY_SIZE(buffers); i++)
    {
        buffers[i] = bufferpoolGetSmallBuffer(rdev.writer_buffer_pool);
        sbufSetLength(buffers[i], sizeof(struct iphdr) + 1);
    }

    writer_probe_t probe = {
        .rdev         = &rdev,
        .buffers      = buffers,
        .buffer_count = ARRAY_SIZE(buffers),
        .start        = false,
        .running      = true,
    };
    pthread_t threads[kWriterThreads];
    for (unsigned int i = 0; i < ARRAY_SIZE(threads); i++)
    {
        require(pthread_create(&threads[i], NULL, senderRoutine, &probe) == 0, "failed to create a raw writer thread");
    }

    while (atomicLoadExplicit(&probe.started, memory_order_acquire) < ARRAY_SIZE(threads))
    {
        YIELD_THREAD();
    }
    atomicStoreExplicit(&probe.start, true, memory_order_release);
    while (atomicLoadExplicit(&probe.attempts, memory_order_acquire) < ARRAY_SIZE(threads))
    {
        YIELD_THREAD();
    }

    require(rawdeviceBringDown(&rdev), "production rawdeviceBringDown failed");
    atomicStoreExplicit(&probe.running, false, memory_order_release);
    for (unsigned int i = 0; i < ARRAY_SIZE(threads); i++)
    {
        require(pthread_join(threads[i], NULL) == 0, "failed to join a raw writer thread");
    }

    sbuf_t *after_down = bufferpoolGetSmallBuffer(rdev.writer_buffer_pool);
    sbufSetLength(after_down, sizeof(struct iphdr) + 1);
    require(! rawdeviceWrite(&rdev, after_down), "rawdeviceWrite accepted a buffer after bring-down");
    bufferpoolReuseBuffer(rdev.writer_buffer_pool, after_down);

    for (unsigned int i = 0; i < ARRAY_SIZE(buffers); i++)
    {
        if (buffers[i] != NULL)
        {
            bufferpoolReuseBuffer(rdev.writer_buffer_pool, buffers[i]);
        }
    }
    const unsigned int consumed_count = atomicLoadExplicit(&consumer.buffer_count, memory_order_acquire);
    for (unsigned int i = 0; i < consumed_count; i++)
    {
        bufferpoolReuseBuffer(rdev.writer_buffer_pool, consumed_buffers[i]);
    }

    require(deviceWriterChannelDestroy(&rdev.writer_channel), "failed to destroy retired raw writer generations");
    require(atomicLoadRelaxed(&shutdown_request_calls) == 0, "normal raw writer stop requested process shutdown");
    memoryFree(rdev.name);
    bufferpoolDestroy(rdev.writer_buffer_pool);
}

static void testRawJoinFailureRetainsOwnership(test_env_t *env)
{
    resetFailureInjection();

    raw_device_t rdev;
    memoryZero(&rdev, sizeof(rdev));
    sbuf_t          *consumed_buffers[1];
    consumer_probe_t consumer = {
        .buffers         = consumed_buffers,
        .buffer_capacity = ARRAY_SIZE(consumed_buffers),
    };
    rdev.name               = stringDuplicate("raw-join-retry-test");
    rdev.writer_buffer_pool = bufferpoolCreate(env->large_master, env->small_master, 16, 8192, 4096);
    rdev.routine_writer     = testWriterRoutine;
    rdev.userdata           = &consumer;
    atomic_init(&rdev.lifecycle, kRawLifecycleDown);
    deviceWriterChannelInit(&rdev.writer_channel);

    require(rawdeviceBringUp(&rdev), "raw join-retry bring-up failed");
    fail_next_thread_join = true;
    require(! rawdeviceBringDown(&rdev), "injected raw writer join failure reported success");
    require(rdev.writer_joinable, "raw writer join failure discarded thread ownership");
    require(deviceWriterChannelHasCurrent(&rdev.writer_channel),
            "raw writer join failure retired a generation still owned by the thread");
    require(! rawdeviceBringUp(&rdev), "raw writer restarted while failed-join ownership remained");

    require(rawdeviceBringDown(&rdev), "raw writer join retry failed");
    require(! rdev.writer_joinable, "raw writer join retry retained thread ownership");
    require(! deviceWriterChannelHasCurrent(&rdev.writer_channel),
            "raw writer join retry did not retire its closed generation");

    require(deviceWriterChannelDestroy(&rdev.writer_channel), "failed to destroy raw join-retry generations");
    require(atomicLoadRelaxed(&shutdown_request_calls) == 0, "raw writer join retry requested process shutdown");
    memoryFree(rdev.name);
    bufferpoolDestroy(rdev.writer_buffer_pool);
}

static void testRawRestartTransfersWriterPoolOwnership(test_env_t *env)
{
    resetFailureInjection();

    raw_device_t      rdev;
    recycling_probe_t probe = {0};
    memoryZero(&rdev, sizeof(rdev));

    rdev.name               = stringDuplicate("raw-pool-restart-test");
    rdev.writer_buffer_pool = bufferpoolCreate(env->large_master, env->small_master, 16, 8192, 4096);
    rdev.routine_writer     = recyclingWriterRoutine;
    rdev.userdata           = &probe;
    atomic_init(&rdev.lifecycle, kRawLifecycleDown);
    deviceWriterChannelInit(&rdev.writer_channel);

    for (unsigned int generation = 0; generation < 2; generation++)
    {
        require(rawdeviceBringUp(&rdev), "raw pool-owner generation failed to start");

        sbuf_t *buf = sbufCreateWithPadding(4096, 0);
        sbufSetLength(buf, sizeof(struct iphdr) + 1);
        require(rawdeviceWrite(&rdev, buf), "raw pool-owner generation rejected its test write");

        const unsigned int expected = generation + 1;
        for (unsigned int spin = 0;
             spin < 1000000 && atomicLoadExplicit(&probe.consumed, memory_order_acquire) < expected;
             spin++)
        {
            YIELD_THREAD();
        }
        require(atomicLoadExplicit(&probe.consumed, memory_order_acquire) == expected,
                "raw pool-owner generation did not recycle its write");
        require(rawdeviceBringDown(&rdev), "raw pool-owner generation failed to stop");
    }

    require(deviceWriterChannelDestroy(&rdev.writer_channel), "failed to destroy raw pool-owner generations");
    require(atomicLoadRelaxed(&shutdown_request_calls) == 0, "normal raw writer restart requested process shutdown");
    memoryFree(rdev.name);
    bufferpoolDestroy(rdev.writer_buffer_pool);
}

static void productionWriterDeviceInit(raw_device_t *rdev, test_env_t *env, const char *name)
{
    memoryZero(rdev, sizeof(*rdev));
    rdev->name               = stringDuplicate(name);
    rdev->socket             = kInjectedRawSocketFd;
    rdev->routine_writer     = rawLinuxWriteRoutine;
    rdev->writer_buffer_pool = bufferpoolCreate(env->large_master, env->small_master, 16, 8192, 4096);
    atomic_init(&rdev->lifecycle, kRawLifecycleDown);
    deviceWriterChannelInit(&rdev->writer_channel);
}

static void productionWriterDeviceDestroy(raw_device_t *rdev)
{
    require(rawLifecycleLoad(&rdev->lifecycle) == kRawLifecycleDown,
            "destroying a raw writer test device that is not down");
    require(! rdev->writer_joinable, "destroying a raw writer test device with an unjoined writer");
    require(! deviceWriterChannelHasCurrent(&rdev->writer_channel),
            "destroying a raw writer test device with a current queue generation");
    require(deviceWriterChannelDestroy(&rdev->writer_channel), "failed to destroy raw writer test queue generations");
    memoryFree(rdev->name);
    bufferpoolDestroy(rdev->writer_buffer_pool);
}

static void queueRawPackets(raw_device_t *rdev, test_env_t *env, unsigned int count)
{
    for (unsigned int i = 0; i < count; i++)
    {
        sbuf_t *buf = bufferpoolGetSmallBuffer(env->worker_buffer_pool);
        sbufSetLength(buf, sizeof(struct iphdr) + 1);
        memoryZero(sbufGetMutablePtr(buf), sbufGetLength(buf));
        require(rawdeviceWrite(rdev, buf), "failed to queue a raw writer failure-injection packet");
    }
}

static void waitForRawWriterFailure(raw_device_t *rdev)
{
    for (unsigned int spin = 0; spin < 1000000; spin++)
    {
        if (rawLifecycleLoad(&rdev->lifecycle) == kRawLifecycleFailed && atomicLoadRelaxed(&shutdown_request_calls) > 0)
        {
            return;
        }
        YIELD_THREAD();
    }
    require(false, "timed out waiting for the raw writer to publish failure");
}

/*
 * Recoverable and packet-local failures must advance to later packets, while
 * the first unknown/terminal failure ends the writer and requests teardown.
 * The sequence deliberately reaches every branch before EBADF; swallowing
 * EBADF would make one more unarmed sendmmsg() call and fail in the wrapper.
 */
static void testRawSendErrorPolicyEndsOnTerminalFailure(test_env_t *env)
{
    resetFailureInjection();

    const injected_send_result_t sends[] = {
        {.result = -1, .error = EINTR},
        {.result = -1, .error = EAGAIN},
        {.result = -1, .error = ENOBUFS},
        {.result = -1, .error = ENOMEM},
        {.result = -1, .error = EMSGSIZE},
        {.result = -1, .error = EINVAL},
        {.result = -1, .error = EHOSTUNREACH},
        {.result = -1, .error = EBADF},
    };
    armInjectedSends(sends, ARRAY_SIZE(sends));

    raw_device_t rdev;
    productionWriterDeviceInit(&rdev, env, "raw-send-error-test");
    require(rawdeviceBringUp(&rdev), "raw send-error test device failed to start");
    queueRawPackets(&rdev, env, 8);
    atomicStoreExplicit(&allow_injected_send, true, memory_order_release);

    waitForRawWriterFailure(&rdev);
    require(! rawdeviceIsUp(&rdev), "terminal sendmmsg() failure left the raw device up");
    require(rawLifecycleLoad(&rdev.lifecycle) == kRawLifecycleFailed,
            "terminal sendmmsg() failure did not publish FAILED");
    require(atomicLoadRelaxed(&observed_send_calls) == ARRAY_SIZE(sends),
            "raw send-error policy stopped before or continued beyond the terminal error");
    require(atomicLoadRelaxed(&shutdown_request_calls) == 1,
            "terminal sendmmsg() failure did not request exactly one shutdown");
    require(atomicLoadRelaxed(&shutdown_request_last_code) == 1,
            "terminal sendmmsg() failure requested the wrong exit code");

    sbuf_t *after_failure = bufferpoolGetSmallBuffer(env->worker_buffer_pool);
    sbufSetLength(after_failure, sizeof(struct iphdr) + 1);
    require(! rawdeviceWrite(&rdev, after_failure), "raw writer accepted a packet after publishing FAILED");
    bufferpoolReuseBuffer(env->worker_buffer_pool, after_failure);

    require(rawdeviceBringDown(&rdev), "bring-down after terminal sendmmsg() failure failed");
    require(rdev.discard_log_limiter.total == 5, "recoverable raw send errors recorded the wrong discard total");
    require(rdev.transient_send_error_total == 2, "raw resource-pressure discard accounting is wrong");
    require(rdev.message_too_large_packet_total == 1, "raw EMSGSIZE discard accounting is wrong");
    require(rdev.packet_local_send_error_total == 2, "raw packet-local discard accounting is wrong");
    productionWriterDeviceDestroy(&rdev);
}

/*
 * EAGAIN delegates to poll(). A dead descriptor is reported through POLLNVAL,
 * not writability, and must end the writer instead of re-entering sendmmsg().
 */
static void testRawPollTerminalEventFailsTheDevice(test_env_t *env)
{
    resetFailureInjection();

    const injected_send_result_t sends[] = {{.result = -1, .error = EAGAIN}};
    armInjectedSends(sends, ARRAY_SIZE(sends));
    injected_poll_result = kInjectedPollInvalid;

    raw_device_t rdev;
    productionWriterDeviceInit(&rdev, env, "raw-poll-error-test");
    require(rawdeviceBringUp(&rdev), "raw poll-error test device failed to start");
    queueRawPackets(&rdev, env, 2);
    atomicStoreExplicit(&allow_injected_send, true, memory_order_release);

    waitForRawWriterFailure(&rdev);
    require(atomicLoadRelaxed(&observed_send_calls) == 1, "raw writer retried sendmmsg() after a terminal poll event");
    require(rawLifecycleLoad(&rdev.lifecycle) == kRawLifecycleFailed,
            "terminal raw writer poll event did not publish FAILED");
    require(atomicLoadRelaxed(&shutdown_request_calls) == 1,
            "terminal raw writer poll event did not request one shutdown");

    require(rawdeviceBringDown(&rdev), "bring-down after a terminal raw writer poll event failed");
    productionWriterDeviceDestroy(&rdev);
}

static void testRawLinuxSendErrorClassifier(void)
{
    require(rawLinuxClassifySendError(EINTR) == kRawLinuxSendRetryImmediately,
            "EINTR was not classified as an immediate retry");
    require(rawLinuxClassifySendError(EAGAIN) == kRawLinuxSendWaitWritable,
            "EAGAIN was not classified as wait-for-writable");
    require(rawLinuxClassifySendError(ENOBUFS) == kRawLinuxSendDiscardPacket,
            "ENOBUFS was not classified as a transient packet discard");
    require(rawLinuxClassifySendError(EINVAL) == kRawLinuxSendDiscardPacket,
            "EINVAL was not classified as a packet-local discard");
    require(rawLinuxClassifySendError(EMSGSIZE) == kRawLinuxSendDiscardPacket,
            "EMSGSIZE was not classified as a packet-local discard");
    require(rawLinuxClassifySendError(EHOSTUNREACH) == kRawLinuxSendDiscardPacket,
            "EHOSTUNREACH was not classified as a destination-local discard");
    require(rawLinuxClassifySendError(EPERM) == kRawLinuxSendDiscardPacket,
            "EPERM was not classified as a packet-policy discard");
    require(rawLinuxClassifySendError(EBADF) == kRawLinuxSendTerminal, "EBADF was not classified as terminal");
    require(rawLinuxClassifySendError(EIO) == kRawLinuxSendTerminal,
            "an unknown raw send error was not classified as terminal");
}

int main(void)
{
    test_env_t env;
    envSetup(&env);
    testRawLinuxSendErrorClassifier();
    testRawBringDownQuiescesConcurrentWriters(&env);
    testRawJoinFailureRetainsOwnership(&env);
    testRawRestartTransfersWriterPoolOwnership(&env);
    testRawSendErrorPolicyEndsOnTerminalFailure(&env);
    testRawPollTerminalEventFailsTheDevice(&env);
    envTeardown(&env);
    puts("Linux raw writer lifetime tests passed");
    return 0;
}

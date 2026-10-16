/*
 * Covers: Linux raw output batching, worker ownership, partial writes, deferred
 * retries, error policy, NOTRACK lifecycle, stop/restart and late cancellation.
 * Setup: Production raw-device and writer code with captured worker messages,
 * injected sendmmsg results, and exact buffer settlement observations.
 * Limits: No privileged socket or firewall access; native integration covers
 * actual kernel injection. This fixture makes no performance claims.
 * CTest: waterwall.raw_linux_writer_unit
 */
#include "devices/raw/raw_linux_internal.h"
#include "devices/raw/raw_linux_send_policy.h"
#include "fixtures/worker_registry_fixture.h"
#include "loggers/internal_logger.h"
#include "test_assert.h"
#include "worker_messages.h"
#include "wwapi.h"

#include <netinet/ip.h>
#include <poll.h>
#include <pthread.h>
#include <sys/socket.h>
#include <unistd.h>

#define require(condition, message) TEST_REQUIRE(TEST_FAILURE_EXIT, condition, message)

enum
{
    kInjectedRawSocketFd = 7001,
    kMaxCapturedMessages = 128,
    kMaxInjectedSends    = 32,
    kMaxTrackedBuffers   = 1024,
    kLogCaptureCapacity  = 8192
};

typedef struct test_env_s
{
    master_pool_t         *large_master;
    master_pool_t         *small_master;
    master_pool_t         *medium_master;
    buffer_pool_t         *buffer_pools[2];
    wloop_t               *loops[2];
    test_worker_registry_t registry;
} test_env_t;

typedef struct captured_message_s
{
    wid_t                        wid;
    uint32_t                     delay_ms;
    WorkerMessageCallback        callback;
    WorkerMessageCleanupCallback cleanup;
    void                        *arg1;
    void                        *arg2;
    void                        *arg3;
} captured_message_t;

typedef struct injected_send_s
{
    int      result;
    int      error;
    unsigned count;
    unsigned first_id;
} injected_send_t;

typedef struct tracked_buffer_s
{
    sbuf_t  *buffer;
    wid_t    owner;
    unsigned settled;
    unsigned recycled;
} tracked_buffer_t;

static test_env_t          *test_env;
static captured_message_t   messages[kMaxCapturedMessages];
static unsigned             message_count, message_head;
static injected_send_t      sends[kMaxInjectedSends];
static unsigned             send_count, send_calls;
static unsigned             poll_calls, poll_not_ready;
static short                poll_events = POLLOUT;
static tracked_buffer_t     buffers[kMaxTrackedBuffers];
static unsigned             buffer_count;
static thread_local sbuf_t *recycling_buffer;
static bool                 fail_next_notrack_install, fail_next_notrack_remove;
static unsigned             notrack_removals, shutdown_calls;
static int                  shutdown_code;
static bool                 shutdown_accepts = true, expect_abort;
static char                 log_capture[kLogCaptureCapacity];
static size_t               log_capture_len;
static atomic_bool          block_send, entered_send, release_send, close_requested, close_finished;

int                            __wrap_sendmmsg(int fd, struct mmsghdr *batch, unsigned count, int flags);
int                            __wrap_poll(struct pollfd *fds, nfds_t count, int timeout_ms);
bool                           __wrap_rawLinuxNotrackInstall(raw_device_t *rdev);
bool                           __wrap_rawLinuxNotrackRemove(raw_device_t *rdev);
bool                           __wrap_requestProgramShutdown(int code);
_Noreturn void                 __wrap_abortProgramNow(int code);
void                           __real_bufferpoolReuseBuffer(buffer_pool_t *pool, sbuf_t *buffer);
void                           __wrap_bufferpoolReuseBuffer(buffer_pool_t *pool, sbuf_t *buffer);
void                           __real_sbufDestroy(sbuf_t *buffer);
void                           __wrap_sbufDestroy(sbuf_t *buffer);
worker_message_submit_result_e __wrap_sendWorkerMessageForceQueueWithCleanup(wid_t wid, WorkerMessageCallback callback,
                                                                             WorkerMessageCleanupCallback cleanup,
                                                                             void *arg1, void *arg2, void *arg3);
worker_message_submit_result_e __wrap_sendWorkerMessageTimedWithCleanup(wid_t wid, WorkerMessageCallback callback,
                                                                        WorkerMessageCleanupCallback cleanup,
                                                                        uint32_t delay_ms, void *arg1, void *arg2,
                                                                        void *arg3);

static worker_message_submit_result_e captureMessage(wid_t wid, WorkerMessageCallback callback,
                                                     WorkerMessageCleanupCallback cleanup, uint32_t delay_ms,
                                                     void *arg1, void *arg2, void *arg3)
{
    require(message_count < ARRAY_SIZE(messages), "raw retry did not yield or exceeded the bounded fixture");
    messages[message_count++] = (captured_message_t) {wid, delay_ms, callback, cleanup, arg1, arg2, arg3};
    return kWorkerMessageSubmitAccepted;
}

worker_message_submit_result_e __wrap_sendWorkerMessageForceQueueWithCleanup(wid_t wid, WorkerMessageCallback callback,
                                                                             WorkerMessageCleanupCallback cleanup,
                                                                             void *arg1, void *arg2, void *arg3)
{
    return captureMessage(wid, callback, cleanup, 0, arg1, arg2, arg3);
}

worker_message_submit_result_e __wrap_sendWorkerMessageTimedWithCleanup(wid_t wid, WorkerMessageCallback callback,
                                                                        WorkerMessageCleanupCallback cleanup,
                                                                        uint32_t delay_ms, void *arg1, void *arg2,
                                                                        void *arg3)
{
    require(delay_ms == 1, "raw EAGAIN retry did not use its bounded event delay");
    return captureMessage(wid, callback, cleanup, delay_ms, arg1, arg2, arg3);
}

static void runMessage(captured_message_t message)
{
    testWorkerBindWID(message.wid);
    message.callback(&GSTATE.workers[message.wid], message.arg1, message.arg2, message.arg3);
    testWorkerBindWID(0);
}

static captured_message_t takeMessage(void)
{
    require(message_head < message_count, "raw output lost its deferred flush");
    return messages[message_head++];
}

static void runAllMessages(void)
{
    while (message_head < message_count)
        runMessage(takeMessage());
}

static void cancelAllMessages(void)
{
    testWorkerUnbindWID();
    while (message_head < message_count)
    {
        captured_message_t message = takeMessage();
        message.cleanup(message.arg1, message.arg2, message.arg3, kWorkerMessageCancelTeardown);
    }
    testWorkerBindWID(0);
}

static void recordSettlement(sbuf_t *buffer, buffer_pool_t *pool)
{
    for (unsigned i = buffer_count; i > 0; --i)
    {
        tracked_buffer_t *tracked = &buffers[i - 1];
        if (tracked->buffer != buffer)
            continue;
        require(++tracked->settled == 1, "raw output settled a buffer more than once");
        if (pool != NULL)
        {
            require(pool == test_env->buffer_pools[tracked->owner], "raw output borrowed another worker's pool");
            require(currentThreadIsEventWorkerWID(tracked->owner), "raw output recycled outside its worker");
            tracked->recycled++;
        }
        return;
    }
}

void __wrap_bufferpoolReuseBuffer(buffer_pool_t *pool, sbuf_t *buffer)
{
    recordSettlement(buffer, pool);
    recycling_buffer = buffer;
    __real_bufferpoolReuseBuffer(pool, buffer);
    recycling_buffer = NULL;
}

void __wrap_sbufDestroy(sbuf_t *buffer)
{
    if (buffer != recycling_buffer)
        recordSettlement(buffer, NULL);
    __real_sbufDestroy(buffer);
}

int __wrap_sendmmsg(int fd, struct mmsghdr *batch, unsigned count, int flags)
{
    require(fd == kInjectedRawSocketFd, "raw send used an unexpected socket");
    require((flags & MSG_DONTWAIT) != 0, "raw worker issued a potentially blocking send");
    require(count > 0 && count <= 512, "raw output exceeded its 512-packet native batch");
    require(send_calls < send_count, "raw output made an unarmed sendmmsg call");
    const injected_send_t expected = sends[send_calls++];
    require(count == expected.count, "raw partial/retry batch lost its exact unsent suffix");
    for (unsigned i = 0; i < count; ++i)
    {
        require(batch[i].msg_hdr.msg_iovlen == 1, "raw packet lost its single original payload span");
        const struct iovec *iov    = batch[i].msg_hdr.msg_iov;
        const uint8_t      *packet = iov->iov_base;
        require(GET_BE16(packet + 4) == expected.first_id + i, "raw output reordered or replayed a packet");
        require(GET_BE16(packet + 2) == iov->iov_len, "raw writer changed packet length");
        const struct sockaddr_in *destination = batch[i].msg_hdr.msg_name;
        require(destination->sin_family == AF_INET && destination->sin_addr.s_addr == htonl(INADDR_LOOPBACK),
                "raw output changed packet destination");
        bool found = false;
        for (unsigned j = 0; j < buffer_count; ++j)
            if (buffers[j].settled == 0 && sbufGetRawPtr(buffers[j].buffer) == packet)
                found = true;
        require(found, "raw send copied payload or referenced an already-settled buffer");
    }
    if (atomicLoadExplicit(&block_send, memory_order_acquire))
    {
        atomicStoreExplicit(&entered_send, true, memory_order_release);
        while (! atomicLoadExplicit(&release_send, memory_order_acquire))
            YIELD_THREAD();
    }
    if (expected.result < 0)
    {
        errno = expected.error;
        return -1;
    }
    require((unsigned) expected.result <= count, "injected raw send consumed beyond its batch");
    return expected.result;
}

int __wrap_poll(struct pollfd *fds, nfds_t count, int timeout_ms)
{
    require(count == 1 && fds[0].fd == kInjectedRawSocketFd && fds[0].events == POLLOUT,
            "raw retry polled an unexpected descriptor");
    require(timeout_ms == 0, "raw event worker waited in poll");
    ++poll_calls;
    if (poll_not_ready != 0)
    {
        --poll_not_ready;
        fds[0].revents = 0;
        return 0;
    }
    fds[0].revents = poll_events;
    return 1;
}

bool __wrap_rawLinuxNotrackInstall(raw_device_t *rdev)
{
    require(rdev->writer.current == NULL, "NOTRACK was installed after writer publication");
    if (! rdev->bypass_conntrack)
        return true;
    rdev->notrack_rule_pending = true;
    const bool result          = ! fail_next_notrack_install;
    fail_next_notrack_install  = false;
    return result;
}

bool __wrap_rawLinuxNotrackRemove(raw_device_t *rdev)
{
    if (! rdev->notrack_rule_pending)
        return true;
    require(rdev->writer.current == NULL, "NOTRACK was removed before output quiesced");
    ++notrack_removals;
    if (fail_next_notrack_remove)
    {
        fail_next_notrack_remove = false;
        return false;
    }
    rdev->notrack_rule_pending = false;
    return true;
}

bool __wrap_requestProgramShutdown(int code)
{
    ++shutdown_calls;
    shutdown_code = code;
    return shutdown_accepts;
}

_Noreturn void __wrap_abortProgramNow(int code)
{
    fprintf(stderr, "%s: raw abortProgramNow(%d)\n", expect_abort ? "expected fallback" : "FAIL", code);
    _Exit(expect_abort ? 77 : 78);
}

static void captureLog(int level, const char *text, int length)
{
    discard level;
    if (text == NULL || length <= 0)
        return;
    const size_t copy = min((size_t) length, sizeof(log_capture) - log_capture_len - 1);
    memoryCopy(log_capture + log_capture_len, text, copy);
    log_capture_len += copy;
    log_capture[log_capture_len] = 0;
}

static void resetLogCapture(void)
{
    log_capture_len = 0;
    log_capture[0]  = 0;
}

static unsigned countLogSubstring(const char *needle)
{
    unsigned count = 0;
    for (const char *match = log_capture; (match = strstr(match, needle)) != NULL; match += strlen(needle))
        ++count;
    return count;
}

static void resetFixture(void)
{
    require(message_head == message_count, "previous raw fixture retained an unsettled message");
    message_head = message_count = send_count = send_calls = buffer_count = shutdown_calls = 0;
    fail_next_notrack_install = fail_next_notrack_remove = false;
    shutdown_accepts                                     = true;
    poll_calls = poll_not_ready = 0;
    poll_events                 = POLLOUT;
    atomicStoreRelaxed(&block_send, false);
    atomicStoreRelaxed(&entered_send, false);
    atomicStoreRelaxed(&release_send, false);
    atomicStoreRelaxed(&close_requested, false);
    atomicStoreRelaxed(&close_finished, false);
    resetLogCapture();
}

static void armSends(const injected_send_t *expected, unsigned count)
{
    require(count <= ARRAY_SIZE(sends), "too many injected raw sends");
    memoryCopy(sends, expected, count * sizeof(*expected));
    send_count = count;
}

static void deviceInit(raw_device_t *rdev, const char *name)
{
    *rdev = (raw_device_t) {.name = stringDuplicate(name), .socket = kInjectedRawSocketFd};
    atomic_init(&rdev->lifecycle, kRawLifecycleDown);
    rawWriterInit(&rdev->writer);
}

static void deviceDestroy(raw_device_t *rdev)
{
    require(rawLifecycleLoad(&rdev->lifecycle) == kRawLifecycleDown, "raw fixture destroyed before bring-down");
    rawWriterDestroy(&rdev->writer);
    memoryFree(rdev->name);
    for (unsigned i = 0; i < buffer_count; ++i)
        require(buffers[i].settled == 1, "raw output leaked an accepted buffer");
}

static sbuf_t *packetCreate(unsigned id, wid_t owner, unsigned length)
{
    require(buffer_count < ARRAY_SIZE(buffers), "raw fixture exceeded buffer ledger");
    sbuf_t *buffer = sbufCreate(length);
    sbufSetLength(buffer, length);
    uint8_t *packet = sbufGetMutablePtr(buffer);
    memoryZero(packet, length);
    packet[0] = 0x45;
    packet[8] = 64;
    packet[9] = 253;
    PUT_BE16(packet + 2, length);
    PUT_BE16(packet + 4, id);
    PUT_BE32(packet + 12, INADDR_LOOPBACK);
    PUT_BE32(packet + 16, INADDR_LOOPBACK);
    buffers[buffer_count++] = (tracked_buffer_t) {.buffer = buffer, .owner = owner};
    return buffer;
}

static void queuePacket(raw_device_t *rdev, unsigned id, wid_t owner, unsigned length)
{
    testWorkerBindWID(owner);
    require(rawdeviceWrite(rdev, packetCreate(id, owner, length)), "raw fixture enqueue failed");
    testWorkerBindWID(0);
}

static void testHeaderOnlyAndBatchLimit(void)
{
    for (unsigned count = 1; count <= 513; count += 512)
    {
        resetFixture();
        raw_device_t rdev;
        deviceInit(&rdev, "raw-batching");
        require(rawdeviceBringUp(&rdev), "raw batch device failed to start");
        const injected_send_t expected[] = {{(int) min(count, 512U), 0, min(count, 512U), 0}, {1, 0, 1, 512}};
        armSends(expected, count == 1 ? 1 : 2);
        for (unsigned i = 0; i < count; ++i)
            queuePacket(&rdev, i, 0, sizeof(struct iphdr));
        require(send_calls == 0 && message_count == 1, "raw enqueue performed native I/O or failed coalescing");
        runAllMessages();
        require(send_calls == send_count, "raw 512-packet batch limit did not preserve native batching");
        for (unsigned i = 0; i < count; ++i)
            require(buffers[i].recycled == 1, "raw worker did not recycle through its existing pool");
        require(rawdeviceBringDown(&rdev), "raw batch stop failed");
        deviceDestroy(&rdev);
    }
}

static void testPartialAndBlockedFifo(void)
{
    resetFixture();
    raw_device_t rdev;
    deviceInit(&rdev, "raw-partial-retry");
    require(rawdeviceBringUp(&rdev), "raw partial fixture start failed");
    const injected_send_t expected[] = {{2, 0, 5, 0}, {-1, EAGAIN, 3, 2}, {3, 0, 3, 2}, {2, 0, 2, 5}};
    armSends(expected, ARRAY_SIZE(expected));
    for (unsigned i = 0; i < 5; ++i)
        queuePacket(&rdev, i, 0, 21);
    runMessage(takeMessage());
    require(send_calls == 1 && buffers[0].settled == 1 && buffers[1].settled == 1 && buffers[2].settled == 0,
            "partial send did not settle exactly its sent prefix");
    runMessage(takeMessage());
    require(send_calls == 2 && buffers[2].settled == 0 && message_count - message_head == 1 &&
                messages[message_head].delay_ms == 1,
            "EAGAIN dropped its unsent suffix or retried without yielding");
    queuePacket(&rdev, 5, 0, 21);
    queuePacket(&rdev, 6, 0, 21);
    require(message_count - message_head == 1, "new input bypassed the pending EAGAIN retry");
    poll_not_ready = 1;
    runMessage(takeMessage());
    require(send_calls == 2 && poll_calls == 1 && messages[message_head].delay_ms == 1 && buffers[2].settled == 0,
            "unwritable socket spun, lost output, or retried without yielding");
    runAllMessages();
    require(send_calls == 4 && poll_calls == 2 && shutdown_calls == 0,
            "partial/EAGAIN retry did not complete normally");
    require(rawdeviceBringDown(&rdev), "raw partial fixture stop failed");
    deviceDestroy(&rdev);
}

static void testSendErrorPolicy(void)
{
    resetFixture();
    raw_device_t rdev;
    deviceInit(&rdev, "raw-errors");
    require(rawdeviceBringUp(&rdev), "raw error fixture start failed");
    const injected_send_t expected[] = {{-1, EINTR, 8, 0},
                                        {-1, EAGAIN, 8, 0},
                                        {-1, ENOBUFS, 8, 0},
                                        {-1, ENOMEM, 7, 1},
                                        {-1, EMSGSIZE, 6, 2},
                                        {-1, EINVAL, 5, 3},
                                        {-1, EHOSTUNREACH, 4, 4},
                                        {-1, EBADF, 3, 5}};
    armSends(expected, ARRAY_SIZE(expected));
    for (unsigned i = 0; i < 8; ++i)
        queuePacket(&rdev, i, 0, 21);
    runMessage(takeMessage());
    require(send_calls == 1 && buffers[0].settled == 0, "EINTR retried synchronously or discarded output");
    runAllMessages();
    require(send_calls == send_count && rawLifecycleLoad(&rdev.lifecycle) == kRawLifecycleFailed,
            "raw errors stopped before or continued beyond the terminal failure");
    require(shutdown_calls == 1 && shutdown_code == 1, "raw terminal failure did not request exactly one shutdown");
    const raw_linux_writer_state_t *state = &rdev.writer_states[0];
    require(state->discard_log_limiter.total == 5 && state->transient_send_error_total == 2 &&
                state->message_too_large_packet_total == 1 && state->packet_local_send_error_total == 2,
            "raw packet/resource failure accounting changed");
    sbuf_t *rejected = packetCreate(8, 0, 21);
    require(! rawdeviceWrite(&rdev, rejected), "raw device accepted output after fatal failure");
    sbufDestroy(rejected);
    require(rawdeviceBringDown(&rdev), "raw error fixture stop failed");
    deviceDestroy(&rdev);
}

static void testValidationAndZeroProgress(void)
{
    resetFixture();
    raw_device_t rdev;
    deviceInit(&rdev, "raw-validation");
    require(rawdeviceBringUp(&rdev), "raw validation fixture start failed");
    const injected_send_t expected[] = {{1, 0, 1, 0}, {1, 0, 1, 2}, {0, 0, 1, 4}};
    armSends(expected, ARRAY_SIZE(expected));
    queuePacket(&rdev, 0, 0, 21);
    sbuf_t *invalid = packetCreate(1, 0, 21);
    PUT_BE16(sbufGetMutablePtr(invalid) + 2, 20);
    require(rawdeviceWrite(&rdev, invalid), "raw malformed fixture failed enqueue");
    queuePacket(&rdev, 2, 0, 21);
    queuePacket(&rdev, 3, 0, kMaxAllowedPacketLength + 1);
    queuePacket(&rdev, 4, 0, 21);
    runAllMessages();
    require(send_calls == 3 && shutdown_calls == 1, "zero-progress native send was not terminal");
    const raw_linux_writer_state_t *state = &rdev.writer_states[0];
    require(state->oversized_packet_total == 1 && state->packet_local_send_error_total == 1,
            "raw preflight did not classify malformed/oversized packets");
    require(rawdeviceBringDown(&rdev), "raw validation fixture stop failed");
    deviceDestroy(&rdev);
}

static void testTerminalReadinessFailure(void)
{
    resetFixture();
    raw_device_t rdev;
    deviceInit(&rdev, "raw-readiness-error");
    require(rawdeviceBringUp(&rdev), "raw readiness fixture start failed");
    const injected_send_t expected[] = {{-1, EAGAIN, 2, 0}};
    armSends(expected, ARRAY_SIZE(expected));
    queuePacket(&rdev, 0, 0, 21);
    queuePacket(&rdev, 1, 0, 21);
    poll_events = POLLNVAL;
    runAllMessages();
    require(send_calls == 1 && poll_calls == 1 && shutdown_calls == 1 &&
                rawLifecycleLoad(&rdev.lifecycle) == kRawLifecycleFailed,
            "terminal readiness event resumed writes or lost fatal device reporting");
    require(rawdeviceBringDown(&rdev), "readiness-failed raw device did not stop");
    deviceDestroy(&rdev);
}

static void testNotrackLifecycle(void)
{
    resetFixture();
    raw_device_t rdev;
    deviceInit(&rdev, "raw-notrack");
    rdev.bypass_conntrack     = true;
    fail_next_notrack_install = true;
    require(! rawdeviceBringUp(&rdev), "failed NOTRACK install published raw writer");
    require(! rdev.notrack_rule_pending && rdev.writer.current == NULL &&
                rawLifecycleLoad(&rdev.lifecycle) == kRawLifecycleDown,
            "NOTRACK startup failure did not roll back");
    require(rawdeviceBringUp(&rdev), "NOTRACK fixture restart failed");
    queuePacket(&rdev, 0, 0, 21);
    const unsigned removals = notrack_removals;
    rawdeviceRequestStop(&rdev);
    require(rdev.notrack_rule_pending && notrack_removals == removals, "nonblocking stop request ran firewall cleanup");
    fail_next_notrack_remove = true;
    require(! rawdeviceBringDown(&rdev) && rdev.notrack_rule_pending && rdev.writer.current == NULL,
            "failed NOTRACK cleanup lost pending ownership");
    require(! rawdeviceBringUp(&rdev), "raw device restarted before NOTRACK cleanup completed");
    require(rawdeviceBringDown(&rdev) && ! rdev.notrack_rule_pending, "NOTRACK cleanup retry failed");
    require(rawdeviceBringUp(&rdev) && rdev.notrack_rule_pending, "restart did not reinstall NOTRACK");
    runAllMessages();
    require(send_calls == 0 && rawdeviceIsUp(&rdev), "stale flush wrote into restarted raw device");
    require(rawdeviceBringDown(&rdev), "restarted NOTRACK stop failed");
    deviceDestroy(&rdev);
}

static void testBlockedStopAndLateCancellation(void)
{
    resetFixture();
    raw_device_t rdev;
    deviceInit(&rdev, "raw-blocked-stop");
    require(rawdeviceBringUp(&rdev), "raw blocked-stop start failed");
    const injected_send_t expected[] = {{-1, EAGAIN, 2, 0}};
    armSends(expected, ARRAY_SIZE(expected));
    queuePacket(&rdev, 0, 0, 21);
    queuePacket(&rdev, 1, 0, 21);
    runMessage(takeMessage());
    require(buffers[0].settled == 0 && messages[message_head].delay_ms == 1, "blocked output was not retained");
    require(rawdeviceBringDown(&rdev), "blocked-output stop failed");
    deviceDestroy(&rdev);
    cancelAllMessages();
    require(send_calls == 1, "late cancellation attempted native output");
}

static void *runNativeWorker(void *arg)
{
    captured_message_t *message = arg;
    testWorkerBindWID(message->wid);
    message->callback(&GSTATE.workers[message->wid], message->arg1, message->arg2, message->arg3);
    testWorkerUnbindWID();
    return NULL;
}

static void *closeNativeWriter(void *arg)
{
    raw_device_t *rdev = arg;
    rawdeviceRequestStop(rdev);
    atomicStoreExplicit(&close_requested, true, memory_order_release);
    require(rawdeviceBringDown(rdev), "concurrent raw bring-down failed");
    atomicStoreExplicit(&close_finished, true, memory_order_release);
    return NULL;
}

static void testStopWaitsForNativeWrite(int error)
{
    resetFixture();
    raw_device_t rdev;
    deviceInit(&rdev, "raw-native-stop");
    rdev.bypass_conntrack = true;
    require(rawdeviceBringUp(&rdev), "native stop fixture start failed");
    const injected_send_t expected[] = {{error == 0 ? 1 : -1, error, 1, 0}};
    armSends(expected, ARRAY_SIZE(expected));
    queuePacket(&rdev, 0, 1, 21);
    captured_message_t message = takeMessage();
    atomicStoreRelaxed(&block_send, true);
    pthread_t native_worker, closer;
    require(pthread_create(&native_worker, NULL, runNativeWorker, &message) == 0, "native worker creation failed");
    while (! atomicLoadExplicit(&entered_send, memory_order_acquire))
        YIELD_THREAD();
    const unsigned removals = notrack_removals;
    require(pthread_create(&closer, NULL, closeNativeWriter, &rdev) == 0, "raw coordinator creation failed");
    while (! atomicLoadExplicit(&close_requested, memory_order_acquire))
        YIELD_THREAD();
    require(! atomicLoadExplicit(&close_finished, memory_order_acquire) && notrack_removals == removals,
            "raw stop removed NOTRACK before admitted native output completed");
    atomicStoreExplicit(&release_send, true, memory_order_release);
    require(pthread_join(native_worker, NULL) == 0 && pthread_join(closer, NULL) == 0,
            "native stop thread join failed");
    bufferpoolResetThreadOwnership(test_env->buffer_pools[1]);
    runAllMessages();
    require(notrack_removals == removals + 1 && shutdown_calls == 0, "normal native stop cleanup changed");
    deviceDestroy(&rdev);
}

static raw_writer_batch_result_t discardBatch(void *context, worker_t *worker, raw_writer_lane_t *lane, sbuf_t **batch,
                                              size_t count)
{
    discard context;
    discard lane;
    for (size_t i = 0; i < count; ++i)
        bufferpoolReuseBuffer(worker->buffer_pool, batch[i]);
    return (raw_writer_batch_result_t) {.consumed = count, .status = kRawWriterBatchContinue};
}

static void *freshRefusal(void *arg)
{
    raw_device_t *rdev = arg;
    testWorkerBindWID(0);
    sbuf_t *buffer = sbufCreate(21);
    sbufSetLength(buffer, 21);
    require(! rawdeviceWrite(rdev, buffer), "raw refusal unexpectedly took caller ownership");
    sbufDestroy(buffer);
    testWorkerUnbindWID();
    return NULL;
}

static void runFreshRefusal(raw_device_t *rdev)
{
    pthread_t thread;
    require(pthread_create(&thread, NULL, freshRefusal, rdev) == 0, "fresh refusal thread create failed");
    require(pthread_join(thread, NULL) == 0, "fresh refusal thread join failed");
}

static void testRefusalLogging(void)
{
    resetFixture();
    raw_device_t rdev;
    deviceInit(&rdev, "raw-refusal");
    runFreshRefusal(&rdev);
    require(countLogSubstring("device is not up") == 1, "fresh Down refusal missed its first diagnostic");
    atomicStoreRelaxed(&rdev.lifecycle, kRawLifecycleUp);
    resetLogCapture();
    runFreshRefusal(&rdev);
    require(countLogSubstring("device is down") == 1, "unpublished raw writer missed its Down diagnostic");
    require(rawWriterOpen(&rdev.writer, 1, 1, NULL, discardBatch, NULL), "capacity-one raw writer open failed");
    queuePacket(&rdev, 0, 0, 21);
    resetLogCapture();
    runFreshRefusal(&rdev);
    require(log_capture_len == 0, "raw Full refusal emitted a diagnostic");
    for (unsigned i = 0; i < 64; ++i)
    {
        sbuf_t *buffer = sbufCreate(21);
        sbufSetLength(buffer, 21);
        require(! rawdeviceWrite(&rdev, buffer), "full raw queue accepted a write");
        sbufDestroy(buffer);
    }
    require(log_capture_len == 0, "raw Full refusal logged at packet rate");
    rawWriterCloseRequest(&rdev.writer);
    rawWriterCloseWait(&rdev.writer);
    atomicStoreRelaxed(&rdev.lifecycle, kRawLifecycleDown);
    deviceDestroy(&rdev);
    cancelAllMessages();
}

static void testSendErrorClassifier(void)
{
    require(rawLinuxClassifySendError(EINTR) == kRawLinuxSendRetryImmediately, "EINTR policy changed");
    require(rawLinuxClassifySendError(EAGAIN) == kRawLinuxSendWaitWritable, "EAGAIN policy changed");
    require(rawLinuxClassifySendError(ENOBUFS) == kRawLinuxSendDiscardPacket, "resource-pressure policy changed");
    require(rawLinuxClassifySendError(EINVAL) == kRawLinuxSendDiscardPacket, "packet-invalid policy changed");
    require(rawLinuxClassifySendError(EMSGSIZE) == kRawLinuxSendDiscardPacket, "oversize policy changed");
    require(rawLinuxClassifySendError(EHOSTUNREACH) == kRawLinuxSendDiscardPacket, "route refusal policy changed");
    require(rawLinuxClassifySendError(EPERM) == kRawLinuxSendDiscardPacket, "policy refusal changed");
    require(rawLinuxClassifySendError(EBADF) == kRawLinuxSendTerminal, "descriptor failure policy changed");
    require(rawLinuxClassifySendError(EIO) == kRawLinuxSendTerminal, "unknown error policy changed");
}

static void envSetup(test_env_t *env)
{
    *env               = (test_env_t) {0};
    test_env           = env;
    env->large_master  = masterpoolCreateWithCapacity(16);
    env->medium_master = masterpoolCreateWithCapacity(16);
    env->small_master  = masterpoolCreateWithCapacity(16);
    for (unsigned i = 0; i < ARRAY_SIZE(env->buffer_pools); ++i)
    {
        env->buffer_pools[i] = bufferpoolCreate(env->large_master,
                                                env->medium_master,
                                                env->small_master,
                                                16,
                                                8192,
                                                MEDIUM_BUFFER_SIZE_RAM_HIGH,
                                                4096,
                                                8192,
                                                8192);
        env->loops[i]        = (wloop_t *) &env->loops[i];
    }
    GSTATE.workers_count         = ARRAY_SIZE(env->buffer_pools);
    GSTATE.shortcut_buffer_pools = env->buffer_pools;
    GSTATE.shortcut_loops        = env->loops;
    GSTATE.ram_profile           = 1;
    testWorkerRegistryInstall(&env->registry);
    for (unsigned i = 0; i < ARRAY_SIZE(env->buffer_pools); ++i)
    {
        GSTATE.workers[i].buffer_pool = env->buffer_pools[i];
        GSTATE.workers[i].loop        = env->loops[i];
    }
    testWorkerBindWID(0);
}

static void envTeardown(test_env_t *env)
{
    testWorkerUnbindWID();
    GSTATE.workers_count         = 0;
    GSTATE.shortcut_buffer_pools = NULL;
    GSTATE.shortcut_loops        = NULL;
    testWorkerRegistryRestore(&env->registry);
    for (unsigned i = 0; i < ARRAY_SIZE(env->buffer_pools); ++i)
        bufferpoolDestroy(env->buffer_pools[i]);
    masterpoolMakeEmpty(env->large_master);
    masterpoolMakeEmpty(env->medium_master);
    masterpoolMakeEmpty(env->small_master);
    masterpoolDestroy(env->large_master);
    masterpoolDestroy(env->medium_master);
    masterpoolDestroy(env->small_master);
}

int main(void)
{
    testCaseSet("raw_linux_writer_test");
    test_env_t env;
    envSetup(&env);
    logger_t *logger = loggerCreate();
    require(logger != NULL, "raw log capture allocation failed");
    loggerSetHandler(logger, captureLog);
    setInternalLogger(logger);
    testSendErrorClassifier();
    testHeaderOnlyAndBatchLimit();
    testPartialAndBlockedFifo();
    testSendErrorPolicy();
    testValidationAndZeroProgress();
    testTerminalReadinessFailure();
    testNotrackLifecycle();
    testBlockedStopAndLateCancellation();
    testStopWaitsForNativeWrite(0);
    testStopWaitsForNativeWrite(EBADF);
    testStopWaitsForNativeWrite(EIO);
    testRefusalLogging();
    internaloggerDestroy();
    envTeardown(&env);
    puts("Linux raw worker output tests passed");
    return 0;
}

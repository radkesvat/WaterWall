// Queued-message lifetime coverage for the Linux TUN device.
//
// tun_linux.c is compiled directly into this executable. Privileged device
// syscalls and thread creation are wrapped, while the production BringUp,
// BringDown, queued-message delivery, and cleanup paths run unchanged.

#include "devices/tun/tun_linux_internal.h"
#include "global_state.h"
#include "worker.h"
#include "worker_messages.h"

#include <errno.h>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <poll.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

enum
{
    kMaxCapturedMessages = 8
};

typedef struct captured_message_s
{
    WorkerMessageCallback        callback;
    WorkerMessageCleanupCallback cleanup;
    void                        *arg1;
    void                        *arg2;
    void                        *arg3;
} captured_message_t;

typedef struct test_env_s
{
    master_pool_t *large_master;
    master_pool_t *small_master;
    buffer_pool_t *worker_buffer_pool;
    buffer_pool_t *buffer_pools[1];
    wloop_t       *loops[1];
} test_env_t;

static captured_message_t       captured_messages[kMaxCapturedMessages];
static unsigned int             captured_message_count;
static unsigned int             callback_count;
static unsigned int             next_fake_thread = 1;
static unsigned int             fake_thread_create_calls;
static unsigned int             fake_thread_join_calls;
static unsigned int             fail_fake_thread_create_on_call;
static void                  *(*captured_first_thread_routine)(void *);
static void                    *captured_first_thread_arg;
static sbuf_t                  *expected_reused_buffer;
static buffer_pool_t           *expected_reuse_pool;
static unsigned int             expected_reuse_count;
static device_reader_session_t *tracked_session;
static master_pool_t           *tracked_message_pool;
static unsigned int             tracked_session_free_count;
static unsigned int             tracked_pool_destroy_count;

int     __real_open(const char *path, int flags, ...);
int     __wrap_open(const char *path, int flags, ...);
int     __wrap_ioctl(int fd, unsigned long request, ...);
int     __real_socket(int domain, int type, int protocol);
int     __wrap_socket(int domain, int type, int protocol);
ssize_t __real_read(int fd, void *buf, size_t count);
ssize_t __wrap_read(int fd, void *buf, size_t count);
ssize_t __real_write(int fd, const void *buf, size_t count);
ssize_t __wrap_write(int fd, const void *buf, size_t count);
int     __real_poll(struct pollfd *fds, nfds_t nfds, int timeout);
int     __wrap_poll(struct pollfd *fds, nfds_t nfds, int timeout);
int     __real_pthread_create(pthread_t *thread, const pthread_attr_t *attr, void *(*routine)(void *), void *arg);
int     __wrap_pthread_create(pthread_t *thread, const pthread_attr_t *attr, void *(*routine)(void *), void *arg);
int     __real_pthread_join(pthread_t thread, void **retval);
int     __wrap_pthread_join(pthread_t thread, void **retval);
pid_t   __wrap_fork(void);
int     __wrap_execvp(const char *file, char *const argv[]);
pid_t   __wrap_waitpid(pid_t pid, int *status, int options);
bool    __wrap_sendWorkerMessageForceQueueWithCleanup(wid_t wid, WorkerMessageCallback callback,
                                                      WorkerMessageCleanupCallback cleanup, void *arg1, void *arg2,
                                                      void *arg3);
void    __real_memoryFree(void *ptr);
void    __wrap_memoryFree(void *ptr);
void    __real_masterpoolDestroy(master_pool_t *pool);
void    __wrap_masterpoolDestroy(master_pool_t *pool);
void    __real_bufferpoolReuseBuffer(buffer_pool_t *pool, sbuf_t *buf);
void    __wrap_bufferpoolReuseBuffer(buffer_pool_t *pool, sbuf_t *buf);

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "FAIL: %s\n", message);
        exit(1);
    }
}

int __wrap_open(const char *path, int flags, ...)
{
    mode_t mode = 0;
    if ((flags & O_CREAT) != 0)
    {
        va_list args;
        va_start(args, flags);
        mode = (mode_t) va_arg(args, int);
        va_end(args);
    }

    if (strcmp(path, "/dev/net/tun") == 0)
    {
        return __real_open("/dev/null", O_RDWR);
    }

    if ((flags & O_CREAT) != 0)
    {
        return __real_open(path, flags, mode);
    }
    return __real_open(path, flags);
}

int __wrap_ioctl(int fd, unsigned long request, ...)
{
    discard fd;

    va_list args;
    va_start(args, request);
    void *argument = va_arg(args, void *);
    va_end(args);

    if (request == TUNSETIFF)
    {
        struct ifreq *ifr = argument;
        stringCopyN(ifr->ifr_name, "ww-lifetime-test", IFNAMSIZ);
        ifr->ifr_name[IFNAMSIZ - 1] = '\0';
    }
    else if (request == SIOCGIFFLAGS)
    {
        struct ifreq *ifr = argument;
        ifr->ifr_flags    = 0;
    }
    return 0;
}

int __wrap_socket(int domain, int type, int protocol)
{
    return __real_socket(domain, type, protocol);
}

ssize_t __wrap_read(int fd, void *buf, size_t count)
{
    return __real_read(fd, buf, count);
}

ssize_t __wrap_write(int fd, const void *buf, size_t count)
{
    return __real_write(fd, buf, count);
}

int __wrap_poll(struct pollfd *fds, nfds_t nfds, int timeout)
{
    return __real_poll(fds, nfds, timeout);
}

int __wrap_pthread_create(pthread_t *thread, const pthread_attr_t *attr, void *(*routine)(void *), void *arg)
{
    discard attr;
    fake_thread_create_calls++;
    if (fake_thread_create_calls == fail_fake_thread_create_on_call)
    {
        return EAGAIN;
    }
    // Record the thread body so a test can run it inline and observe what the
    // device does when a routine returns on its own. Nothing is spawned here.
    if (fake_thread_create_calls == 1)
    {
        captured_first_thread_routine = routine;
        captured_first_thread_arg     = arg;
    }
    *thread = (pthread_t) next_fake_thread++;
    return 0;
}

int __wrap_pthread_join(pthread_t thread, void **retval)
{
    discard thread;
    fake_thread_join_calls++;
    if (retval != NULL)
    {
        *retval = NULL;
    }
    return 0;
}

pid_t __wrap_fork(void)
{
    return (pid_t) 4242;
}

int __wrap_execvp(const char *file, char *const argv[])
{
    discard file;
    discard argv;
    errno = ENOSYS;
    return -1;
}

pid_t __wrap_waitpid(pid_t pid, int *status, int options)
{
    discard options;
    if (status != NULL)
    {
        *status = 0;
    }
    return pid;
}

bool __wrap_sendWorkerMessageForceQueueWithCleanup(wid_t wid, WorkerMessageCallback callback,
                                                   WorkerMessageCleanupCallback cleanup, void *arg1, void *arg2,
                                                   void *arg3)
{
    discard wid;
    require(captured_message_count < kMaxCapturedMessages, "captured-message queue overflow");
    captured_messages[captured_message_count++] = (captured_message_t) {
        .callback = callback,
        .cleanup  = cleanup,
        .arg1     = arg1,
        .arg2     = arg2,
        .arg3     = arg3,
    };
    return true;
}

void __wrap_memoryFree(void *ptr)
{
    if (ptr == tracked_session)
    {
        tracked_session_free_count++;
    }
    __real_memoryFree(ptr);
}

void __wrap_masterpoolDestroy(master_pool_t *pool)
{
    if (pool == tracked_message_pool)
    {
        tracked_pool_destroy_count++;
    }
    __real_masterpoolDestroy(pool);
}

void __wrap_bufferpoolReuseBuffer(buffer_pool_t *pool, sbuf_t *buf)
{
    if (pool == expected_reuse_pool && buf == expected_reused_buffer)
    {
        expected_reuse_count++;
    }
    __real_bufferpoolReuseBuffer(pool, buf);
}

static void envSetup(test_env_t *env)
{
    memoryZero(env, sizeof(*env));
    env->large_master       = masterpoolCreateWithCapacity(16);
    env->small_master       = masterpoolCreateWithCapacity(16);
    env->worker_buffer_pool = bufferpoolCreate(env->large_master, env->small_master, 16, 8192, 4096);
    env->buffer_pools[0]    = env->worker_buffer_pool;
    env->loops[0]           = (wloop_t *) (void *) env;

    GSTATE.masterpool_buffer_pools_large = env->large_master;
    GSTATE.masterpool_buffer_pools_small = env->small_master;
    GSTATE.shortcut_buffer_pools         = env->buffer_pools;
    GSTATE.shortcut_loops                = env->loops;
    GSTATE.workers_count                 = 2;
    GSTATE.ram_profile                   = 1;
    atomicStoreExplicit(&GSTATE.application_stopping_flag, false, memory_order_release);
    tl_wid = 0;
}

static void envTeardown(test_env_t *env)
{
    GSTATE.masterpool_buffer_pools_large = NULL;
    GSTATE.masterpool_buffer_pools_small = NULL;
    GSTATE.shortcut_buffer_pools         = NULL;
    GSTATE.shortcut_loops                = NULL;
    GSTATE.workers_count                 = 0;

    bufferpoolDestroy(env->worker_buffer_pool);
    masterpoolMakeEmpty(env->large_master);
    masterpoolMakeEmpty(env->small_master);
    masterpoolDestroy(env->large_master);
    masterpoolDestroy(env->small_master);
}

static void resetCapturedMessages(void)
{
    memoryZero(captured_messages, sizeof(captured_messages));
    captured_message_count = 0;
}

static void resetFakeThreads(unsigned int fail_on_call)
{
    fake_thread_create_calls        = 0;
    fake_thread_join_calls          = 0;
    fail_fake_thread_create_on_call = fail_on_call;
    captured_first_thread_routine   = NULL;
    captured_first_thread_arg       = NULL;
}

static tun_device_t *createRunningDevice(void)
{
    tun_device_t *tdev = tundeviceCreate("ww-lifetime-test", false, 1500, NULL, NULL);
    require(tdev != NULL, "production tundeviceCreate failed");
    require(tundeviceBringUp(tdev), "production tundeviceBringUp failed");
    return tdev;
}

static void observeReadCallback(tun_device_t *tdev, void *userdata, sbuf_t *buf, uint8_t wid)
{
    discard tdev;
    discard userdata;
    callback_count++;
    bufferpoolReuseBuffer(getWorkerBufferPool(wid), buf);
}

static tun_device_t *createRunningReaderDevice(void)
{
    tun_device_t *tdev = tundeviceCreate("ww-lifetime-test", false, 1500, NULL, observeReadCallback);
    require(tdev != NULL, "production reader-device create failed");
    require(tundeviceBringUp(tdev), "production reader-device bring-up failed");
    return tdev;
}

static void postOne(tun_device_t *tdev, sbuf_t *buf)
{
    unsigned int before = captured_message_count;
    deviceReaderSessionPost(tunLinuxReaderSession(tdev), 0, &buf, 1);
    require(captured_message_count == before + 1, "production distribution did not post one message");
    require(captured_messages[before].callback == deviceReaderSessionMessageReceived,
            "production distribution installed the wrong delivery callback");
    require(captured_messages[before].cleanup == deviceReaderSessionCleanupPostedMessage,
            "production distribution installed the wrong cleanup callback");
}

static void deliverMessage(unsigned int index, worker_t *worker)
{
    captured_message_t *message = &captured_messages[index];
    message->callback(worker, message->arg1, message->arg2, message->arg3);
}

static void cleanupMessage(unsigned int index)
{
    captured_message_t *message = &captured_messages[index];
    message->cleanup(message->arg1, message->arg2, message->arg3);
}

static void testQueuedCleanupOutlivesDevice(void)
{
    resetCapturedMessages();
    tun_device_t            *tdev    = createRunningDevice();
    device_reader_session_t *session = tunLinuxReaderSession(tdev);

    tracked_session            = session;
    tracked_message_pool       = session->message_pool;
    tracked_session_free_count = 0;
    tracked_pool_destroy_count = 0;

    sbuf_t *buf = sbufCreate(64);
    postOne(tdev, buf);
    require(atomicLoadExplicit(&session->refcount, memory_order_acquire) == 2,
            "posting did not retain the reader session");

    tundeviceDestroy(tdev);
    require(atomicLoadExplicit(&session->refcount, memory_order_acquire) == 1,
            "device destroy did not release exactly its session reference");
    require(tracked_session_free_count == 0 && tracked_pool_destroy_count == 0,
            "device destroy freed a session retained by a queued message");

    cleanupMessage(0);
    require(tracked_session_free_count == 1, "the last queued-message cleanup did not free the session exactly once");
    require(tracked_pool_destroy_count == 1, "the last queued-message cleanup did not destroy the pool exactly once");

    tracked_session      = NULL;
    tracked_message_pool = NULL;
    resetCapturedMessages();
}

static void testClosedAndStaleDeliveriesDoNotTouchDevice(void)
{
    resetCapturedMessages();
    callback_count = 0;

    tun_device_t            *tdev     = createRunningReaderDevice();
    device_reader_session_t *session  = tunLinuxReaderSession(tdev);
    worker_t                 receiver = {.wid = 0};

    sbuf_t *closed_buf = bufferpoolGetSmallBuffer(getWorkerBufferPool(0));
    sbuf_t *stale_buf  = bufferpoolGetSmallBuffer(getWorkerBufferPool(0));
    postOne(tdev, closed_buf);
    postOne(tdev, stale_buf);

    require(tundeviceBringDown(tdev), "production bring-down failed");
    require(! deviceLifetimeGateEnter(&session->delivery_gate), "delivery gate accepted an entry after bring-down");

    expected_reuse_pool    = getWorkerBufferPool(0);
    expected_reused_buffer = closed_buf;
    expected_reuse_count   = 0;
    deliverMessage(0, &receiver);
    require(callback_count == 0, "delivery after bring-down invoked the device callback");
    require(expected_reuse_count == 1, "delivery after bring-down did not return its buffer to the worker pool");

    require(tundeviceBringUp(tdev), "production restart bring-up failed");
    expected_reused_buffer = stale_buf;
    expected_reuse_count   = 0;
    deliverMessage(1, &receiver);
    require(callback_count == 0, "stale generation delivery invoked the device callback");
    require(expected_reuse_count == 1, "stale generation delivery did not return its buffer to the worker pool");

    expected_reused_buffer = NULL;
    expected_reuse_pool    = NULL;
    tundeviceDestroy(tdev);
    resetCapturedMessages();
}

static void testBringUpRollsBackThreadCreationFailures(void)
{
    for (unsigned int failed_call = 1; failed_call <= 2; failed_call++)
    {
        resetFakeThreads(failed_call);
        tun_device_t *tdev = tundeviceCreate("ww-lifetime-test", false, 1500, NULL, observeReadCallback);
        require(tdev != NULL, "thread-failure device create failed");

        device_reader_session_t *session           = tunLinuxReaderSession(tdev);
        uint32_t                 failed_generation = deviceReaderSessionGeneration(session) + 1;
        require(! tundeviceBringUp(tdev), "bring-up unexpectedly survived a thread-creation failure");
        require(fake_thread_create_calls == failed_call, "bring-up failed on the wrong thread-creation call");
        require(fake_thread_join_calls == (failed_call == 2 ? 1U : 0U),
                "bring-up rollback joined the wrong number of started threads");
        require(! tundeviceIsUp(tdev), "thread-creation rollback left the device up");
        require(! deviceLifetimeGateIsActive(&session->delivery_gate),
                "thread-creation rollback left the delivery gate open");
        require(atomicLoadExplicit(&session->refcount, memory_order_acquire) == 1,
                "thread-creation rollback leaked a reader-session reference");
        require(deviceReaderSessionGeneration(session) == failed_generation,
                "failed bring-up did not stamp exactly one reader generation");

        resetFakeThreads(0);
        require(tundeviceBringUp(tdev), "device could not restart after thread-creation rollback");
        require(deviceReaderSessionGeneration(session) == failed_generation + 1,
                "restart after rollback did not advance the reader generation");
        require(tundeviceBringDown(tdev), "restart after thread-creation rollback did not shut down");
        tundeviceDestroy(tdev);
    }
}

// The reader stub stands in for a routine that hit a real device error -- a poll
// failure, EOF, an unexpected revents -- and returned while `running` was still
// set. Every one of those paths simply returns; none of them used to tell anyone.
static WTHREAD_ROUTINE(failingReaderRoutine) // NOLINT
{
    discard userdata;
    return 0;
}

// Regression: a reader/writer routine that dies on a device error left `up` set,
// so tundeviceIsUp() kept advertising a device whose reads had silently stopped
// and whose writes only piled into a channel nobody drains. Bring-down then had
// to stay reachable, which is why it can no longer gate on `up` alone.
static void testUnexpectedThreadExitTakesTheDeviceDown(void)
{
    resetFakeThreads(0);
    tun_device_t *tdev = tundeviceCreate("ww-lifetime-test", false, 1500, NULL, observeReadCallback);
    require(tdev != NULL, "unexpected-exit device create failed");

    // Return immediately from the reader body instead of running the real loop.
    tunLinuxSetReaderRoutine(tdev, failingReaderRoutine);
    require(tundeviceBringUp(tdev), "unexpected-exit device bring-up failed");
    require(tundeviceIsUp(tdev), "bring-up did not publish the device as up");
    require(captured_first_thread_routine != NULL, "the reader thread body was not captured");

    // Run the captured thread body inline: the wrapper sees `running` still set
    // and must treat the return as a device failure.
    captured_first_thread_routine(captured_first_thread_arg);

    require(! tundeviceIsUp(tdev), "an unexpected reader-thread exit left the device advertised as up");

    // The teardown must still run: `up` is now false, so a bring-down gated on it
    // would skip both joins and leave the writer channel allocated.
    const unsigned int joins_before = fake_thread_join_calls;
    require(tundeviceBringDown(tdev), "bring-down after an unexpected reader exit failed");
    require(fake_thread_join_calls == joins_before + 2, "bring-down after a thread failure skipped its joins");
    require(tundeviceBringDown(tdev), "a second bring-down must stay a successful no-op");
    require(fake_thread_join_calls == joins_before + 2, "the no-op bring-down joined an already-joined thread");

    tundeviceDestroy(tdev);
}

typedef struct writer_race_probe_s
{
    tun_device_t *tdev;
    sbuf_t      **buffers;
    unsigned int  buffer_count;
    atomic_bool   running;
    atomic_bool   start;
    atomic_uint   next_buffer;
    atomic_uint   started;
    atomic_uint   attempts;
} writer_race_probe_t;

static void *writerRaceRoutine(void *userdata)
{
    writer_race_probe_t *probe = userdata;
    atomicAddExplicit(&probe->started, 1, memory_order_release);

    while (! atomicLoadExplicit(&probe->start, memory_order_acquire))
    {
        YIELD_THREAD();
    }

    while (atomicLoadExplicit(&probe->running, memory_order_acquire))
    {
        unsigned int index = atomicAddExplicit(&probe->next_buffer, 1, memory_order_relaxed);
        if (index >= probe->buffer_count)
        {
            break;
        }

        sbuf_t *buf = probe->buffers[index];
        if (tundeviceWrite(probe->tdev, buf))
        {
            probe->buffers[index] = NULL;
        }
        atomicAddExplicit(&probe->attempts, 1, memory_order_release);
    }
    return NULL;
}

static void testWriterGateQuiescesConcurrentSenders(void)
{
    enum
    {
        kWriterThreads = 4,
        kWriterBuffers = 1024
    };

    tun_device_t  *tdev        = createRunningDevice();
    buffer_pool_t *writer_pool = tunLinuxWriterBufferPool(tdev);
    sbuf_t        *buffers[kWriterBuffers];
    for (unsigned int i = 0; i < kWriterBuffers; i++)
    {
        buffers[i] = bufferpoolGetSmallBuffer(writer_pool);
        sbufSetLength(buffers[i], 32);
    }

    writer_race_probe_t probe = {
        .tdev         = tdev,
        .buffers      = buffers,
        .buffer_count = ARRAY_SIZE(buffers),
        .running      = true,
    };
    pthread_t threads[kWriterThreads];
    for (unsigned int i = 0; i < kWriterThreads; i++)
    {
        require(__real_pthread_create(&threads[i], NULL, writerRaceRoutine, &probe) == 0,
                "failed to start a writer-gate race thread");
    }

    while (atomicLoadExplicit(&probe.started, memory_order_acquire) < kWriterThreads)
    {
        YIELD_THREAD();
    }
    atomicStoreExplicit(&probe.start, true, memory_order_release);
    while (atomicLoadExplicit(&probe.attempts, memory_order_acquire) < kWriterThreads)
    {
        YIELD_THREAD();
    }

    require(tundeviceBringDown(tdev), "bring-down failed while writer-gate senders were active");
    atomicStoreExplicit(&probe.running, false, memory_order_release);
    for (unsigned int i = 0; i < kWriterThreads; i++)
    {
        require(__real_pthread_join(threads[i], NULL) == 0, "failed to join a writer-gate race thread");
    }

    require(atomicLoadExplicit(&probe.attempts, memory_order_acquire) >= kWriterThreads,
            "writer-gate race threads did not exercise the write path");

    for (unsigned int i = 0; i < kWriterBuffers; i++)
    {
        if (buffers[i] != NULL)
        {
            bufferpoolReuseBuffer(writer_pool, buffers[i]);
        }
    }
    tundeviceDestroy(tdev);
}

int main(void)
{
    test_env_t env;
    envSetup(&env);
    testQueuedCleanupOutlivesDevice();
    testClosedAndStaleDeliveriesDoNotTouchDevice();
    testBringUpRollsBackThreadCreationFailures();
    testUnexpectedThreadExitTakesTheDeviceDown();
    testWriterGateQuiescesConcurrentSenders();
    envTeardown(&env);
    puts("Linux TUN message lifetime tests passed");
    return 0;
}

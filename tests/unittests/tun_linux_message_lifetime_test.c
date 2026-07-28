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

static captured_message_t captured_messages[kMaxCapturedMessages];
static unsigned int       captured_message_count;
static unsigned int       callback_count;
static unsigned int       next_fake_thread = 1;
static unsigned int       fake_thread_create_calls;
static unsigned int       fake_thread_join_calls;
static unsigned int       fail_fake_thread_create_on_call;
static unsigned int       fail_fake_thread_join_on_call;
static unsigned int       run_fake_thread_on_create_call;
static unsigned int       fail_interface_down_calls;
static unsigned int       interface_down_attempts;
// Reader is created first, writer second, so index 0 is the reader body and
// index 1 the writer body. Capturing both lets a test invoke either wrapper
// independently.
enum
{
    kCapturedReaderThread = 0,
    kCapturedWriterThread = 1,
    kMaxCapturedThreads   = 2
};
static void *(*captured_thread_routines[kMaxCapturedThreads])(void *);
static void                    *captured_thread_args[kMaxCapturedThreads];
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
pid_t   __real_fork(void);
pid_t   __wrap_fork(void);
int     __wrap_execvp(const char *file, char *const argv[]);
pid_t   __real_waitpid(pid_t pid, int *status, int options);
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

/*
 * tun_linux.c is compiled directly into this test, so its shutdown request is
 * intercepted here instead of running the real process shutdown. The worker-0
 * executor half of the composition is covered by shutdown_manager_test.
 */
bool           __wrap_requestProgramShutdown(int exit_code);
_Noreturn void __wrap_abortProgramNow(int exit_code);

enum
{
    // Exit status a child uses when the documented hard fallback is reached.
    kFallbackAbortExitStatus = 77
};

static unsigned int shutdown_request_calls;
static int          shutdown_request_last_code;
static bool         shutdown_request_accepts = true;
// Set only by the forked child that deliberately exercises the hard fallback, so
// its diagnostic does not read like a failure in CI output.
static bool hard_abort_is_expected;

/*
 * Device I/O error injection.
 *
 * The routines under test are the production routineReadFromTun and
 * routineWriteToTun, driven through the wrapped read()/write()/poll() against
 * the fake handle. Each test arms exactly the number of device operations the
 * correct implementation should perform and queues one more unit of work than
 * that, so an implementation that swallows a permanent error runs off the end
 * of the armed sequence and fails loudly instead of hanging.
 */
enum
{
    kMaxInjectedIoResults = 8
};

typedef struct injected_io_result_s
{
    ssize_t result; // Bytes to report; 0 for end of stream, -1 for an error.
    int     error;  // errno to publish when result is -1.
} injected_io_result_t;

static int                  tun_handle_fd = -1;
static injected_io_result_t injected_reads[kMaxInjectedIoResults];
static unsigned int         injected_read_count;
static unsigned int         observed_read_calls;
static injected_io_result_t injected_writes[kMaxInjectedIoResults];
static unsigned int         injected_write_count;
static unsigned int         observed_write_calls;
static bool                 inject_reader_pollin;
// Observed from inside the I/O loop, before the routine has returned, so a
// recoverable error can be checked while the device is still meant to be up.
static tun_device_t *in_flight_device;
static unsigned int  in_flight_check_call;
static unsigned int  in_flight_checks_run;

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "FAIL: %s\n", message);
        exit(1);
    }
}

// A recoverable error must leave the device usable: the routine keeps running,
// the lifecycle stays UP, and nothing has asked the process to shut down.
static void checkInFlightExpectations(unsigned int call_number)
{
    if (in_flight_device == NULL || call_number != in_flight_check_call)
    {
        return;
    }
    in_flight_checks_run++;
    require(tunLinuxLifecycleState(in_flight_device) == kTunLifecycleUp,
            "a recoverable device I/O error took the device out of UP");
    require(shutdown_request_calls == 0, "a recoverable device I/O error requested process shutdown");
}

static ssize_t applyInjectedIoResult(const injected_io_result_t *entry)
{
    if (entry->result < 0)
    {
        errno = entry->error;
        return -1;
    }
    return entry->result;
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
        // Remembered so error injection can target the device handle only, and
        // never the stop pipe the reader also read()s from.
        tun_handle_fd = __real_open("/dev/null", O_RDWR);
        return tun_handle_fd;
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
    else if (request == SIOCSIFFLAGS)
    {
        struct ifreq *ifr = argument;
        if ((ifr->ifr_flags & IFF_UP) == 0)
        {
            interface_down_attempts++;
            if (fail_interface_down_calls > 0)
            {
                fail_interface_down_calls--;
                errno = EIO;
                return -1;
            }
        }
    }
    return 0;
}

int __wrap_socket(int domain, int type, int protocol)
{
    return __real_socket(domain, type, protocol);
}

ssize_t __wrap_read(int fd, void *buf, size_t count)
{
    if (fd == tun_handle_fd && injected_read_count > 0)
    {
        require(observed_read_calls < injected_read_count,
                "the reader kept reading a device that reported a permanent error");
        const unsigned int index = observed_read_calls++;
        checkInFlightExpectations(index + 1);
        return applyInjectedIoResult(&injected_reads[index]);
    }
    return __real_read(fd, buf, count);
}

ssize_t __wrap_write(int fd, const void *buf, size_t count)
{
    if (fd == tun_handle_fd && injected_write_count > 0)
    {
        require(observed_write_calls < injected_write_count,
                "the writer kept writing to a device that reported a permanent error");
        const unsigned int index = observed_write_calls++;
        checkInFlightExpectations(index + 1);
        return applyInjectedIoResult(&injected_writes[index]);
    }
    return __real_write(fd, buf, count);
}

int __wrap_poll(struct pollfd *fds, nfds_t nfds, int timeout)
{
    if (inject_reader_pollin && nfds == 2)
    {
        // Report the device readable and the stop pipe idle, so the reader loop
        // is driven purely by the armed read results.
        fds[0].revents = POLLIN;
        fds[1].revents = 0;
        return 1;
    }
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
    *thread = (pthread_t) next_fake_thread++;
    if (fake_thread_create_calls <= kMaxCapturedThreads)
    {
        captured_thread_routines[fake_thread_create_calls - 1] = routine;
        captured_thread_args[fake_thread_create_calls - 1]     = arg;
    }
    if (fake_thread_create_calls == run_fake_thread_on_create_call)
    {
        discard routine(arg);
    }
    return 0;
}

int __wrap_pthread_join(pthread_t thread, void **retval)
{
    discard thread;
    fake_thread_join_calls++;
    if (fake_thread_join_calls == fail_fake_thread_join_on_call)
    {
        return EBUSY;
    }
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

    /*
     * Recycling a buffer runs arbitrary code, which is free to leave any errno
     * behind. The I/O routines recycle between the failing syscall and their
     * error classification, so they must classify a copy captured immediately
     * after the syscall. Clobbering with a transient value here means any
     * routine that re-reads errno afterwards sees "retry" and keeps going, which
     * every injected-error case below detects.
     */
    if (injected_read_count > 0 || injected_write_count > 0)
    {
        errno = EAGAIN;
    }
}

bool __wrap_requestProgramShutdown(int exit_code)
{
    shutdown_request_calls++;
    shutdown_request_last_code = exit_code;
    return shutdown_request_accepts;
}

_Noreturn void __wrap_abortProgramNow(int exit_code)
{
    /*
     * Any hard abort the test did not deliberately provoke is a failure: the
     * whole point of this change is that a structured device I/O failure goes
     * through the orderly request path. Cases that do exercise the documented
     * fallback run in a forked child and check for this exit status.
     */
    fprintf(stderr,
            "%s: abortProgramNow(%d) was reached\n",
            hard_abort_is_expected ? "expected hard fallback" : "FAIL",
            exit_code);
    _Exit(kFallbackAbortExitStatus);
}

static void resetShutdownRequests(void)
{
    shutdown_request_calls     = 0;
    shutdown_request_last_code = 0;
    shutdown_request_accepts   = true;
}

static void resetIoInjection(void)
{
    memoryZero(injected_reads, sizeof(injected_reads));
    memoryZero(injected_writes, sizeof(injected_writes));
    injected_read_count  = 0;
    observed_read_calls  = 0;
    injected_write_count = 0;
    observed_write_calls = 0;
    inject_reader_pollin = false;
    in_flight_device     = NULL;
    in_flight_check_call = 0;
    in_flight_checks_run = 0;
}

static void armDeviceReads(const injected_io_result_t *results, unsigned int count)
{
    require(count <= kMaxInjectedIoResults, "too many injected read results");
    memoryCopy(injected_reads, results, count * sizeof(results[0]));
    injected_read_count = count;
    observed_read_calls = 0;
}

static void armDeviceWrites(const injected_io_result_t *results, unsigned int count)
{
    require(count <= kMaxInjectedIoResults, "too many injected write results");
    memoryCopy(injected_writes, results, count * sizeof(results[0]));
    injected_write_count = count;
    observed_write_calls = 0;
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
    fail_fake_thread_join_on_call   = 0;
    run_fake_thread_on_create_call  = 0;
    memoryZero(captured_thread_routines, sizeof(captured_thread_routines));
    memoryZero(captured_thread_args, sizeof(captured_thread_args));
}

// Runs one captured device I/O thread body inline, exactly as the OS thread
// would: the routine returns and the production wrapper then decides whether the
// exit was expected.
static void runCapturedThreadBody(unsigned int index)
{
    require(index < kMaxCapturedThreads, "invalid captured thread index");
    require(captured_thread_routines[index] != NULL, "the requested thread body was not captured");
    discard captured_thread_routines[index](captured_thread_args[index]);
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

// This stub stands in for an I/O routine that hit a real device error and
// returned while `running` was still set.
static WTHREAD_ROUTINE(failingIoRoutine) // NOLINT
{
    discard userdata;
    return 0;
}

static void testThreadExitDuringStartupRollsBack(unsigned int exit_on_create_call)
{
    resetFakeThreads(0);
    resetShutdownRequests();
    run_fake_thread_on_create_call = exit_on_create_call;

    tun_device_t *tdev = tundeviceCreate("ww-lifetime-test", false, 1500, NULL, observeReadCallback);
    require(tdev != NULL, "startup-exit device create failed");

    if (exit_on_create_call == 1)
    {
        tunLinuxSetReaderRoutine(tdev, failingIoRoutine);
    }
    else
    {
        require(exit_on_create_call == 2, "invalid startup-exit injection point");
        tunLinuxSetWriterRoutine(tdev, failingIoRoutine);
    }

    device_reader_session_t *session           = tunLinuxReaderSession(tdev);
    uint32_t                 failed_generation = deviceReaderSessionGeneration(session) + 1;

    require(! tundeviceBringUp(tdev), "bring-up survived an I/O thread exiting during startup");
    require(fake_thread_create_calls == exit_on_create_call, "startup rollback created an unexpected thread");
    require(fake_thread_join_calls == exit_on_create_call, "startup rollback did not join every created thread");
    require(! tundeviceIsUp(tdev), "startup rollback left the device advertised as up");
    require(tunLinuxLifecycleState(tdev) == kTunLifecycleDown, "startup rollback did not publish final DOWN");
    require(! deviceLifetimeGateIsActive(&session->delivery_gate), "startup rollback left the delivery gate open");
    require(atomicLoadExplicit(&session->refcount, memory_order_acquire) == 1,
            "startup rollback leaked a reader-session reference");
    require(deviceReaderSessionGeneration(session) == failed_generation,
            "startup rollback did not stamp exactly one reader generation");
    /*
     * STARTING -> FAILED must stay a synchronous bring-up rollback. Requesting
     * process shutdown from the device thread here would race the rollback and
     * take the decision away from the main-thread TunDevice::onStart path.
     */
    require(shutdown_request_calls == 0, "an I/O thread exit during startup requested process shutdown");

    sbuf_t *buf = bufferpoolGetSmallBuffer(getWorkerBufferPool(0));
    sbufSetLength(buf, 64);
    require(! tundeviceWrite(tdev, buf), "startup rollback left the writer gate open");
    bufferpoolReuseBuffer(getWorkerBufferPool(0), buf);

    resetFakeThreads(0);
    require(tundeviceBringUp(tdev), "device could not restart after an I/O thread startup exit");
    require(tundeviceBringDown(tdev), "restart after an I/O thread startup exit did not shut down");
    require(shutdown_request_calls == 0, "restarting after a startup exit requested process shutdown");
    tundeviceDestroy(tdev);
}

static void testThreadExitsDuringStartupAreNotPublishedAsUp(void)
{
    testThreadExitDuringStartupRollsBack(1);
    testThreadExitDuringStartupRollsBack(2);
}

// Regression: a reader/writer routine that dies on a device error left `up` set,
// so tundeviceIsUp() kept advertising a device whose reads had silently stopped
// and whose writes only piled into a channel nobody drains. Bring-down then had
// to stay reachable, which is why it can no longer gate on `up` alone.
//
// A published device that loses either I/O thread is also process-fatal, so the
// wrapper must request exactly one orderly shutdown and then return so worker 0
// can join it. @p which selects the reader or the writer body.
static void testUnexpectedThreadExitTakesTheDeviceDown(unsigned int which)
{
    const char *side = (which == kCapturedReaderThread) ? "reader" : "writer";
    discard     side;

    resetFakeThreads(0);
    resetShutdownRequests();
    tun_device_t *tdev = tundeviceCreate("ww-lifetime-test", false, 1500, NULL, observeReadCallback);
    require(tdev != NULL, "unexpected-exit device create failed");

    // Return immediately from the selected body instead of running the real loop.
    if (which == kCapturedReaderThread)
    {
        tunLinuxSetReaderRoutine(tdev, failingIoRoutine);
    }
    else
    {
        tunLinuxSetWriterRoutine(tdev, failingIoRoutine);
    }

    require(tundeviceBringUp(tdev), "unexpected-exit device bring-up failed");
    require(tundeviceIsUp(tdev), "bring-up did not publish the device as up");

    // Run the captured thread body inline: the wrapper sees `running` still set
    // and must treat the return as a device failure.
    runCapturedThreadBody(which);

    require(! tundeviceIsUp(tdev), "an unexpected I/O thread exit left the device advertised as up");
    require(tunLinuxLifecycleState(tdev) == kTunLifecycleFailed,
            "an unexpected I/O thread exit did not publish FAILED");
    require(shutdown_request_calls == 1, "an unexpected exit from a published device did not request shutdown once");
    require(shutdown_request_last_code == 1, "the device failure shutdown request used the wrong exit code");

    // The peer thread returning afterwards observes an already FAILED device and
    // must not request a second shutdown.
    runCapturedThreadBody(which == kCapturedReaderThread ? kCapturedWriterThread : kCapturedReaderThread);
    require(shutdown_request_calls == 1, "the peer I/O thread requested a duplicate shutdown");

    // The teardown must still run: `up` is now false, so a bring-down gated on it
    // would skip both joins and leave the writer channel allocated.
    const unsigned int joins_before = fake_thread_join_calls;
    require(tundeviceBringDown(tdev), "bring-down after an unexpected I/O exit failed");
    require(fake_thread_join_calls == joins_before + 2, "bring-down after a thread failure skipped its joins");
    require(tundeviceBringDown(tdev), "a second bring-down must stay a successful no-op");
    require(fake_thread_join_calls == joins_before + 2, "the no-op bring-down joined an already-joined thread");
    require(shutdown_request_calls == 1, "teardown after a device failure requested shutdown again");

    tundeviceDestroy(tdev);
}

static void testUnexpectedThreadExitsRequestShutdownOnce(void)
{
    testUnexpectedThreadExitTakesTheDeviceDown(kCapturedReaderThread);
    testUnexpectedThreadExitTakesTheDeviceDown(kCapturedWriterThread);
}

// A routine that returns because normal teardown closed/woke it is not a
// failure: the lifecycle has already left the active states, so the wrapper must
// neither publish FAILED nor request shutdown.
static void testNormalStopDoesNotRequestShutdown(void)
{
    resetFakeThreads(0);
    resetShutdownRequests();

    tun_device_t *tdev = tundeviceCreate("ww-lifetime-test", false, 1500, NULL, observeReadCallback);
    require(tdev != NULL, "normal-stop device create failed");

    // Capture both bodies without running them, so they can return after the
    // owner path has already taken the device down.
    tunLinuxSetReaderRoutine(tdev, failingIoRoutine);
    tunLinuxSetWriterRoutine(tdev, failingIoRoutine);
    require(tundeviceBringUp(tdev), "normal-stop device bring-up failed");
    require(tundeviceIsUp(tdev), "bring-up did not publish the device as up");

    require(tundeviceBringDown(tdev), "normal bring-down failed");
    require(tunLinuxLifecycleState(tdev) == kTunLifecycleDown, "normal bring-down did not publish DOWN");

    runCapturedThreadBody(kCapturedReaderThread);
    runCapturedThreadBody(kCapturedWriterThread);

    require(tunLinuxLifecycleState(tdev) == kTunLifecycleDown,
            "a routine returning after a normal stop published FAILED");
    require(shutdown_request_calls == 0, "a routine returning after a normal stop requested process shutdown");

    tundeviceDestroy(tdev);
}

/*
 * A permanent read error must end the read routine so the thread wrapper can
 * publish FAILED and request the orderly shutdown.
 *
 * Before this, the drain helper reported "other error" and the reader loop
 * ignored it: on a dead-but-readable handle that became an unbounded spin that
 * discarded every packet while tundeviceIsUp() still advertised the device.
 */
static void testPermanentReadErrorFailsTheDevice(int io_errno, const char *label)
{
    discard label;

    resetFakeThreads(0);
    resetShutdownRequests();
    resetIoInjection();

    tun_device_t *tdev = tundeviceCreate("ww-lifetime-test", false, 1500, NULL, observeReadCallback);
    require(tdev != NULL, "read-error device create failed");
    require(tundeviceBringUp(tdev), "read-error device bring-up failed");
    require(tundeviceIsUp(tdev), "bring-up did not publish the device as up");

    // Exactly one device read is expected. A reader that swallows the error
    // asks for a second one and trips the wrap's own assertion.
    const injected_io_result_t reads[] = {{.result = -1, .error = io_errno}};
    inject_reader_pollin               = true;
    armDeviceReads(reads, ARRAY_SIZE(reads));

    runCapturedThreadBody(kCapturedReaderThread);

    require(observed_read_calls == 1, "a permanent read error did not end the read routine immediately");
    require(! tundeviceIsUp(tdev), "a permanent read error left the device advertised as up");
    require(tunLinuxLifecycleState(tdev) == kTunLifecycleFailed, "a permanent read error did not publish FAILED");
    require(shutdown_request_calls == 1, "a permanent read error did not request exactly one shutdown");
    require(shutdown_request_last_code == 1, "a permanent read error requested the wrong exit code");

    resetIoInjection();
    require(tundeviceBringDown(tdev), "bring-down after a permanent read error failed");
    tundeviceDestroy(tdev);
}

// EAGAIN means "nothing to read right now", so the reader must go back to
// poll() with the device still up, and only the following permanent error ends
// it. The in-flight check runs on read #2, before the routine has returned.
static void testTransientReadErrorKeepsTheDeviceUp(void)
{
    resetFakeThreads(0);
    resetShutdownRequests();
    resetIoInjection();

    tun_device_t *tdev = tundeviceCreate("ww-lifetime-test", false, 1500, NULL, observeReadCallback);
    require(tdev != NULL, "transient-read device create failed");
    require(tundeviceBringUp(tdev), "transient-read device bring-up failed");

    const injected_io_result_t reads[] = {
        {.result = -1, .error = EAGAIN},
        {.result = -1, .error = EIO},
    };
    inject_reader_pollin = true;
    armDeviceReads(reads, ARRAY_SIZE(reads));
    in_flight_device     = tdev;
    in_flight_check_call = 2;

    runCapturedThreadBody(kCapturedReaderThread);

    require(observed_read_calls == 2, "EAGAIN did not send the reader back to poll()");
    require(in_flight_checks_run == 1, "the in-flight recoverable-error check never ran");
    require(tunLinuxLifecycleState(tdev) == kTunLifecycleFailed,
            "the permanent read error after EAGAIN did not publish FAILED");
    require(shutdown_request_calls == 1, "the permanent read error after EAGAIN did not request one shutdown");

    resetIoInjection();
    require(tundeviceBringDown(tdev), "bring-down after a transient read error failed");
    tundeviceDestroy(tdev);
}

// Queues @p count packets for the writer thread to consume.
static void queuePacketsForWriter(tun_device_t *tdev, unsigned int count)
{
    for (unsigned int i = 0; i < count; i++)
    {
        sbuf_t *buf = bufferpoolGetSmallBuffer(getWorkerBufferPool(0));
        sbufSetLength(buf, 64);
        require(tundeviceWrite(tdev, buf), "queuing a packet for the writer failed");
    }
}

/*
 * A permanent write error must end the write routine.
 *
 * Before this, only a small transient whitelist and EMSGSIZE were handled and
 * everything else fell through to `continue`, so EIO/EBADF/ENODEV silently
 * discarded every packet forever on a device that still looked usable.
 */
static void testPermanentWriteErrorFailsTheDevice(int io_errno, const char *label)
{
    discard label;

    resetFakeThreads(0);
    resetShutdownRequests();
    resetIoInjection();

    // A read callback is required: without one, bring-up creates no reader
    // thread and the writer body would land at the reader's captured index.
    tun_device_t *tdev = createRunningReaderDevice();
    require(tundeviceIsUp(tdev), "bring-up did not publish the device as up");

    // One armed write, two queued packets: a writer that swallows the error
    // reaches for the second packet and trips the wrap's own assertion.
    const injected_io_result_t writes[] = {{.result = -1, .error = io_errno}};
    armDeviceWrites(writes, ARRAY_SIZE(writes));
    queuePacketsForWriter(tdev, 2);

    runCapturedThreadBody(kCapturedWriterThread);

    require(observed_write_calls == 1, "a permanent write error did not end the write routine immediately");
    require(! tundeviceIsUp(tdev), "a permanent write error left the device advertised as up");
    require(tunLinuxLifecycleState(tdev) == kTunLifecycleFailed, "a permanent write error did not publish FAILED");
    require(shutdown_request_calls == 1, "a permanent write error did not request exactly one shutdown");
    require(shutdown_request_last_code == 1, "a permanent write error requested the wrong exit code");

    resetIoInjection();
    require(tundeviceBringDown(tdev), "bring-down after a permanent write error failed");
    tundeviceDestroy(tdev);
}

/*
 * EINVAL condemns one packet, not the device: the kernel rejects a malformed
 * frame that way, and those frames arrive from remote peers. Making it fatal
 * would hand any peer a one-packet process kill, so the writer must drop it and
 * keep going. EAGAIN is likewise recoverable. Only the trailing EIO ends the
 * routine, and the in-flight check proves the device was still up before it.
 */
static void testRecoverableWriteErrorsKeepTheDeviceUp(void)
{
    resetFakeThreads(0);
    resetShutdownRequests();
    resetIoInjection();

    tun_device_t *tdev = createRunningReaderDevice();

    const injected_io_result_t writes[] = {
        {.result = -1, .error = EAGAIN},
        {.result = -1, .error = EINVAL},
        {.result = -1, .error = EIO},
    };
    armDeviceWrites(writes, ARRAY_SIZE(writes));
    in_flight_device     = tdev;
    in_flight_check_call = 3;
    queuePacketsForWriter(tdev, ARRAY_SIZE(writes) + 1);

    runCapturedThreadBody(kCapturedWriterThread);

    require(observed_write_calls == 3, "a recoverable write error ended the write routine");
    require(in_flight_checks_run == 1, "the in-flight recoverable-error check never ran");
    require(tunLinuxLifecycleState(tdev) == kTunLifecycleFailed,
            "the permanent write error after the recoverable ones did not publish FAILED");
    require(shutdown_request_calls == 1, "the permanent write error did not request exactly one shutdown");

    resetIoInjection();
    require(tundeviceBringDown(tdev), "bring-down after recoverable write errors failed");
    tundeviceDestroy(tdev);
}

static void testPermanentIoErrorsReachTheShutdownWrapper(void)
{
    testPermanentReadErrorFailsTheDevice(EIO, "EIO");
    testPermanentReadErrorFailsTheDevice(EBADF, "EBADF");
    testTransientReadErrorKeepsTheDeviceUp();

    // EMSGSIZE only reaches write() when the configured MTU exceeds the real
    // device MTU, because oversized packets are dropped before the syscall. That
    // is an operator misconfiguration that never recovers, so it is terminal.
    testPermanentWriteErrorFailsTheDevice(EMSGSIZE, "EMSGSIZE");
    testPermanentWriteErrorFailsTheDevice(EIO, "EIO");
    testPermanentWriteErrorFailsTheDevice(EBADF, "EBADF");
    testRecoverableWriteErrorsKeepTheDeviceUp();
}

static void testInterfaceDownFailureRemainsRetryable(void)
{
    resetFakeThreads(0);
    tun_device_t *tdev = createRunningReaderDevice();

    fail_interface_down_calls = 1;
    interface_down_attempts   = 0;

    require(! tundeviceBringDown(tdev), "interface-down failure reported successful cleanup");
    require(tunLinuxLifecycleState(tdev) == kTunLifecycleStopping, "interface-down failure did not retain STOPPING");
    require(fake_thread_join_calls == 2, "interface-down failure skipped owned thread joins");
    require(interface_down_attempts == 1, "interface-down failure did not attempt interface cleanup");
    require(! tundeviceBringUp(tdev), "bring-up was accepted while interface cleanup remained incomplete");

    require(tundeviceBringDown(tdev), "interface-down cleanup retry failed");
    require(tunLinuxLifecycleState(tdev) == kTunLifecycleDown, "successful interface-down retry did not publish DOWN");
    require(interface_down_attempts == 2, "cleanup retry did not retry the interface-down operation");
    require(fake_thread_join_calls == 2, "cleanup retry rejoined already released threads");

    tundeviceDestroy(tdev);
}

static void testJoinFailureRetainsOwnershipForRetry(void)
{
    resetFakeThreads(0);
    tun_device_t *tdev = createRunningReaderDevice();

    fail_fake_thread_join_on_call = 1;
    require(! tundeviceBringDown(tdev), "reader join failure reported successful cleanup");
    require(tunLinuxLifecycleState(tdev) == kTunLifecycleStopping,
            "join failure published DOWN while thread ownership remained");
    require(! tundeviceBringUp(tdev), "restart succeeded while failed-join ownership remained");

    fail_fake_thread_join_on_call = 0;
    require(tundeviceBringDown(tdev), "join retry did not complete retained teardown");
    require(tunLinuxLifecycleState(tdev) == kTunLifecycleDown, "join retry did not publish DOWN");
    require(fake_thread_join_calls == 3, "join retry did not target only the retained reader");

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

typedef struct pool_claim_probe_s
{
    buffer_pool_t *pool;
    sbuf_t        *buf;
} pool_claim_probe_t;

// Stands in for the production writer thread, which claims writer_buffer_pool
// the first time it recycles a packet it has written to the device.
static void *writerPoolClaimRoutine(void *userdata)
{
    pool_claim_probe_t *probe = userdata;
    bufferpoolReuseBuffer(probe->pool, probe->buf);
    return NULL;
}

static void testBringDownReleasesQueuedWritesOffTheWriterThread(void)
{
    enum
    {
        kQueuedWrites = 4
    };

    resetFakeThreads(0);
    tun_device_t *tdev = createRunningDevice();

    // Bind writer_buffer_pool to a thread that is not the one running teardown,
    // exactly as the real writer thread does on its first recycled packet.
    pool_claim_probe_t probe = {.pool = tunLinuxWriterBufferPool(tdev),
                                .buf  = bufferpoolGetSmallBuffer(getWorkerBufferPool(0))};
    pthread_t          claimer;
    require(__real_pthread_create(&claimer, NULL, writerPoolClaimRoutine, &probe) == 0,
            "failed to start the writer-pool claim thread");
    require(__real_pthread_join(claimer, NULL) == 0, "failed to join the writer-pool claim thread");

    // Leave packets in the ring, as workers do when a device stops under load.
    for (unsigned int i = 0; i < kQueuedWrites; i++)
    {
        sbuf_t *buf = bufferpoolGetSmallBuffer(getWorkerBufferPool(0));
        sbufSetLength(buf, 64);
        require(tundeviceWrite(tdev, buf), "queuing a write before bring-down failed");
    }

    // Pre-fix this drained on the owner's thread into the writer thread's pool,
    // which aborts the process on the buffer-pool thread check.
    require(tundeviceBringDown(tdev), "bring-down with a non-empty writer channel failed");
    require(! tundeviceIsUp(tdev), "device stayed up after bring-down");

    tundeviceDestroy(tdev);
}

/*
 * When the worker-0 handoff is unavailable, the documented fallback is the hard
 * abort. abortProgramNow() is _Noreturn, so this runs in a forked child and the
 * parent checks the status the wrap function exits with.
 */
static void testHandoffFailureFallsBackToHardAbort(void)
{
    // fork()/waitpid() are wrapped for the device's script-running paths, so
    // this test must reach the real ones to actually spawn a child.
    pid_t child = __real_fork();
    require(child >= 0, "failed to fork the TUN handoff-failure child");

    if (child == 0)
    {
        resetFakeThreads(0);
        resetShutdownRequests();
        shutdown_request_accepts = false;
        hard_abort_is_expected   = true;

        tun_device_t *tdev = tundeviceCreate("ww-lifetime-test", false, 1500, NULL, observeReadCallback);
        if (tdev == NULL)
        {
            _Exit(70);
        }
        tunLinuxSetReaderRoutine(tdev, failingIoRoutine);
        if (! tundeviceBringUp(tdev))
        {
            _Exit(71);
        }

        // The wrapper requests shutdown, is refused, and must hard-abort rather
        // than let the process keep running with a dead TUN device.
        runCapturedThreadBody(kCapturedReaderThread);
        _Exit(72); // must not be reached
    }

    int status = 0;
    require(__real_waitpid(child, &status, 0) == child, "failed to wait for the TUN handoff-failure child");
    require(WIFEXITED(status), "the TUN handoff-failure child did not exit normally");
    require(WEXITSTATUS(status) == kFallbackAbortExitStatus,
            "a refused shutdown request did not fall back to the hard abort");
}

int main(void)
{
    test_env_t env;
    envSetup(&env);
    testQueuedCleanupOutlivesDevice();
    testClosedAndStaleDeliveriesDoNotTouchDevice();
    testBringUpRollsBackThreadCreationFailures();
    testThreadExitsDuringStartupAreNotPublishedAsUp();
    testUnexpectedThreadExitsRequestShutdownOnce();
    testNormalStopDoesNotRequestShutdown();
    testPermanentIoErrorsReachTheShutdownWrapper();
    testHandoffFailureFallsBackToHardAbort();
    testInterfaceDownFailureRemainsRetryable();
    testJoinFailureRetainsOwnershipForRetry();
    testWriterGateQuiescesConcurrentSenders();
    testBringDownReleasesQueuedWritesOffTheWriterThread();
    envTeardown(&env);
    puts("Linux TUN message lifetime tests passed");
    return 0;
}

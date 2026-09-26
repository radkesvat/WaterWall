// Queued-message lifetime coverage for the Linux TUN device.
//
// tun_linux.c is compiled directly into this executable. Privileged device
// syscalls and thread creation are wrapped, while the production BringUp,
// BringDown, queued-message delivery, and cleanup paths run unchanged.

#include "wwapi.h"

#include "devices/tun/tun_linux_gso_limits.h"
#include "devices/tun/tun_linux_internal.h"
#include "loggers/internal_logger.h"
#include "wchecksum.h"
#include "worker_messages.h"

#include "worker_registry_fixture.h"
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <linux/virtio_net.h>
#include <poll.h>
#include <pthread.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

/*
 * Fake worker table for the stubbed GSTATE below. Without it the identity
 * predicates correctly report "not an event worker" and the checked
 * current-worker accessors reject this test.
 */
static test_worker_registry_t g_test_worker_registry;

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
    master_pool_t *medium_master;
    master_pool_t *splice_master;
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
static unsigned int       gso_feature_checks;
static unsigned int       gso_setiff_calls;
static unsigned int       raw_setiff_calls;
static unsigned int       gso_header_size_calls;
static unsigned int       gso_byte_order_calls;
static unsigned int       gso_offload_calls;
static unsigned int       gso_limit_calls;
static unsigned long      fail_gso_ioctl_request;
static int                fail_gso_ioctl_errno;
static bool               gso_feature_available;
static bool               fail_gso_scratch_once;
static unsigned int       gso_scratch_failures;
static char               gso_attach_name[IFNAMSIZ];
static char               raw_attach_name[IFNAMSIZ];
static bool               raw_attach_exclusive;
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

enum
{
    kTunLogCaptureCapacity = 4096
};

static char   tun_log_capture[kTunLogCaptureCapacity];
static size_t tun_log_capture_len;

typedef struct tun_refusal_probe_s
{
    tun_device_t *tdev;
    bool          accepted;
} tun_refusal_probe_t;

#ifdef DEVICE_WRITER_CHANNEL_TEST_HOOKS
typedef struct tun_selected_closed_probe_s
{
    tun_device_t *tdev;
    atomic_bool   selected;
    atomic_bool   resume;
} tun_selected_closed_probe_t;
#endif

int     __real_open(const char *path, int flags, ...);
int     __wrap_open(const char *path, int flags, ...);
int     __wrap_ioctl(int fd, unsigned long request, ...);
int     __real_socket(int domain, int type, int protocol);
int     __wrap_socket(int domain, int type, int protocol);
ssize_t __real_read(int fd, void *buf, size_t count);
ssize_t __wrap_read(int fd, void *buf, size_t count);
ssize_t __real_write(int fd, const void *buf, size_t count);
ssize_t __wrap_write(int fd, const void *buf, size_t count);
ssize_t __real_writev(int fd, const struct iovec *iov, int iovcnt);
ssize_t __wrap_writev(int fd, const struct iovec *iov, int iovcnt);
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
worker_message_submit_result_e __wrap_sendWorkerMessageForceQueueWithCleanup(wid_t wid, WorkerMessageCallback callback,
                                                                             WorkerMessageCleanupCallback cleanup,
                                                                             void *arg1, void *arg2, void *arg3);
void                           __real_memoryFree(void *ptr);
void                           __wrap_memoryFree(void *ptr);
void                           __real_masterpoolDestroy(master_pool_t *pool);
void                           __wrap_masterpoolDestroy(master_pool_t *pool);
void                           __real_bufferpoolReuseBuffer(buffer_pool_t *pool, sbuf_t *buf);
void                           __wrap_bufferpoolReuseBuffer(buffer_pool_t *pool, sbuf_t *buf);
sbuf_t                        *__real_sbufTryCreateWithPadding(uint32_t minimum_capacity, uint16_t pad_left);
sbuf_t                        *__wrap_sbufTryCreateWithPadding(uint32_t minimum_capacity, uint16_t pad_left);
void                           __real_sbufDestroy(sbuf_t *buf);
void                           __wrap_sbufDestroy(sbuf_t *buf);
bool __wrap_tunLinuxGsoMaxSegmentsConfigure(const char *ifname, uint32_t requested, uint32_t *active);

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
    ssize_t        result; // Bytes to report; 0 for end of stream, -1 for an error.
    int            error;  // errno to publish when result is -1.
    const uint8_t *bytes;
} injected_io_result_t;

static int                      tun_handle_fd = -1;
static injected_io_result_t     injected_reads[kMaxInjectedIoResults];
static unsigned int             injected_read_count;
static unsigned int             observed_read_calls;
static injected_io_result_t     injected_writes[kMaxInjectedIoResults];
static unsigned int             injected_write_count;
static unsigned int             observed_write_calls;
static unsigned int             observed_writev_calls;
static size_t                   largest_writev_packet;
static bool                     inject_reader_pollin;
static bool                     inject_gso_reader_poll;
static bool                     stop_gso_reader_on_budget_wait;
static unsigned int             gso_budget_wake_polls;
static unsigned int             gso_device_ready_polls;
static unsigned int             gso_messages_delivered;
static unsigned int             gso_deliver_after_read_calls;
static bool                     verify_gso_scratch_overwrite;
static unsigned int             ordinary_after_gso_deliveries;
static device_reader_session_t *gso_probe_session;
static sbuf_t                  *gso_scratch_buffer;
static unsigned int             gso_scratch_destroy_count;
static bool                     deliver_fragment_batch;
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

static void captureTunLog(int log_level, const char *buf, int len)
{
    discard log_level;
    if (buf == NULL || len <= 0 || tun_log_capture_len >= sizeof(tun_log_capture) - 1U)
    {
        return;
    }
    const size_t copy_len = min((size_t) len, sizeof(tun_log_capture) - tun_log_capture_len - 1U);
    memoryCopy(tun_log_capture + tun_log_capture_len, buf, copy_len);
    tun_log_capture_len += copy_len;
    tun_log_capture[tun_log_capture_len] = '\0';
}

static void resetTunLogCapture(void)
{
    memoryZero(tun_log_capture, sizeof(tun_log_capture));
    tun_log_capture_len = 0;
}

static unsigned int countTunLogSubstring(const char *needle)
{
    unsigned int count  = 0;
    const char  *match  = tun_log_capture;
    const size_t length = strlen(needle);
    while ((match = strstr(match, needle)) != NULL)
    {
        ++count;
        match += length;
    }
    return count;
}

/* The fake pthread wrapper executes a device body inline, but its production
 * contract is still that of an auxiliary, unregistered thread. */
static void runAuxiliaryThreadBody(void *(*routine)(void *), void *arg)
{
    const wid_t saved_wid = getWID();
    testWorkerUnbindWID();
    discard routine(arg);
    testWorkerBindWID(saved_wid);
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
    if (request == TUNSETOFFLOAD)
    {
        const unsigned long flags = va_arg(args, unsigned long);
        va_end(args);
        gso_offload_calls++;
        require(flags == (TUN_F_CSUM | TUN_F_TSO4), "GSO setup advertised unexpected offload flags");
        if (fail_gso_ioctl_request == request)
        {
            errno = fail_gso_ioctl_errno;
            return -1;
        }
        return 0;
    }
    void *argument = va_arg(args, void *);
    va_end(args);

    if (request == TUNGETFEATURES)
    {
        gso_feature_checks++;
        *(unsigned int *) argument = gso_feature_available ? IFF_VNET_HDR : 0;
    }
    else if (request == TUNSETIFF)
    {
        struct ifreq *ifr = argument;
        if ((ifr->ifr_flags & IFF_VNET_HDR) != 0)
        {
            gso_setiff_calls++;
            memoryCopy(gso_attach_name, ifr->ifr_name, IFNAMSIZ);
            require((ifr->ifr_flags & IFF_TUN_EXCL) != 0, "GSO setup omitted exclusive TUN attach");
        }
        else
        {
            raw_setiff_calls++;
            memoryCopy(raw_attach_name, ifr->ifr_name, IFNAMSIZ);
            raw_attach_exclusive = (ifr->ifr_flags & IFF_TUN_EXCL) != 0;
        }
        if (fail_gso_ioctl_request == request && (ifr->ifr_flags & IFF_VNET_HDR) != 0)
        {
            errno = fail_gso_ioctl_errno;
            return -1;
        }
        stringCopyN(ifr->ifr_name, "ww-lifetime-test", IFNAMSIZ);
        ifr->ifr_name[IFNAMSIZ - 1] = '\0';
    }
    else if (request == TUNSETVNETHDRSZ)
    {
        gso_header_size_calls++;
        require(*(int *) argument == 10, "GSO setup selected an unexpected virtio header size");
    }
    else if (request == TUNSETVNETLE)
    {
        gso_byte_order_calls++;
        require(*(int *) argument == 1, "GSO setup did not select little-endian metadata");
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
    if (fail_gso_ioctl_request == request && request != TUNSETIFF)
    {
        errno = fail_gso_ioctl_errno;
        return -1;
    }
    return 0;
}

bool __wrap_tunLinuxGsoMaxSegmentsConfigure(const char *ifname, uint32_t requested, uint32_t *active)
{
    require(strncmp(ifname, "ww-lifetime-test", IFNAMSIZ - 1) == 0, "GSO limit targeted the wrong interface");
    require(requested == kTunLinuxRequestedGsoMaxSegments, "GSO limit request changed unexpectedly");
    gso_limit_calls++;
    *active = requested;
    return true;
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
        if (injected_reads[index].bytes != NULL)
        {
            require(injected_reads[index].result > 0 && (size_t) injected_reads[index].result <= count,
                    "injected packet too large");
            memoryCopy(buf, injected_reads[index].bytes, (size_t) injected_reads[index].result);
        }
        if (verify_gso_scratch_overwrite && index == 1)
        {
            require(gso_messages_delivered == 0 && captured_message_count == 3,
                    "GSO output reached a worker before the next TUN record overwrote scratch");
        }
        if (deliver_fragment_batch && index == 3)
        {
            require(captured_message_count == 1, "reader did not flush one fragment batch");
            testWorkerBindWID(0);
            worker_t            worker  = {.wid = 0};
            captured_message_t *message = &captured_messages[0];
            message->callback(&worker, message->arg1, message->arg2, message->arg3);
            testWorkerUnbindWID();
            captured_message_count = 0;
        }
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

ssize_t __wrap_writev(int fd, const struct iovec *iov, int iovcnt)
{
    if (fd == tun_handle_fd)
    {
        require(iovcnt == 2 && iov[0].iov_len == 10, "GSO writer did not use one virtio-framed writev");
        const uint8_t *header = iov[0].iov_base;
        for (unsigned int i = 0; i < 10; ++i)
        {
            require(header[i] == 0, "GSO writer emitted nonzero metadata for an ordinary packet");
        }
        largest_writev_packet = max(largest_writev_packet, iov[1].iov_len);
        if (injected_write_count > 0)
        {
            require(observed_writev_calls < injected_write_count,
                    "the GSO writer continued after a permanent descriptor error");
            const unsigned int index = observed_writev_calls++;
            checkInFlightExpectations(index + 1);
            return applyInjectedIoResult(&injected_writes[index]);
        }
    }
    return __real_writev(fd, iov, iovcnt);
}

static void deliverNextGsoMessage(void)
{
    require(gso_messages_delivered < captured_message_count, "no queued GSO message to settle");
    testWorkerBindWID(0);
    worker_t            worker  = {.wid = 0};
    captured_message_t *message = &captured_messages[gso_messages_delivered++];
    message->callback(&worker, message->arg1, message->arg2, message->arg3);
    testWorkerUnbindWID();
}

int __wrap_poll(struct pollfd *fds, nfds_t nfds, int timeout)
{
    if (inject_gso_reader_poll && nfds == 3)
    {
        if ((fds[2].events & POLLIN) != 0)
        {
            require(gso_probe_session != NULL &&
                        atomic_load_explicit(&gso_probe_session->output_packets, memory_order_acquire) == 1 &&
                        atomic_load_explicit(&gso_probe_session->output_charge, memory_order_acquire) <=
                            gso_probe_session->output_charge_limit,
                    "pending GSO output exceeded its packet or allocation budget");
            if (stop_gso_reader_on_budget_wait)
            {
                fds[0].revents = 0;
                fds[1].revents = POLLIN;
                fds[2].revents = 0;
                return 1;
            }
            deliverNextGsoMessage();
            gso_budget_wake_polls++;
            const int ready = __real_poll(fds, nfds, 0);
            require(ready > 0 && (fds[2].revents & POLLIN), "budget release did not wake GSO reader via eventfd");
            return ready;
        }
        require((fds[0].events & POLLIN) != 0, "GSO reader polled no descriptor while unblocked");
        if (observed_read_calls >= gso_deliver_after_read_calls)
        {
            while (gso_messages_delivered < captured_message_count)
            {
                deliverNextGsoMessage();
            }
        }
        fds[0].revents = POLLIN;
        fds[1].revents = 0;
        fds[2].revents = 0;
        gso_device_ready_polls++;
        return 1;
    }
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
        runAuxiliaryThreadBody(routine, arg);
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

worker_message_submit_result_e __wrap_sendWorkerMessageForceQueueWithCleanup(wid_t wid, WorkerMessageCallback callback,
                                                                             WorkerMessageCleanupCallback cleanup,
                                                                             void *arg1, void *arg2, void *arg3)
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
        require(atomic_load_explicit(&tracked_session->output_packets, memory_order_acquire) == 0 &&
                    atomic_load_explicit(&tracked_session->output_charge, memory_order_acquire) == 0,
                "reader session was freed with outstanding GSO output reservations");
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

sbuf_t *__wrap_sbufTryCreateWithPadding(uint32_t minimum_capacity, uint16_t pad_left)
{
    if (fail_gso_scratch_once && minimum_capacity == 65536 && pad_left >= 10)
    {
        fail_gso_scratch_once = false;
        gso_scratch_failures++;
        errno = ENOMEM;
        return NULL;
    }
    sbuf_t *buf = __real_sbufTryCreateWithPadding(minimum_capacity, pad_left);
    if (minimum_capacity == 65536 && pad_left >= 10)
    {
        gso_scratch_buffer = buf;
    }
    return buf;
}

void __wrap_sbufDestroy(sbuf_t *buf)
{
    if (buf == gso_scratch_buffer)
    {
        gso_scratch_destroy_count++;
    }
    __real_sbufDestroy(buf);
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
    injected_read_count            = 0;
    observed_read_calls            = 0;
    injected_write_count           = 0;
    observed_write_calls           = 0;
    observed_writev_calls          = 0;
    largest_writev_packet          = 0;
    inject_reader_pollin           = false;
    inject_gso_reader_poll         = false;
    stop_gso_reader_on_budget_wait = false;
    gso_budget_wake_polls          = 0;
    gso_device_ready_polls         = 0;
    gso_messages_delivered         = 0;
    gso_deliver_after_read_calls   = 1;
    verify_gso_scratch_overwrite   = false;
    ordinary_after_gso_deliveries  = 0;
    gso_probe_session              = NULL;
    gso_scratch_buffer             = NULL;
    gso_scratch_destroy_count      = 0;
    in_flight_device               = NULL;
    in_flight_check_call           = 0;
    in_flight_checks_run           = 0;
}

static void resetGsoSetup(void)
{
    gso_feature_checks     = 0;
    gso_setiff_calls       = 0;
    raw_setiff_calls       = 0;
    gso_header_size_calls  = 0;
    gso_byte_order_calls   = 0;
    gso_offload_calls      = 0;
    gso_limit_calls        = 0;
    fail_gso_ioctl_request = 0;
    fail_gso_ioctl_errno   = EOPNOTSUPP;
    gso_feature_available  = true;
    fail_gso_scratch_once  = false;
    gso_scratch_failures   = 0;
    memoryZero(gso_attach_name, sizeof(gso_attach_name));
    memoryZero(raw_attach_name, sizeof(raw_attach_name));
    raw_attach_exclusive      = false;
    gso_scratch_buffer        = NULL;
    gso_scratch_destroy_count = 0;
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
    env->medium_master      = masterpoolCreateWithCapacity(16);
    env->splice_master      = masterpoolCreateWithCapacity(16);
    env->worker_buffer_pool = bufferpoolCreate(env->large_master,
                                               env->medium_master,
                                               env->small_master,
                                               env->splice_master,
                                               16,
                                               8192,
                                               MEDIUM_BUFFER_SIZE_RAM_HIGH,
                                               4096,
                                               8192,
                                               8192);
    env->buffer_pools[0]    = env->worker_buffer_pool;
    env->loops[0]           = (wloop_t *) (void *) env;

    GSTATE.masterpool_buffer_pools_large = env->large_master;
    GSTATE.masterpool_buffer_pools_small = env->small_master;
    GSTATE.masterpool_buffer_pools_medium = env->medium_master;
    GSTATE.masterpool_buffer_pools_splice = env->splice_master;
    GSTATE.shortcut_buffer_pools         = env->buffer_pools;
    GSTATE.shortcut_loops                = env->loops;
    GSTATE.workers_count                 = 2;
    testWorkerRegistryInstall(&g_test_worker_registry);
    GSTATE.ram_profile = 1;
    testWorkerBindWID(0);
}

static void envTeardown(test_env_t *env)
{
    GSTATE.masterpool_buffer_pools_large = NULL;
    GSTATE.masterpool_buffer_pools_small = NULL;
    GSTATE.masterpool_buffer_pools_medium = NULL;
    GSTATE.masterpool_buffer_pools_splice = NULL;
    GSTATE.shortcut_buffer_pools         = NULL;
    GSTATE.shortcut_loops                = NULL;
    GSTATE.workers_count                 = 0;
    testWorkerRegistryRestore(&g_test_worker_registry);

    bufferpoolDestroy(env->worker_buffer_pool);
    masterpoolMakeEmpty(env->large_master);
    masterpoolMakeEmpty(env->small_master);
    masterpoolMakeEmpty(env->medium_master);
    masterpoolMakeEmpty(env->splice_master);
    masterpoolDestroy(env->large_master);
    masterpoolDestroy(env->small_master);
    masterpoolDestroy(env->medium_master);
    masterpoolDestroy(env->splice_master);
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

// Runs one captured device I/O thread body inline. Emulate the real auxiliary
// thread's unregistered identity while the production wrapper runs; the test
// process itself is deliberately bound to worker zero.
static void runCapturedThreadBody(unsigned int index)
{
    require(index < kMaxCapturedThreads, "invalid captured thread index");
    require(captured_thread_routines[index] != NULL, "the requested thread body was not captured");
    runAuxiliaryThreadBody(captured_thread_routines[index], captured_thread_args[index]);
}

static tun_device_t *createRunningDevice(void)
{
    tun_device_t *tdev = tundeviceCreate("ww-lifetime-test", false, 1500, NULL, NULL, kDeviceFragmentPreserve);
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
    tun_device_t *tdev =
        tundeviceCreate("ww-lifetime-test", false, 1500, NULL, observeReadCallback, kDeviceFragmentPreserve);
    require(tdev != NULL, "production reader-device create failed");
    require(tundeviceBringUp(tdev), "production reader-device bring-up failed");
    return tdev;
}

static tun_device_t *createRunningGsoReaderDevice(TunReadEventHandle callback)
{
    resetFakeThreads(0);
    resetGsoSetup();
    tun_device_t *tdev = tundeviceCreate("ww-lifetime-test", true, 1500, NULL, callback, kDeviceFragmentPreserve);
    require(tdev != NULL, "GSO reader-device create failed");
    require(deviceReaderSessionOutputWakeFd(tunLinuxReaderSession(tdev)) >= 0,
            "GSO reader-device was not configured with output credits");
    require(gso_feature_checks == 1 && gso_setiff_calls == 1 && raw_setiff_calls == 0 && gso_header_size_calls == 1 &&
                gso_byte_order_calls == 1 && gso_offload_calls == 1 && gso_limit_calls == 1,
            "GSO setup skipped or repeated one negotiated descriptor step");
    require(tundeviceBringUp(tdev), "GSO reader-device bring-up failed");
    return tdev;
}

static void testGsoNegotiationAndRawFallback(void)
{
    const unsigned long failing_requests[] = {TUNGETFEATURES, TUNSETIFF, TUNSETVNETHDRSZ, TUNSETVNETLE, TUNSETOFFLOAD};
    for (unsigned int i = 0; i < ARRAY_SIZE(failing_requests); ++i)
    {
        resetFakeThreads(0);
        resetGsoSetup();
        resetTunLogCapture();
        fail_gso_ioctl_request = failing_requests[i];
        tun_device_t *tdev     = tundeviceCreate("ww-lifetime-test", true, 1500, NULL, NULL, kDeviceFragmentPreserve);
        require(tdev != NULL, "GSO setup failure did not fall back to a raw-IP descriptor");
        require(deviceReaderSessionOutputWakeFd(tunLinuxReaderSession(tdev)) < 0,
                "raw-IP fallback incorrectly configured GSO output credits");
        require(raw_setiff_calls == 1 && gso_feature_checks == 1,
                "GSO fallback did not retry exactly one raw descriptor");
        require(countTunLogSubstring("falling back to raw-IP TUN") == 1,
                "GSO setup fallback did not emit one runtime diagnostic");
        tundeviceDestroy(tdev);
    }

    resetFakeThreads(0);
    resetGsoSetup();
    fail_gso_ioctl_request = TUNSETIFF;
    fail_gso_ioctl_errno   = EBUSY;
    tun_device_t *conflict = tundeviceCreate("ww-lifetime-test", true, 1500, NULL, NULL, kDeviceFragmentPreserve);
    require(conflict == NULL && raw_setiff_calls == 0,
            "exclusive GSO name conflict unexpectedly fell back onto the same TUN name");

    resetGsoSetup();
    resetFakeThreads(0);
    tun_device_t *active = tundeviceCreate("ww-lifetime-test", true, 1500, NULL, NULL, kDeviceFragmentPreserve);
    require(active != NULL && deviceReaderSessionOutputWakeFd(tunLinuxReaderSession(active)) >= 0,
            "supported GSO descriptor did not activate offload mode");
    require(gso_feature_checks == 1 && gso_setiff_calls == 1 && raw_setiff_calls == 0 && gso_header_size_calls == 1 &&
                gso_byte_order_calls == 1 && gso_offload_calls == 1 && gso_limit_calls == 1,
            "supported GSO setup did not complete every descriptor step exactly once");
    tundeviceDestroy(active);
}

static void testGsoScratchAllocationFallsBackToRaw(void)
{
    resetFakeThreads(0);
    resetGsoSetup();
    resetTunLogCapture();
    fail_gso_scratch_once = true;

    tun_device_t *tdev = tundeviceCreate("ww-lifetime-test", true, 1500, NULL, NULL, kDeviceFragmentPreserve);
    require(tdev != NULL, "GSO scratch-allocation failure did not fall back to raw TUN");
    require(gso_scratch_failures == 1 && ! fail_gso_scratch_once,
            "GSO scratch-allocation injection did not hit exactly one scratch request");
    require(gso_setiff_calls == 1 && raw_setiff_calls == 1 && raw_attach_exclusive &&
                memoryEqual(gso_attach_name, raw_attach_name, IFNAMSIZ),
            "scratch failure did not reopen the same exclusive TUN name in raw mode");
    require(deviceReaderSessionOutputWakeFd(tunLinuxReaderSession(tdev)) < 0,
            "scratch failure left offload output credits active on raw TUN");
    require(countTunLogSubstring("GSO receive scratch unavailable") == 1 &&
                countTunLogSubstring("falling back to raw-IP TUN") == 1,
            "scratch failure did not explain the one-time raw fallback");
    require(tundeviceBringUp(tdev), "raw TUN fallback after scratch failure did not start");
    require(tundeviceBringDown(tdev), "raw TUN fallback after scratch failure did not stop");
    tundeviceDestroy(tdev);
}

static void *tunRefusalWriterRoutine(void *userdata)
{
    tun_refusal_probe_t *probe = userdata;
    sbuf_t              *buf   = sbufCreate(64);
    require(buf != NULL, "failed to create fresh TUN refusal helper buffer");
    sbufSetLength(buf, 64);
    probe->accepted = tundeviceWrite(probe->tdev, buf);
    if (! probe->accepted)
    {
        sbufDestroy(buf);
    }
    return NULL;
}

static void runFreshTunRefusalThread(tun_refusal_probe_t *probe)
{
    pthread_t thread;
    require(__real_pthread_create(&thread, NULL, tunRefusalWriterRoutine, probe) == 0,
            "failed to create fresh TUN refusal helper thread");
    require(__real_pthread_join(thread, NULL) == 0, "failed to join fresh TUN refusal helper thread");
    require(! probe->accepted, "TUN refusal helper unexpectedly transferred caller buffer ownership");
}

#ifdef DEVICE_WRITER_CHANNEL_TEST_HOOKS
static void pauseTunWriterAfterGenerationSelect(device_writer_channel_t    *writer_channel,
                                                device_writer_generation_t *generation, void *context)
{
    tun_selected_closed_probe_t *probe = context;
    discard                      generation;
    require(writer_channel == tunLinuxWriterChannel(probe->tdev),
            "TUN closed-refusal hook selected the wrong writer generation");
    atomicStoreExplicit(&probe->selected, true, memory_order_release);
    while (! atomicLoadExplicit(&probe->resume, memory_order_acquire))
    {
        YIELD_THREAD();
    }
}
#endif

static void reopenTunWriterChannelWithCapacityOne(tun_device_t *tdev)
{
    device_writer_channel_t *writer_channel = tunLinuxWriterChannel(tdev);
    deviceWriterChannelClose(writer_channel);
    require(deviceWriterChannelRetireCurrent(writer_channel), "failed to retire synthetic TUN writer generation");
    require(deviceWriterChannelOpen(writer_channel, 1), "failed to open synthetic capacity-one TUN writer generation");
}

static void testTunWriterRefusalClassesUseFreshTlsState(void)
{
    /* Down reaches the actual Linux TUN device layer without a published writer
     * generation. A fresh helper starts its sparse TLS sampler at ordinal one. */
    resetFakeThreads(0);
    tun_device_t *tdev = tundeviceCreate("ww-lifetime-test", false, 1500, NULL, NULL, kDeviceFragmentPreserve);
    require(tdev != NULL, "failed to create down TUN refusal fixture");
    tun_refusal_probe_t down = {.tdev = tdev};
    resetTunLogCapture();
    runFreshTunRefusalThread(&down);
    require(countTunLogSubstring("TunDevice: write failed, device is down") == 1,
            "fresh TUN writer thread did not emit exactly its first Down diagnostic");
    tundeviceDestroy(tdev);

    /* The real wrapper remains UP while its test fixture replaces the large
     * production generation with a capacity-one open one. Full is silent. */
    resetFakeThreads(0);
    tdev = createRunningDevice();
    reopenTunWriterChannelWithCapacityOne(tdev);
    sbuf_t *prefill = sbufCreate(64);
    require(prefill != NULL, "failed to create TUN Full-refusal prefill buffer");
    sbufSetLength(prefill, 64);
    require(tundeviceWrite(tdev, prefill), "failed to prefill capacity-one TUN writer generation");
    tun_refusal_probe_t full = {.tdev = tdev};
    resetTunLogCapture();
    runFreshTunRefusalThread(&full);
    require(tun_log_capture_len == 0, "TUN Full refusal emitted a diagnostic");
    require(tundeviceBringDown(tdev), "failed to bring down TUN Full-refusal fixture");
    tundeviceDestroy(tdev);

#ifdef DEVICE_WRITER_CHANNEL_TEST_HOOKS
    resetFakeThreads(0);
    tdev = createRunningDevice();
    reopenTunWriterChannelWithCapacityOne(tdev);
    tun_selected_closed_probe_t selected = {.tdev = tdev, .selected = false, .resume = false};
    deviceWriterChannelInstallAfterSelectHook(pauseTunWriterAfterGenerationSelect, &selected);
    tun_refusal_probe_t closed = {.tdev = tdev};
    pthread_t           thread;
    resetTunLogCapture();
    require(__real_pthread_create(&thread, NULL, tunRefusalWriterRoutine, &closed) == 0,
            "failed to create fresh TUN Closed-refusal helper thread");
    while (! atomicLoadExplicit(&selected.selected, memory_order_acquire))
    {
        YIELD_THREAD();
    }
    deviceWriterChannelClose(tunLinuxWriterChannel(tdev));
    atomicStoreExplicit(&selected.resume, true, memory_order_release);
    require(__real_pthread_join(thread, NULL) == 0, "failed to join TUN Closed-refusal helper thread");
    deviceWriterChannelInstallAfterSelectHook(NULL, NULL);
    require(! closed.accepted, "selected TUN Closed-refusal helper unexpectedly accepted caller ownership");
    require(countTunLogSubstring("TunDevice: write failed, channel was closed") == 1,
            "fresh TUN writer thread did not emit exactly its first Closed diagnostic");
    require(tundeviceBringDown(tdev), "failed to bring down TUN Closed-refusal fixture");
    tundeviceDestroy(tdev);
#endif
}

static void postOne(tun_device_t *tdev, sbuf_t *buf)
{
    unsigned int before = captured_message_count;
    deviceReaderSessionPost(tunLinuxReaderSession(tdev), 0, &buf, 1);
    require(captured_message_count == before + 1, "production distribution did not post one message");
    require(captured_messages[before].callback != NULL, "production distribution omitted its delivery callback");
    require(captured_messages[before].cleanup != NULL, "production distribution omitted its cleanup callback");
}

static void deliverMessage(unsigned int index, worker_t *worker)
{
    captured_message_t *message = &captured_messages[index];
    message->callback(worker, message->arg1, message->arg2, message->arg3);
}

static void cleanupMessage(unsigned int index)
{
    captured_message_t *message = &captured_messages[index];
    message->cleanup(message->arg1, message->arg2, message->arg3, kWorkerMessageCancelQuiesced);
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
    require(! quiescenceGateEnter(&session->delivery_gate), "delivery gate accepted an entry after bring-down");

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
        tun_device_t *tdev =
            tundeviceCreate("ww-lifetime-test", false, 1500, NULL, observeReadCallback, kDeviceFragmentPreserve);
        require(tdev != NULL, "thread-failure device create failed");

        device_reader_session_t *session           = tunLinuxReaderSession(tdev);
        uint32_t                 failed_generation = (uint32_t) atomicLoadRelaxed(&session->generation) + 1U;
        require(! tundeviceBringUp(tdev), "bring-up unexpectedly survived a thread-creation failure");
        require(fake_thread_create_calls == failed_call, "bring-up failed on the wrong thread-creation call");
        require(fake_thread_join_calls == (failed_call == 2 ? 1U : 0U),
                "bring-up rollback joined the wrong number of started threads");
        require(! tundeviceIsUp(tdev), "thread-creation rollback left the device up");
        require(! quiescenceGateIsActive(&session->delivery_gate),
                "thread-creation rollback left the delivery gate open");
        require(atomicLoadExplicit(&session->refcount, memory_order_acquire) == 1,
                "thread-creation rollback leaked a reader-session reference");
        require((uint32_t) atomicLoadRelaxed(&session->generation) == failed_generation,
                "failed bring-up did not stamp exactly one reader generation");

        resetFakeThreads(0);
        require(tundeviceBringUp(tdev), "device could not restart after thread-creation rollback");
        require((uint32_t) atomicLoadRelaxed(&session->generation) == failed_generation + 1U,
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

    tun_device_t *tdev =
        tundeviceCreate("ww-lifetime-test", false, 1500, NULL, observeReadCallback, kDeviceFragmentPreserve);
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
    uint32_t                 failed_generation = (uint32_t) atomicLoadRelaxed(&session->generation) + 1U;

    require(! tundeviceBringUp(tdev), "bring-up survived an I/O thread exiting during startup");
    require(fake_thread_create_calls == exit_on_create_call, "startup rollback created an unexpected thread");
    require(fake_thread_join_calls == exit_on_create_call, "startup rollback did not join every created thread");
    require(! tundeviceIsUp(tdev), "startup rollback left the device advertised as up");
    require(tunLinuxLifecycleState(tdev) == kTunLifecycleDown, "startup rollback did not publish final DOWN");
    require(! quiescenceGateIsActive(&session->delivery_gate), "startup rollback left the delivery gate open");
    require(atomicLoadExplicit(&session->refcount, memory_order_acquire) == 1,
            "startup rollback leaked a reader-session reference");
    require((uint32_t) atomicLoadRelaxed(&session->generation) == failed_generation,
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
    tun_device_t *tdev =
        tundeviceCreate("ww-lifetime-test", false, 1500, NULL, observeReadCallback, kDeviceFragmentPreserve);
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

    tun_device_t *tdev =
        tundeviceCreate("ww-lifetime-test", false, 1500, NULL, observeReadCallback, kDeviceFragmentPreserve);
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

    tun_device_t *tdev =
        tundeviceCreate("ww-lifetime-test", false, 1500, NULL, observeReadCallback, kDeviceFragmentPreserve);
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

    tun_device_t *tdev =
        tundeviceCreate("ww-lifetime-test", false, 1500, NULL, observeReadCallback, kDeviceFragmentPreserve);
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

        tun_device_t *tdev =
            tundeviceCreate("ww-lifetime-test", false, 1500, NULL, observeReadCallback, kDeviceFragmentPreserve);
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

static unsigned fragment_deliveries;
static bool     normalized_delivery;
static void     observeFragmentPacket(tun_device_t *tdev, void *userdata, sbuf_t *buf, uint8_t wid)
{
    discard        tdev;
    discard        userdata;
    const uint8_t *bytes = sbufGetRawPtr(buf);
    if (normalized_delivery)
    {
        require(fragment_deliveries == 0 && sbufGetLength(buf) == 148 && GET_BE16(bytes + 6) == 0,
                "normalized backend emitted a fragment");
        for (unsigned i = 0; i < 128; ++i)
            require(bytes[20 + i] == (uint8_t) i, "normalized backend changed payload");
    }
    else
    {
        require(sbufGetLength(buf) == 84 && GET_BE16(bytes + 6) == (fragment_deliveries == 0 ? 8 : 0x2000),
                "raw backend changed fragment order/size");
        unsigned start = fragment_deliveries == 0 ? 64 : 0;
        for (unsigned i = 0; i < 64; ++i)
            require(bytes[20 + i] == (uint8_t) (start + i), "raw backend changed bytes");
    }
    ++fragment_deliveries;
    bufferpoolReuseBuffer(getWorkerBufferPool(wid), buf);
}
static void testReaderFragmentPolicy(bool normalized)
{
    resetFakeThreads(0);
    resetShutdownRequests();
    resetIoInjection();
    resetCapturedMessages();
    uint8_t packets[2][84] = {{0}};
    for (unsigned part = 0; part < 2; ++part)
    {
        uint8_t *p = packets[part];
        p[0]       = 0x45;
        p[8]       = 64;
        p[9]       = 17;
        PUT_BE16(p + 2, 84);
        PUT_BE16(p + 4, 42);
        PUT_BE16(p + 6, part ? 8 : 0x2000);
        PUT_BE32(p + 12, 0x0a000001);
        PUT_BE32(p + 16, 0xc0000201);
        for (unsigned i = 0; i < 64; ++i)
            p[20 + i] = (uint8_t) (part * 64 + i);
        uint32_t sum = 0;
        for (unsigned i = 0; i < 20; i += 2)
            sum += GET_BE16(p + i);
        while (sum >> 16)
            sum = (sum & 65535) + (sum >> 16);
        PUT_BE16(p + 10, (uint16_t) ~sum);
    }
    tun_device_t *tdev = tundeviceCreate("ww-fragment-test",
                                         false,
                                         1500,
                                         NULL,
                                         observeFragmentPacket,
                                         normalized ? kDeviceFragmentReassemble : kDeviceFragmentPreserve);
    require(tdev && tundeviceBringUp(tdev), "fragment backend setup failed");
    const injected_io_result_t reads[] = {{.result = 84, .bytes = packets[1]},
                                          {.result = 84, .bytes = packets[0]},
                                          {.result = -1, .error = EAGAIN},
                                          {.result = -1, .error = EIO}};
    normalized_delivery                = normalized;
    fragment_deliveries                = 0;
    deliver_fragment_batch             = true;
    inject_reader_pollin               = true;
    armDeviceReads(reads, ARRAY_SIZE(reads));
    runCapturedThreadBody(kCapturedReaderThread);
    deliver_fragment_batch = false;
    require(fragment_deliveries == (normalized ? 1U : 2U), "backend policy lost/duplicated packets");
    resetIoInjection();
    require(tundeviceBringDown(tdev), "fragment backend shutdown failed");
    tundeviceDestroy(tdev);
}

enum
{
    kGsoFixtureIpLength = 43,
    kGsoFixtureRecordLength = 10 + kGsoFixtureIpLength
};

static void makeSmallGsoRecord(uint8_t record[kGsoFixtureRecordLength])
{
    memoryZero(record, kGsoFixtureRecordLength);
    record[1]   = VIRTIO_NET_HDR_GSO_TCPV4;
    record[2]   = 40; /* IPv4 and TCP header bytes, little endian. */
    record[4]   = 1;  /* One data byte per segment. */
    uint8_t *ip = record + 10;
    ip[0]       = 0x45;
    PUT_BE16(ip + 2, kGsoFixtureIpLength);
    PUT_BE16(ip + 4, 0x1234);
    ip[8] = 64;
    ip[9] = 6;
    PUT_BE32(ip + 12, 0x0a000001);
    PUT_BE32(ip + 16, 0x0a000002);
    PUT_BE16(ip + 20, 1234);
    PUT_BE16(ip + 22, 443);
    PUT_BE32(ip + 24, 1000);
    ip[32] = 0x50;
    ip[33] = 0x19; /* ACK, PSH, FIN. */
    PUT_BE16(ip + 34, 4096);
    ip[40]       = 'A';
    ip[41]       = 'B';
    ip[42]       = 'C';
    uint32_t sum = 0;
    for (unsigned int i = 0; i < 20; i += 2)
    {
        sum += GET_BE16(ip + i);
    }
    while (sum >> 16)
    {
        sum = (sum & 0xffffU) + (sum >> 16);
    }
    PUT_BE16(ip + 10, (uint16_t) ~sum);
}

static uint32_t gsoChecksumWords(const uint8_t *bytes, size_t length, uint32_t sum)
{
    for (size_t i = 0; i < length; i += 2)
    {
        sum += (uint32_t) bytes[i] << 8U;
        if (i + 1 < length)
        {
            sum += bytes[i + 1];
        }
    }
    while ((sum >> 16U) != 0)
    {
        sum = (sum & UINT32_C(0xFFFF)) + (sum >> 16U);
    }
    return sum;
}

static bool gsoSegmentChecksumsValid(const uint8_t *ip, size_t length)
{
    if (length < 40 || gsoChecksumWords(ip, 20, 0) != UINT16_MAX)
    {
        return false;
    }
    uint32_t sum = gsoChecksumWords(ip + 12, 8, 0);
    sum += 6U + (uint32_t) (length - 20);
    return gsoChecksumWords(ip + 20, length - 20, sum) == UINT16_MAX;
}

static void observeGsoSegment(tun_device_t *tdev, void *userdata, sbuf_t *buf, uint8_t wid)
{
    discard        tdev;
    discard        userdata;
    const uint8_t *ip = sbufGetRawPtr(buf);
    require(currentThreadIsEventWorkerWID(wid), "GSO checksum completion was not published on the event worker");
    require(gso_probe_session != NULL &&
                atomic_load_explicit(&gso_probe_session->output_packets, memory_order_acquire) > 0,
            "GSO output reservation was released before worker publication");
    require(callback_count < 3 && sbufGetLength(buf) == 41, "GSO reader emitted a wrong-sized segment");
    require(GET_BE16(ip + 2) == 41 && GET_BE16(ip + 4) == 0x1234U + callback_count &&
                GET_BE32(ip + 24) == 1000U + callback_count && ip[40] == (uint8_t) ('A' + callback_count),
            "GSO reader lost sequence, IP ID, or payload order");
    require((ip[33] & 0x19) == (callback_count == 2 ? 0x19 : 0x10), "GSO reader placed FIN/PSH on a non-final segment");
    require(gsoSegmentChecksumsValid(ip, sbufGetLength(buf)),
            "GSO output reached the packet chain before worker-side checksum completion");
    callback_count++;
    bufferpoolReuseBuffer(getWorkerBufferPool(wid), buf);
}

static void observeGsoThenOrdinary(tun_device_t *tdev, void *userdata, sbuf_t *buf, uint8_t wid)
{
    if (callback_count < 3)
    {
        observeGsoSegment(tdev, userdata, buf, wid);
        return;
    }
    discard        tdev;
    discard        userdata;
    const uint8_t *ip = sbufGetRawPtr(buf);
    require(ordinary_after_gso_deliveries == 0 && sbufGetLength(buf) == kGsoFixtureIpLength && ip[40] == 'A' &&
                ip[41] == 'B' && ip[42] == 'C',
            "ordinary packet overtook or corrupted deferred GSO segments");
    ordinary_after_gso_deliveries++;
    bufferpoolReuseBuffer(getWorkerBufferPool(wid), buf);
}

static void testGsoWorkerCompletionSurvivesScratchOverwrite(void)
{
    resetShutdownRequests();
    resetIoInjection();
    resetCapturedMessages();
    tun_device_t *tdev = createRunningGsoReaderDevice(observeGsoThenOrdinary);
    uint8_t       aggregate[kGsoFixtureRecordLength];
    uint8_t       ordinary[kGsoFixtureRecordLength];
    makeSmallGsoRecord(aggregate);
    memoryCopy(ordinary, aggregate, sizeof(ordinary));
    memoryZero(ordinary, 10); /* GSO_NONE, no deferred checksum request. */
    const injected_io_result_t reads[] = {{.result = kGsoFixtureRecordLength, .bytes = aggregate},
                                          {.result = kGsoFixtureRecordLength, .bytes = ordinary},
                                          {.result = -1, .error = EIO}};
    armDeviceReads(reads, ARRAY_SIZE(reads));
    inject_gso_reader_poll       = true;
    verify_gso_scratch_overwrite = true;
    gso_deliver_after_read_calls = 2;
    gso_probe_session            = tunLinuxReaderSession(tdev);
    callback_count               = 0;

    runCapturedThreadBody(kCapturedReaderThread);

    require(callback_count == 3 && ordinary_after_gso_deliveries == 1 && gso_messages_delivered == 4,
            "deferred GSO output was not prepared and delivered after scratch reuse");
    require(observed_read_calls == 3 && gso_device_ready_polls == 3 && gso_budget_wake_polls == 0,
            "scratch-overwrite fixture did not defer worker delivery until after the second read");
    require(atomic_load_explicit(&gso_probe_session->output_packets, memory_order_acquire) == 0 &&
                atomic_load_explicit(&gso_probe_session->output_charge, memory_order_acquire) == 0,
            "worker checksum completion leaked GSO output reservations");
    resetIoInjection();
    require(tundeviceBringDown(tdev), "GSO scratch-overwrite device did not stop");
    tundeviceDestroy(tdev);
    resetCapturedMessages();
}

static void testGsoReaderResumesPendingWithoutTunReadiness(void)
{
    resetShutdownRequests();
    resetIoInjection();
    resetCapturedMessages();
    tun_device_t            *tdev    = createRunningGsoReaderDevice(observeGsoSegment);
    device_reader_session_t *session = tunLinuxReaderSession(tdev);
    session->output_packet_limit     = 1; /* Force a real pending-budget wait after each generated segment. */
    uint8_t record[kGsoFixtureRecordLength];
    makeSmallGsoRecord(record);
    const injected_io_result_t reads[] = {{.result = -1, .error = EINTR},
                                          {.result = kGsoFixtureRecordLength, .bytes = record},
                                          {.result = -1, .error = EIO}};
    armDeviceReads(reads, ARRAY_SIZE(reads));
    inject_gso_reader_poll = true;
    gso_probe_session      = session;
    callback_count         = 0;

    runCapturedThreadBody(kCapturedReaderThread);

    require(callback_count == 3 && observed_read_calls == 3,
            "GSO reader did not retry EINTR or complete its pending aggregate");
    require(gso_budget_wake_polls == 2 && gso_device_ready_polls == 2,
            "GSO pending output required a new TUN readability event to resume");
    require(atomic_load_explicit(&session->output_packets, memory_order_acquire) == 0 &&
                atomic_load_explicit(&session->output_charge, memory_order_acquire) == 0,
            "GSO delivery did not return every output reservation");
    require(shutdown_request_calls == 1, "terminal GSO reader error did not request orderly shutdown");
    resetIoInjection();
    require(tundeviceBringDown(tdev), "GSO reader did not bring down after terminal error");
    tundeviceDestroy(tdev);
    resetCapturedMessages();
}

static void testGsoWriterFramingAndPacketOutcomes(void)
{
    resetShutdownRequests();
    resetIoInjection();
    resetTunLogCapture();
    tun_device_t  *tdev      = createRunningGsoReaderDevice(observeReadCallback);
    const uint16_t lengths[] = {1500, 64, 64, 64};
    for (unsigned int i = 0; i < ARRAY_SIZE(lengths); ++i)
    {
        sbuf_t *buf = bufferpoolGetSmallBuffer(getWorkerBufferPool(0));
        sbufSetLength(buf, lengths[i]);
        memorySet(sbufGetMutablePtr(buf), (int) ('a' + i), lengths[i]);
        require(tundeviceWrite(tdev, buf), "failed to queue a GSO-writer packet");
    }
    const injected_io_result_t writes[] = {{.result = -1, .error = EINTR},
                                           {.result = 1510},
                                           {.result = 73},
                                           {.result = -1, .error = EAGAIN},
                                           {.result = -1, .error = EIO}};
    armDeviceWrites(writes, ARRAY_SIZE(writes));

    runCapturedThreadBody(kCapturedWriterThread);

    require(observed_writev_calls == 5 && observed_write_calls == 0 && largest_writev_packet == 1500,
            "GSO writer did not frame, retry, and bound writes as packet operations");
    require(countTunLogSubstring("short device write") == 1,
            "GSO writer did not diagnose its positive short packet write");
    require(shutdown_request_calls == 1 && tunLinuxLifecycleState(tdev) == kTunLifecycleFailed,
            "GSO writer did not end on a permanent descriptor error");
    resetIoInjection();
    require(tundeviceBringDown(tdev), "GSO writer did not bring down after terminal error");
    tundeviceDestroy(tdev);
}

static void testGsoPendingAggregateSettlesOnReaderExit(void)
{
    resetShutdownRequests();
    resetIoInjection();
    resetCapturedMessages();
    tun_device_t            *tdev    = createRunningGsoReaderDevice(observeGsoSegment);
    device_reader_session_t *session = tunLinuxReaderSession(tdev);
    session->output_packet_limit     = 1;
    uint8_t record[kGsoFixtureRecordLength];
    makeSmallGsoRecord(record);
    const injected_io_result_t reads[] = {{.result = kGsoFixtureRecordLength, .bytes = record}};
    armDeviceReads(reads, ARRAY_SIZE(reads));
    inject_gso_reader_poll         = true;
    stop_gso_reader_on_budget_wait = true;
    gso_probe_session              = session;
    require(gso_scratch_buffer != NULL, "GSO device did not preallocate direct scratch storage");
    callback_count = 0;

    runCapturedThreadBody(kCapturedReaderThread);

    require(observed_read_calls == 1 && callback_count == 0 && captured_message_count == 1,
            "reader stop did not retain exactly one queued GSO output");
    require(gso_scratch_destroy_count == 0, "reader exit destroyed device-owned GSO scratch before restart");
    require(atomic_load_explicit(&session->output_packets, memory_order_acquire) == 1 &&
                atomic_load_explicit(&session->output_charge, memory_order_acquire) > 0,
            "reader exit prematurely settled a worker-owned GSO output");

    tracked_session            = session;
    tracked_message_pool       = session->message_pool;
    tracked_session_free_count = 0;
    tracked_pool_destroy_count = 0;
    require(tundeviceBringDown(tdev), "pending GSO reader did not bring down after exit");
    require(tundeviceBringUp(tdev), "GSO device did not restart with its retained scratch allocation");
    require(gso_scratch_destroy_count == 0, "GSO scratch was destroyed before the restarted device stopped");
    require(tundeviceBringDown(tdev), "restarted GSO device did not stop");
    tundeviceDestroy(tdev);
    require(gso_scratch_destroy_count == 1, "device destroy did not release GSO scratch exactly once");
    require(tracked_session_free_count == 0, "device destroyed a session with queued GSO output");
    cleanupMessage(0);
    require(tracked_session_free_count == 1 && tracked_pool_destroy_count == 1,
            "queued GSO output cancellation did not settle its session exactly once");
    tracked_session      = NULL;
    tracked_message_pool = NULL;
    resetIoInjection();
    resetCapturedMessages();
}

int main(void)
{
    test_env_t env;
    envSetup(&env);
    logger_t *logger = loggerCreate();
    require(logger != NULL, "failed to create TUN writer log-capture logger");
    loggerSetHandler(logger, captureTunLog);
    setInternalLogger(logger);
    checkSumInit();
    testGsoNegotiationAndRawFallback();
    testGsoScratchAllocationFallsBackToRaw();
    testGsoReaderResumesPendingWithoutTunReadiness();
    testGsoWorkerCompletionSurvivesScratchOverwrite();
    testGsoWriterFramingAndPacketOutcomes();
    testGsoPendingAggregateSettlesOnReaderExit();
    testReaderFragmentPolicy(true);
    testReaderFragmentPolicy(false);
    testQueuedCleanupOutlivesDevice();
    testClosedAndStaleDeliveriesDoNotTouchDevice();
    testTunWriterRefusalClassesUseFreshTlsState();
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
    internaloggerDestroy();
    envTeardown(&env);
    puts("Linux TUN message lifetime tests passed");
    return 0;
}

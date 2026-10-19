/* Covers worker-owned TUN readiness, activation rollback, asynchronous packet
 * lifetime, fragment ownership, and ordered GSO/checksum delivery. Native I/O,
 * WIO registration and worker queues are controlled; the real production
 * lifecycle, bounded receive callbacks and packet FIFO run unchanged.
 * CTest: waterwall.tun_linux_message_lifetime_unit */

#include "wwapi.h"

#include "test_assert.h"

#define require(condition, message) TEST_REQUIRE(TEST_FAILURE_EXIT, condition, message)

#include "devices/device_flow_affinity.h"
#include "devices/tun/tun_linux_gso_limits.h"
#include "devices/tun/tun_linux_gso_write.h"
#include "devices/tun/tun_linux_internal.h"
#include "devices/tun/tun_linux_offload.h"
#include "loggers/internal_logger.h"
#include "lwip/engine_runtime.h"
#include "lwip/ip.h"
#include "lwip/netif.h"
#include "lwip/priv/tcp_priv.h"
#include "lwip/ww_lwip.h"
#include "wchecksum.h"
#include "wevent.h"
#include "wfrand.h"
#include "wloop_internal.h"
#include "worker_messages.h"

#include "fixtures/worker_registry_fixture.h"
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
    kMaxCapturedMessages = 128
};

typedef struct captured_message_s
{
    wid_t                        wid;
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
    wloop_t        loop;
} test_env_t;

static captured_message_t captured_messages[kMaxCapturedMessages];
static unsigned int       captured_message_count;
static captured_message_t writer_messages[kMaxCapturedMessages];
static unsigned int       writer_message_count;
static bool               capture_writer_messages;
static unsigned int       callback_count;

typedef struct tcp_ack_probe_s
{
    ww_lwip_engine_t *engine;
    struct netif      netif;
    struct tcp_pcb   *pcb;
    uint32_t          peer_next, peer_ack, last_ack;
    unsigned          received, outputs, batches;
    uint8_t           last_flags;
} tcp_ack_probe_t;

static tcp_ack_probe_t *active_ack_probe;
static unsigned int       fake_thread_create_calls;
static unsigned int       fake_thread_join_calls;
static unsigned int       reject_reader_activation;
static unsigned int       fail_interface_down_calls;
static unsigned int       interface_down_attempts;
static unsigned int       gso_feature_checks;
static unsigned int       gso_setiff_calls;
static unsigned int       raw_setiff_calls;
static unsigned int       gso_header_size_calls;
static unsigned int       gso_byte_order_calls;
static unsigned int       gso_offload_calls;
static unsigned long      offload_masks[8];
static unsigned long      active_offload_mask;
static unsigned long      fail_offload_mask;
static unsigned int       fail_offload_call;
static unsigned int       fail_feature_check;
static unsigned int       tun_open_calls, fail_tun_open_call;
static bool               fail_nonblocking;
static unsigned int       gso_limit_calls;
static unsigned long      fail_gso_ioctl_request;
static int                fail_gso_ioctl_errno;
static bool               gso_feature_available;
static char               gso_attach_name[IFNAMSIZ];
static char               raw_attach_name[IFNAMSIZ];
static bool               raw_attach_exclusive;
static short              requested_tun_flags[8];
static unsigned int       requested_tun_flag_count, queue_flag_probes;
static bool               refuse_multi_queue, record_queue_preference;
/* Readiness callbacks and their worker notifications are separate from the
 * packet delivery FIFO. All production callbacks run as the registered owner. */
static captured_message_t    reader_messages[kMaxCapturedMessages];
static unsigned              reader_message_count, reader_messages_done;
static WorkerMessageCallback reader_message_callback;
static bool                  opening_reader, closing_reader, inside_reader_callback;
static bool                  fail_watcher_registration;
static wio_t                 reader_io;
static wio_cb                reader_ready_callback;
static unsigned              watcher_detach_calls;

static sbuf_t                  *expected_discarded_buffer;
static unsigned int             expected_discard_count;
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

int     __real_open(const char *path, int flags, ...);
int     __wrap_open(const char *path, int flags, ...);
int     __wrap_ioctl(int fd, unsigned long request, ...);
int     __real_fcntl(int fd, int command, ...);
int     __wrap_fcntl(int fd, int command, ...);
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
sbuf_t *__real_bufferpoolGetBestFit(buffer_pool_t *pool, uint32_t minimum_capacity, uint16_t pad_left);
sbuf_t *__wrap_bufferpoolGetBestFit(buffer_pool_t *pool, uint32_t minimum_capacity, uint16_t pad_left);
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

static int          command_outcomes[3];
static unsigned int command_calls;
static bool         existing_interface;

bool __wrap_procRunArgvWithDeadline(const char *file, const char *const argv[], const proc_command_options_t *options,
                                    proc_command_result_t *out);

bool __wrap_procRunArgvWithDeadline(const char *file, const char *const argv[], const proc_command_options_t *options,
                                    proc_command_result_t *out)
{
    discard options;
    if (strcmp(file, "resolvectl") != 0 || command_calls >= 3 ||
        (strcmp(argv[1], "dns") != 0 && strcmp(argv[1], "domain") != 0 && strcmp(argv[1], "revert") != 0))
    {
        abort();
    }
    int result = command_outcomes[command_calls++];
    *out       = (proc_command_result_t) {.exit_code = result == 2 ? -1 : result, .timed_out = result == 2};
    return result == 0;
}

static unsigned int shutdown_request_calls;
static int          shutdown_request_last_code;
static bool         shutdown_request_accepts = true;
// Set only by the forked child that deliberately exercises the hard fallback, so
// its diagnostic does not read like a failure in CI output.
static bool hard_abort_is_expected;

/*
 * Device I/O error injection.
 *
 * Production receive callbacks and worker writer batches run through wrapped
 * read()/write() against the fake descriptor. Each test arms exactly the number of device operations the
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
static bool                     expect_trusted_write, fail_worker_queue_once;
static bool                     fail_worker_gso_once, fail_output_budget_once;
static unsigned                 output_budget_calls;
bool                            __real_tunConfigureWorkerGso(tun_device_t *tdev);
bool                            __wrap_tunConfigureWorkerGso(tun_device_t *tdev);
bool                            __wrap_tunConfigureWorkerGso(tun_device_t *tdev)
{
    if (fail_worker_gso_once)
    {
        fail_worker_gso_once = false;
        return false;
    }
    return __real_tunConfigureWorkerGso(tdev);
}
bool __real_deviceReaderSessionConfigureOutputBudget(device_reader_session_t *session, size_t charge, uint32_t packets);
bool __wrap_deviceReaderSessionConfigureOutputBudget(device_reader_session_t *session, size_t charge, uint32_t packets);
bool __wrap_deviceReaderSessionConfigureOutputBudget(device_reader_session_t *session, size_t charge, uint32_t packets)
{
    ++output_budget_calls;
    if (fail_output_budget_once)
    {
        fail_output_budget_once = false;
        return false;
    }
    return __real_deviceReaderSessionConfigureOutputBudget(session, charge, packets);
}
bool                            __real_deviceReaderSessionEnableWorkerQueue(device_reader_session_t *session);
bool                            __wrap_deviceReaderSessionEnableWorkerQueue(device_reader_session_t *session);
bool                            __wrap_deviceReaderSessionEnableWorkerQueue(device_reader_session_t *session)
{
    if (fail_worker_queue_once)
    {
        fail_worker_queue_once = false;
        return false;
    }
    return __real_deviceReaderSessionEnableWorkerQueue(session);
}

static size_t                   largest_writev_packet;
static bool                     drive_worker_delivery;
static bool                     stop_when_receive_blocked;
static unsigned int             capacity_resumes;
static unsigned int             receive_attempts;
static unsigned int             gso_messages_delivered;
static unsigned int             gso_deliver_after_read_calls;
static bool                     verify_gso_aggregate_transfer;
static const void              *first_gso_read_storage;
static unsigned int             prepared_gso_segments;
static unsigned int             prepared_gso_bytes;
static unsigned int             gso_expected_segments = 3;
static unsigned int             ordinary_after_gso_deliveries;
static unsigned int             queued_checksum_completions;
static unsigned int             receive_checksum_completions;
static device_reader_session_t *gso_probe_session;
static sbuf_t                  *gso_scratch_buffer;
static unsigned int             gso_scratch_destroy_count;
static bool                     deliver_fragment_batch;
static const uint8_t           *expected_raw_write;
static size_t                   expected_raw_write_length;
// Observed from inside the I/O loop, before the routine has returned, so a
// recoverable error can be checked while the device is still meant to be up.
static tun_device_t *in_flight_device;
static unsigned int  in_flight_check_call;
static unsigned int  in_flight_checks_run;

static bool          writer_batch_probe, writer_batch_recycling;
static sbuf_t       *writer_batch_buffers[130];
static unsigned      writer_batch_settled[130], writer_batch_count, writer_batch_offset;
static unsigned      writer_batch_calls, writer_batch_aggregates, writer_batch_max;
static unsigned      writer_batch_fault;
static tun_device_t *writer_batch_device;
static void          deliverNextGsoMessage(void);

bool __wrap_tunLinuxOffloadPrepareSegment(const uint8_t *ip, const tun_linux_offload_plan_t *plan, uint32_t offset,
                                          uint8_t *destination, uint32_t capacity, uint32_t *length);
bool __real_tunLinuxOffloadPrepareSegment(const uint8_t *ip, const tun_linux_offload_plan_t *plan, uint32_t offset,
                                          uint8_t *destination, uint32_t capacity, uint32_t *length);
bool __wrap_tunLinuxOffloadPrepareSegment(const uint8_t *ip, const tun_linux_offload_plan_t *plan, uint32_t offset,
                                          uint8_t *destination, uint32_t capacity, uint32_t *length)
{
    require(currentThreadIsEventWorkerWID(0), "GSO segmentation or payload copying ran outside the processing worker");
    prepared_gso_segments++;
    const bool prepared = __real_tunLinuxOffloadPrepareSegment(ip, plan, offset, destination, capacity, length);
    if (prepared)
    {
        prepared_gso_bytes += *length;
    }
    return prepared;
}

void __real_tunLinuxOffloadCompleteChecksum(uint8_t *ip, const tun_linux_offload_plan_t *plan);
void __wrap_tunLinuxOffloadCompleteChecksum(uint8_t *ip, const tun_linux_offload_plan_t *plan);
void __wrap_tunLinuxOffloadCompleteChecksum(uint8_t *ip, const tun_linux_offload_plan_t *plan)
{
    if (! inside_reader_callback)
    {
        queued_checksum_completions++;
    }
    else
    {
        require(currentThreadIsEventWorkerWID(0), "ordinary checksum ran outside its receive worker");
        receive_checksum_completions++;
    }
    __real_tunLinuxOffloadCompleteChecksum(ip, plan);
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
        active_offload_mask = 0;
        if (++tun_open_calls == fail_tun_open_call)
        {
            errno = EACCES;
            return -1;
        }
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

int __wrap_fcntl(int fd, int command, ...)
{
    if (command == F_GETFL || command == F_GETFD || command == F_GETPIPE_SZ)
        return __real_fcntl(fd, command);
    va_list args;
    va_start(args, command);
    const int argument = va_arg(args, int);
    va_end(args);
    if (fd == tun_handle_fd && command == F_SETFL && fail_nonblocking)
    {
        errno = EIO;
        return -1;
    }
    return __real_fcntl(fd, command, argument);
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
        require(gso_offload_calls < ARRAY_SIZE(offload_masks), "too many offload setup calls");
        offload_masks[gso_offload_calls++] = flags;
        require(flags == TUN_F_CSUM || flags == (TUN_F_CSUM | TUN_F_TSO4), "unexpected offload mask");
        if (fail_gso_ioctl_request == request || flags == fail_offload_mask || gso_offload_calls == fail_offload_call)
        {
            errno = fail_gso_ioctl_errno;
            return -1;
        }
        active_offload_mask = flags;
        return 0;
    }
    void *argument = va_arg(args, void *);
    va_end(args);

    if (request == TUNGETFEATURES)
    {
        gso_feature_checks++;
        if (gso_feature_checks == fail_feature_check)
        {
            errno = EOPNOTSUPP;
            return -1;
        }
        *(unsigned int *) argument = gso_feature_available ? IFF_VNET_HDR : 0;
    }
    else if (request == TUNSETIFF)
    {
        struct ifreq *ifr = argument;
        if (record_queue_preference)
        {
            require(requested_tun_flag_count < ARRAY_SIZE(requested_tun_flags), "too many TUN attach attempts");
            requested_tun_flags[requested_tun_flag_count++] = ifr->ifr_flags;
        }
        if (refuse_multi_queue && (ifr->ifr_flags & IFF_MULTI_QUEUE) != 0)
        {
            errno = EOPNOTSUPP;
            return -1;
        }
        if ((ifr->ifr_flags & IFF_VNET_HDR) != 0)
        {
            gso_setiff_calls++;
            memoryCopy(gso_attach_name, ifr->ifr_name, IFNAMSIZ);
            require((ifr->ifr_flags & IFF_TUN_EXCL) != 0, "GSO setup omitted exclusive TUN attach");
            if (existing_interface)
            {
                errno = EBUSY;
                return -1;
            }
        }
        else
        {
            raw_setiff_calls++;
            memoryCopy(raw_attach_name, ifr->ifr_name, IFNAMSIZ);
            raw_attach_exclusive = (ifr->ifr_flags & IFF_TUN_EXCL) != 0;
            if (existing_interface && raw_attach_exclusive)
            {
                errno = EBUSY;
                return -1;
            }
        }
        if (fail_gso_ioctl_request == request && (ifr->ifr_flags & IFF_VNET_HDR) != 0)
        {
            errno = fail_gso_ioctl_errno;
            return -1;
        }
        stringCopyN(ifr->ifr_name, "ww-lifetime-test", IFNAMSIZ);
        ifr->ifr_name[IFNAMSIZ - 1] = '\0';
    }
    else if (request == TUNGETIFF)
    {
        ++queue_flag_probes;
        /* Queue-setup syscall behavior has its own fixture. This constructor
         * fixture emulates the documented single-queue capability fallback. */
        ((struct ifreq *) argument)->ifr_flags = IFF_TUN | IFF_NO_PI;
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
    if (fd == tun_handle_fd && (opening_reader || injected_read_count == 0))
    {
        errno = EAGAIN;
        return -1;
    }
    if (fd == tun_handle_fd && injected_read_count > 0)
    {
        if (active_ack_probe != NULL)
        {
            require(active_ack_probe->received == 0 && active_ack_probe->outputs == 0 && active_ack_probe->batches == 0,
                    "same-worker TCP delivery started before the bounded native read burst ended");
        }
        if (drive_worker_delivery && observed_read_calls >= gso_deliver_after_read_calls)
        {
            while (gso_messages_delivered < captured_message_count)
                deliverNextGsoMessage();
        }
        if (drive_worker_delivery)
            ++receive_attempts;
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
        if (verify_gso_aggregate_transfer && index == 0)
        {
            first_gso_read_storage = buf;
        }
        if (verify_gso_aggregate_transfer && index == 1)
        {
            require(gso_messages_delivered == 0 && captured_message_count == 1 && prepared_gso_segments == 0,
                    "reader expanded an aggregate before its worker ran");
            require(buf != first_gso_read_storage, "reader reused aggregate storage after transferring it");
        }
        if (deliver_fragment_batch && index == 3)
        {
            require(captured_message_count == 1, "reader did not flush one fragment batch");
            testWorkerBindWID(0);
            worker_t            worker  = {.wid = 0};
            captured_message_t *message = &captured_messages[0];
            message->callback(&worker, message->arg1, message->arg2, message->arg3);
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
        if (expected_raw_write != NULL)
            require(count == expected_raw_write_length && memoryEqual(buf, expected_raw_write, count),
                    "trusted raw writer changed complete checksum bytes or packet framing");
        require(observed_write_calls < injected_write_count,
                "the writer kept writing to a device that reported a permanent error");
        const unsigned int index = observed_write_calls++;
        checkInFlightExpectations(index + 1);
        return applyInjectedIoResult(&injected_writes[index]);
    }
    return __real_write(fd, buf, count);
}

static void *stopWriterFromCoordinator(void *context)
{
    require(tundeviceRequestStop(context), "concurrent batch stop request");
    return NULL;
}

ssize_t __wrap_writev(int fd, const struct iovec *iov, int iovcnt)
{
    if (fd == tun_handle_fd && writer_batch_probe)
    {
        ++writer_batch_calls;
        const uint8_t *metadata = iov[0].iov_base;
        const uint8_t *ip       = iov[1].iov_base;
        const unsigned members  = metadata[1] == 1 ? (unsigned) iovcnt - 2 : 1;
        size_t         total    = 0;
        for (int i = 0; i < iovcnt; ++i)
            total += iov[i].iov_len;
        require(iov[0].iov_len == 10 && metadata[0] == 1 && metadata[6] == 20 && metadata[8] == 16,
                "batch checksum metadata");
        require(GET_BE32(ip + 24) == writer_batch_offset * 100U, "batch/lookahead reordered output");
        if (metadata[1] == 1)
        {
            ++writer_batch_aggregates;
            writer_batch_max = max(writer_batch_max, members);
            require(iov[1].iov_len == 40 && metadata[2] == 40 && metadata[4] == 100, "batch GSO geometry");
            require(GET_BE16(ip + 2) + 10U == total, "batch total length");
            for (unsigned i = 0; i < members; ++i)
            {
                sbuf_t *buf = writer_batch_buffers[writer_batch_offset + i];
                require(iov[i + 2].iov_base == (const uint8_t *) sbufGetRawPtr(buf) + 40 && iov[i + 2].iov_len == 100,
                        "writer copied payload or mixed batch members");
                require(writer_batch_settled[writer_batch_offset + i] == 0, "write used settled buffer");
            }
        }
        else
            require(iovcnt == 2 && ip == sbufGetRawPtr(writer_batch_buffers[writer_batch_offset]),
                    "ordinary fallback lost original buffer");
        if (writer_batch_calls == 1 && (writer_batch_fault == 1 || writer_batch_fault == 2))
        {
            errno = writer_batch_fault == 1 ? EINTR : EINVAL;
            return -1;
        }
        writer_batch_offset += members;
        if (writer_batch_fault == 5 || writer_batch_fault == 8)
        {
            pthread_t stopper;
            require(__real_pthread_create(&stopper, NULL, stopWriterFromCoordinator, writer_batch_device) == 0,
                    "failed to start concurrent batch stop");
            require(__real_pthread_join(stopper, NULL) == 0, "failed to join concurrent batch stop");
        }
        if (writer_batch_calls == 1 && (writer_batch_fault == 3 || writer_batch_fault == 6 || writer_batch_fault == 8))
        {
            errno = writer_batch_fault == 3 ? EAGAIN : writer_batch_fault == 8 ? EINTR : EIO;
            return -1;
        }
        if (writer_batch_fault == 9)
            return 0;
        return writer_batch_calls == 1 && writer_batch_fault == 4 ? (ssize_t) total - 1 : (ssize_t) total;
    }
    if (fd == tun_handle_fd)
    {
        require(iovcnt == 2 && iov[0].iov_len == 10, "GSO writer did not use one virtio-framed writev");
        const uint8_t *header = iov[0].iov_base;
        if (expect_trusted_write)
        {
            const uint8_t  expected[10] = {1, 0, 0, 0, 0, 0, 20, 0, 16, 0};
            const uint8_t *ip           = iov[1].iov_base;
            require(memoryEqual(header, expected, 10), "trusted writer metadata bytes");
            uint32_t seed = 6 + (uint32_t) iov[1].iov_len - 20;
            for (unsigned i = 12; i < 20; i += 2)
                seed += GET_BE16(ip + i);
            while (seed >> 16)
                seed = (seed & 65535U) + (seed >> 16);
            require(GET_BE16(ip + 36) == seed, "trusted writer did not replace full checksum with seed");
        }
        else
        {
            for (unsigned int i = 0; i < 10; ++i)
            {
                require(header[i] == 0, "GSO writer emitted nonzero metadata for an ordinary packet");
            }
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
    worker_t            worker       = {.wid = 0};
    captured_message_t *message      = &captured_messages[gso_messages_delivered++];
    const unsigned int  bytes_before = prepared_gso_bytes;
    const unsigned int  before       = prepared_gso_segments;
    const bool          previous     = inside_reader_callback;
    inside_reader_callback           = false;
    message->callback(&worker, message->arg1, message->arg2, message->arg3);
    inside_reader_callback = previous;
    require(prepared_gso_segments - before <= 256, "worker segmented more than 256 packets in one callback");
    require(prepared_gso_bytes - bytes_before <= 256U * 1024U, "worker segmented more than 256 KiB in one callback");
}

int __wrap_poll(struct pollfd *fds, nfds_t nfds, int timeout)
{
    return __real_poll(fds, nfds, timeout);
}

int __wrap_pthread_create(pthread_t *thread, const pthread_attr_t *attr, void *(*routine)(void *), void *arg)
{
    discard thread;
    discard attr;
    discard routine;
    discard arg;
    fake_thread_create_calls++;
    require(false, "TUN must not create a dedicated read or write thread");
    return EAGAIN;
}

int __wrap_pthread_join(pthread_t thread, void **retval)
{
    discard thread;
    discard retval;
    fake_thread_join_calls++;
    require(false, "TUN must not join a dedicated read or write thread");
    return EINVAL;
}

wio_t *__wrap_wioGet(wloop_t *loop, int fd);
int    __wrap_wioAdd(wio_t *io, wio_cb callback, int events);
int    __wrap_wioDel(wio_t *io, int events);
void   __wrap_wioReleaseNoClose(wio_t *io);

wio_t *__wrap_wioGet(wloop_t *loop, int fd)
{
    require(currentThreadIsEventWorkerWID(0), "watcher installed on its owner worker");
    require(fd == tun_handle_fd, "watcher owns the receive descriptor");
    memoryZero(&reader_io, sizeof(reader_io));
    reader_io.loop = loop;
    reader_io.fd   = fd;
    return &reader_io;
}

int __wrap_wioAdd(wio_t *io, wio_cb callback, int events)
{
    require(io == &reader_io && currentThreadIsEventWorkerWID(0), "read watcher changed only by its owner");
    if (fail_watcher_registration)
    {
        errno = ENOMEM;
        return -1;
    }
    reader_ready_callback = callback;
    io->events |= events;
    return 0;
}

int __wrap_wioDel(wio_t *io, int events)
{
    require(io == &reader_io && currentThreadIsEventWorkerWID(0), "read interest removed by its owner");
    io->events &= ~events;
    return 0;
}

void __wrap_wioReleaseNoClose(wio_t *io)
{
    require(io == &reader_io && currentThreadIsEventWorkerWID(0), "watcher detached on its owner worker");
    require(io->fd == tun_handle_fd, "watcher retains the caller-owned TUN descriptor");
    io->events = 0;
    io->fd     = -1;
    ++watcher_detach_calls;
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
    require(wid < getWorkersCount(), "TUN fixture posted to an unexpected worker");
    const bool reader_message = opening_reader || closing_reader || callback == reader_message_callback;
    if (reader_message)
    {
        reader_message_callback = callback;
        if (reject_reader_activation != 0)
        {
            reject_reader_activation = 0;
            cleanup(arg1, arg2, arg3, kWorkerMessageCancelQuiesced);
            return kWorkerMessageSubmitRejectedCleanupRan;
        }
    }
    captured_message_t *messages = reader_message            ? reader_messages
                                   : capture_writer_messages ? writer_messages
                                                             : captured_messages;
    unsigned int       *count    = reader_message            ? &reader_message_count
                                   : capture_writer_messages ? &writer_message_count
                                                             : &captured_message_count;
    require(*count < kMaxCapturedMessages, "captured-message queue overflow");
    messages[(*count)++] = (captured_message_t) {
        .wid      = wid,
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
    if (tracked_session != NULL && ptr == tracked_session)
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
    if (writer_batch_probe)
    {
        for (unsigned i = 0; i < writer_batch_count; ++i)
            if (buf == writer_batch_buffers[i])
                require(++writer_batch_settled[i] == 1, "batch double recycling");
    }
    writer_batch_recycling = true;
    __real_bufferpoolReuseBuffer(pool, buf);
    writer_batch_recycling = false;

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

sbuf_t *__wrap_bufferpoolGetBestFit(buffer_pool_t *pool, uint32_t minimum_capacity, uint16_t pad_left)
{
    sbuf_t *buf = __real_bufferpoolGetBestFit(pool, minimum_capacity, pad_left);
    if (inside_reader_callback && gso_scratch_buffer == NULL && minimum_capacity == 65536)
    {
        gso_scratch_buffer = buf;
    }
    return buf;
}

void __wrap_sbufDestroy(sbuf_t *buf)
{
    if (buf == expected_discarded_buffer)
        ++expected_discard_count;
    if (writer_batch_probe && ! writer_batch_recycling)
    {
        for (unsigned i = 0; i < writer_batch_count; ++i)
            if (buf == writer_batch_buffers[i])
                require(++writer_batch_settled[i] == 1, "batch double destruction");
    }
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
    if (hard_abort_is_expected && shutdown_request_calls != 1)
    {
        fprintf(stderr, "FAIL: hard fallback occurred before the intended shutdown handoff\n");
        _Exit(75);
    }
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
    drive_worker_delivery          = false;
    stop_when_receive_blocked      = false;
    capacity_resumes               = 0;
    receive_attempts               = 0;
    gso_messages_delivered         = 0;
    gso_deliver_after_read_calls   = 1;
    verify_gso_aggregate_transfer  = false;
    first_gso_read_storage         = NULL;
    prepared_gso_segments          = 0;
    prepared_gso_bytes             = 0;
    gso_expected_segments          = 3;
    ordinary_after_gso_deliveries  = 0;
    queued_checksum_completions    = 0;
    receive_checksum_completions   = 0;
    gso_probe_session              = NULL;
    gso_scratch_buffer             = NULL;
    gso_scratch_destroy_count      = 0;
    expected_raw_write             = NULL;
    expected_raw_write_length      = 0;
    in_flight_device               = NULL;
    in_flight_check_call           = 0;
    in_flight_checks_run           = 0;
}

static void resetGsoSetup(void)
{
    memoryZero(offload_masks, sizeof(offload_masks));
    active_offload_mask     = 0;
    fail_offload_mask       = 0;
    fail_offload_call       = 0;
    fail_feature_check      = 0;
    tun_open_calls          = 0;
    fail_tun_open_call      = 0;
    fail_nonblocking        = false;
    fail_worker_gso_once    = false;
    fail_output_budget_once = false;
    output_budget_calls     = 0;
    gso_feature_checks     = 0;
    gso_setiff_calls       = 0;
    raw_setiff_calls       = 0;
    gso_header_size_calls  = 0;
    gso_byte_order_calls   = 0;
    gso_offload_calls      = 0;
    gso_limit_calls        = 0;
    fail_gso_ioctl_request = 0;
    fail_gso_ioctl_errno    = EOPNOTSUPP;
    gso_feature_available   = true;
    memoryZero(gso_attach_name, sizeof(gso_attach_name));
    memoryZero(raw_attach_name, sizeof(raw_attach_name));
    raw_attach_exclusive      = false;
    requested_tun_flag_count  = 0;
    queue_flag_probes         = 0;
    refuse_multi_queue        = false;
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
                                               16,
                                               8192,
                                               MEDIUM_BUFFER_SIZE_RAM_HIGH,
                                               4096,
                                               8192,
                                               8192);
    env->buffer_pools[0]    = env->worker_buffer_pool;
    env->loops[0]           = &env->loop;

    GSTATE.masterpool_buffer_pools_large  = env->large_master;
    GSTATE.masterpool_buffer_pools_small  = env->small_master;
    GSTATE.masterpool_buffer_pools_medium = env->medium_master;

    GSTATE.shortcut_buffer_pools = env->buffer_pools;
    GSTATE.shortcut_loops        = env->loops;
    GSTATE.workers_count         = 1;
    testWorkerRegistryInstall(&g_test_worker_registry);
    GSTATE.workers[0].buffer_pool = env->worker_buffer_pool;
    GSTATE.workers[0].loop        = env->loops[0];
    GSTATE.ram_profile            = 1;
    testWorkerBindWID(0);
}

static void envTeardown(test_env_t *env)
{
    GSTATE.masterpool_buffer_pools_large  = NULL;
    GSTATE.masterpool_buffer_pools_small  = NULL;
    GSTATE.masterpool_buffer_pools_medium = NULL;

    GSTATE.shortcut_buffer_pools = NULL;
    GSTATE.shortcut_loops        = NULL;
    GSTATE.workers_count         = 0;
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

static bool queueWriterPacket(tun_device_t *tdev, sbuf_t *buf)
{
    const bool previous     = capture_writer_messages;
    capture_writer_messages = true;
    const bool accepted     = tundeviceWrite(tdev, buf);
    capture_writer_messages = previous;
    return accepted;
}

static void runWriterMessages(void)
{
    const bool previous     = capture_writer_messages;
    capture_writer_messages = true;
    for (unsigned i = 0; i < writer_message_count; ++i)
    {
        captured_message_t message = writer_messages[i];
        message.callback(getCurrentEventWorker(), message.arg1, message.arg2, message.arg3);
    }
    writer_message_count    = 0;
    capture_writer_messages = previous;
}

static void cancelWriterMessages(void)
{
    for (unsigned i = 0; i < writer_message_count; ++i)
    {
        captured_message_t message = writer_messages[i];
        message.cleanup(message.arg1, message.arg2, message.arg3, kWorkerMessageCancelTeardown);
    }
    writer_message_count = 0;
}

static void runReaderMessages(void)
{
    for (; reader_messages_done < reader_message_count;)
    {
        captured_message_t message  = reader_messages[reader_messages_done++];
        const bool         previous = inside_reader_callback;
        inside_reader_callback      = true;
        message.callback(getCurrentEventWorker(), message.arg1, message.arg2, message.arg3);
        inside_reader_callback = previous;
    }
    reader_message_count = reader_messages_done = 0;
}

static bool bringUpDevice(tun_device_t *tdev)
{
    opening_reader = true;
    const bool up  = tundeviceBringUp(tdev);
    runReaderMessages();
    opening_reader = false;
    return up;
}

static bool bringDownDevice(tun_device_t *tdev)
{
    closing_reader  = true;
    const bool down = tundeviceBringDown(tdev);
    runReaderMessages();
    closing_reader = false;
    return down;
}

static void destroyDevice(tun_device_t *tdev)
{
    if (tdev != NULL)
        discard bringDownDevice(tdev);
    tundeviceDestroy(tdev);
    runReaderMessages();
}

static void resetReaderFixture(unsigned int fail_on_call)
{
    require(reader_message_count == 0, "previous reader generation settled its worker messages");
    fake_thread_create_calls = fake_thread_join_calls = 0;
    reject_reader_activation                          = fail_on_call;
    fail_watcher_registration                         = false;
    watcher_detach_calls                              = 0;
}

/* Drive the production bounded receive callback and its capacity notifications.
 * Packet FIFO callbacks remain explicitly controlled by each test. */
static void runReaderUntilIdle(void)
{
    unsigned steps = 0;
    while (++steps < 128 && observed_read_calls < injected_read_count)
    {
        if (reader_io.events == 0)
        {
            if (stop_when_receive_blocked)
                return;
            require(gso_messages_delivered < captured_message_count, "blocked reader has retained work to retire");
            deliverNextGsoMessage();
            ++capacity_resumes;
            runReaderMessages();
        }
        else
        {
            require(reader_ready_callback != NULL, "receive readiness was registered");
            inside_reader_callback = true;
            reader_ready_callback(&reader_io);
            inside_reader_callback = false;
            runReaderMessages();
        }
    }
    require(steps < 128, "bounded receive progress");
}

/* Raw lifecycle fixtures explicitly reject virtio support; GSO false by itself
 * selects checksum-only framing on a capable fresh device. */
static tun_device_t *createRawDevice(const char *name, bool gso_requested, uint16_t mtu, void *userdata,
                                     TunReadEventHandle callback, device_fragment_policy_t policy)
{
    const bool available  = gso_feature_available;
    gso_feature_available = false;
    tun_device_t *tdev    = tundeviceCreate(name, gso_requested, true, mtu, userdata, callback, policy);
    gso_feature_available = available;
    return tdev;
}

static tun_device_t *createRunningDevice(void)
{
    tun_device_t *tdev = createRawDevice("ww-lifetime-test", false, 1500, NULL, NULL, kDeviceFragmentPreserve);
    require(tdev != NULL, "production tundeviceCreate failed");
    require(bringUpDevice(tdev), "production tundeviceBringUp failed");
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
        createRawDevice("ww-lifetime-test", false, 1500, NULL, observeReadCallback, kDeviceFragmentPreserve);
    require(tdev != NULL, "production reader-device create failed");
    require(bringUpDevice(tdev), "production reader-device bring-up failed");
    return tdev;
}

static tun_device_t *createRunningOffloadReaderDevice(TunReadEventHandle callback, bool gso_requested)
{
    resetReaderFixture(0);
    resetGsoSetup();
    tun_device_t *tdev =
        tundeviceCreate("ww-lifetime-test", gso_requested, true, 1500, NULL, callback, kDeviceFragmentPreserve);
    require(tdev != NULL, "GSO reader-device create failed");
    require(deviceReaderSessionOutputWakeFd(tunLinuxReaderSession(tdev)) >= 0,
            "GSO reader-device was not configured with output credits");
    require(gso_feature_checks == 1 && gso_setiff_calls == 1 && raw_setiff_calls == 0 && gso_header_size_calls == 1 &&
                gso_byte_order_calls == 1 && gso_offload_calls == (gso_requested ? 2U : 1U) &&
                gso_limit_calls == (gso_requested ? 1U : 0U),
            "GSO setup skipped or repeated one negotiated descriptor step");
    require(bringUpDevice(tdev), "GSO reader-device bring-up failed");
    return tdev;
}

static void testChecksumOnlyNegotiation(void)
{
    resetReaderFixture(0);
    resetGsoSetup();
    tun_device_t *tdev = tundeviceCreate("ww-lifetime-test", false, true, 1500, NULL, NULL, kDeviceFragmentPreserve);
    require(tdev != NULL, "checksum-only device create failed");
    require(gso_feature_checks == 1 && gso_setiff_calls == 1 && raw_setiff_calls == 0 && gso_header_size_calls == 1 &&
                gso_byte_order_calls == 1 && gso_offload_calls == 1 && gso_limit_calls == 0,
            "GSO false did not negotiate checksum-only virtio framing");
    require(tundeviceEnableTrustedChecksums(tdev), "checksum-only setup did not retain direct-pair trust");
    require(offload_masks[0] == TUN_F_CSUM && active_offload_mask == TUN_F_CSUM,
            "checksum-only setup enabled segmentation");
    require(deviceReaderSessionOutputWakeFd(tunLinuxReaderSession(tdev)) >= 0,
            "checksum-only setup omitted worker admission resources");
    destroyDevice(tdev);
}

static void testGsoNegotiationAndRawFallback(void)
{
    const unsigned long failing_requests[] = {TUNGETFEATURES, TUNSETIFF, TUNSETVNETHDRSZ, TUNSETVNETLE, TUNSETOFFLOAD};
    for (unsigned mode = 0; mode < 2; ++mode)
        for (unsigned int i = 0; i < ARRAY_SIZE(failing_requests); ++i)
        {
            resetReaderFixture(0);
            resetGsoSetup();
            resetTunLogCapture();
            fail_gso_ioctl_request = failing_requests[i];
            tun_device_t *tdev =
                tundeviceCreate("ww-lifetime-test", mode != 0, true, 1500, NULL, NULL, kDeviceFragmentPreserve);
            require(tdev != NULL, "GSO setup failure did not fall back to a raw-IP descriptor");
            require(! tundeviceEnableTrustedChecksums(tdev), "fallback activated trust");
            require(deviceReaderSessionOutputWakeFd(tunLinuxReaderSession(tdev)) >= 0,
                    "raw-IP fallback omitted bounded worker admission");
            require(raw_setiff_calls == 1 && gso_feature_checks == 1,
                    "GSO fallback did not retry exactly one raw descriptor");
            require(countTunLogSubstring("falling back to raw-IP TUN") == 1,
                    "GSO setup fallback did not emit one runtime diagnostic");
            destroyDevice(tdev);
        }

    resetReaderFixture(0);
    resetGsoSetup();
    fail_gso_ioctl_request = TUNSETIFF;
    fail_gso_ioctl_errno   = EBUSY;
    tun_device_t *conflict = tundeviceCreate("ww-lifetime-test", true, true, 1500, NULL, NULL, kDeviceFragmentPreserve);
    require(conflict == NULL && raw_setiff_calls == 0,
            "exclusive GSO name conflict unexpectedly fell back onto the same TUN name");

    resetGsoSetup();
    resetReaderFixture(0);
    tun_device_t *active = tundeviceCreate("ww-lifetime-test", true, true, 1500, NULL, NULL, kDeviceFragmentPreserve);
    require(active != NULL && tundeviceEnableTrustedChecksums(active) &&
                deviceReaderSessionOutputWakeFd(tunLinuxReaderSession(active)) >= 0,
            "supported GSO descriptor did not activate offload mode");
    require(gso_feature_checks == 1 && gso_setiff_calls == 1 && raw_setiff_calls == 0 && gso_header_size_calls == 1 &&
                gso_byte_order_calls == 1 && gso_offload_calls == 2 && gso_limit_calls == 1,
            "supported GSO setup did not complete every descriptor step exactly once");
    require(offload_masks[0] == TUN_F_CSUM && offload_masks[1] == (TUN_F_CSUM | TUN_F_TSO4) &&
                active_offload_mask == offload_masks[1],
            "GSO upgrade did not retain CSUM in the replacement mask");
    destroyDevice(active);

    resetGsoSetup();
    fail_offload_mask = TUN_F_CSUM | TUN_F_TSO4;
    active            = tundeviceCreate("ww-lifetime-test", true, true, 1500, NULL, NULL, kDeviceFragmentPreserve);
    require(active && tundeviceEnableTrustedChecksums(active) && active_offload_mask == TUN_F_CSUM &&
                tun_open_calls == 1 && gso_offload_calls == 2 && gso_limit_calls == 0 && raw_setiff_calls == 0,
            "rejected TSO upgrade did not retain checksum-only mode on the same descriptor");
    destroyDevice(active);

    for (unsigned mode = 0; mode < 2; ++mode)
    {
        resetGsoSetup();
        gso_feature_available = false;
        active = tundeviceCreate("ww-lifetime-test", mode != 0, true, 1500, NULL, NULL, kDeviceFragmentPreserve);
        require(active && ! tundeviceEnableTrustedChecksums(active) && raw_setiff_calls == 1 && gso_setiff_calls == 0,
                "missing virtio feature did not select raw fallback");
        destroyDevice(active);

        resetGsoSetup();
        existing_interface = true;
        active = tundeviceCreate("ww-lifetime-test", mode != 0, true, 1500, NULL, NULL, kDeviceFragmentPreserve);
        if (mode == 0)
        {
            require(active && raw_setiff_calls == 2 && ! raw_attach_exclusive && gso_offload_calls == 0 &&
                        ! tundeviceEnableTrustedChecksums(active),
                    "GSO false lost pre-existing raw attachment");
            destroyDevice(active);
        }
        else
            require(active == NULL && raw_setiff_calls == 0, "GSO request attached a pre-existing interface");
        existing_interface = false;
    }

    const unsigned long serious_failures[] = {
        TUNGETFEATURES, TUNSETIFF, TUNSETVNETHDRSZ, TUNSETVNETLE, TUNSETOFFLOAD, SIOCSIFMTU};
    for (unsigned mode = 0; mode < 2; ++mode)
    {
        for (unsigned i = 0; i < ARRAY_SIZE(serious_failures); ++i)
        {
            resetGsoSetup();
            fail_gso_ioctl_request = serious_failures[i];
            fail_gso_ioctl_errno   = EIO;
            active = tundeviceCreate("ww-lifetime-test", mode != 0, true, 1500, NULL, NULL, kDeviceFragmentPreserve);
            require(active == NULL && raw_setiff_calls == 0 && tun_open_calls == 1,
                    "genuine construction failure was treated as optional capability rejection");
        }
        resetGsoSetup();
        fail_tun_open_call = 1;
        require(tundeviceCreate("ww-lifetime-test", mode != 0, true, 1500, NULL, NULL, kDeviceFragmentPreserve) ==
                        NULL &&
                    tun_open_calls == 1,
                "open failure retried optional capability fallback");
        resetGsoSetup();
        fail_nonblocking = true;
        require(tundeviceCreate("ww-lifetime-test", mode != 0, true, 1500, NULL, NULL, kDeviceFragmentPreserve) ==
                        NULL &&
                    tun_open_calls == 1 && raw_setiff_calls == 0,
                "nonblocking failure entered capability fallback");
    }
}

static void testOffloadResourceFallbacks(void)
{
    for (unsigned mode = 0; mode < 2; ++mode)
        for (unsigned failure = 0; failure < 2; ++failure)
        {
            resetGsoSetup();
            resetReaderFixture(0);
            fail_output_budget_once = failure == 0;
            fail_worker_queue_once  = failure == 1;
            tun_device_t *tdev =
                tundeviceCreate("ww-lifetime-test", mode != 0, true, 1500, NULL, NULL, kDeviceFragmentPreserve);
            require(tdev && ! tundeviceEnableTrustedChecksums(tdev) && active_offload_mask == 0 &&
                        raw_setiff_calls == 1 && output_budget_calls == (failure == 0 ? 2U : 1U),
                    "common resource failure did not roll back into usable raw mode");
            require(bringUpDevice(tdev) && bringDownDevice(tdev), "partially configured session lost raw usability");
            destroyDevice(tdev);
        }
    for (unsigned failure = 0; failure < 4; ++failure)
    {
        resetGsoSetup();
        resetReaderFixture(0);
        resetTunLogCapture();
        fail_worker_gso_once = true;
        fail_offload_call    = failure == 0 ? 0 : 3;
        fail_feature_check   = failure == 2 ? 2 : 0;
        fail_tun_open_call   = failure == 3 ? 2 : 0;
        tun_device_t *tdev = tundeviceCreate("ww-lifetime-test", true, true, 1500, NULL, NULL, kDeviceFragmentPreserve);
        require(! fail_worker_gso_once && output_budget_calls == 1, "GSO-only failure repeated common setup");
        if (failure == 3)
        {
            require(tdev == NULL, "serious checksum-only reopen failure published a device");
            continue;
        }
        require(tdev && active_offload_mask == (failure == 2 ? 0UL : (unsigned long) TUN_F_CSUM) &&
                    tundeviceEnableTrustedChecksums(tdev) == (failure != 2),
                "GSO resource downgrade disagrees with kernel features or trust");
        require(tun_open_calls == (failure == 0 ? 1U : failure == 1 ? 2U : 3U), "unexpected downgrade reopen count");
        require(countTunLogSubstring("configured framing: checksum-only offload") == (failure == 2 ? 0U : 1U),
                "GSO downgrade published the wrong mode");
        require(bringUpDevice(tdev) && bringDownDevice(tdev), "downgraded device could not start and stop");
        destroyDevice(tdev);
    }
}

static void *tunRefusalWriterRoutine(void *userdata)
{
    tun_refusal_probe_t *probe = userdata;
    testWorkerBindWID(0);
    sbuf_t *buf = sbufCreate(64);
    require(buf != NULL, "failed to create fresh TUN refusal helper buffer");
    sbufSetLength(buf, 64);
    probe->accepted = queueWriterPacket(probe->tdev, buf);
    if (! probe->accepted)
    {
        sbufDestroy(buf);
    }
    testWorkerUnbindWID();
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

static bool discardWriterBatch(void *context, worker_t *worker, sbuf_t **buffers, size_t count)
{
    discard context;
    for (size_t i = 0; i < count; ++i)
        bufferpoolReuseBuffer(worker->buffer_pool, buffers[i]);
    return true;
}

static void reopenTunWriterWithCapacityOne(tun_device_t *tdev)
{
    tun_writer_t *writer = tunLinuxWriter(tdev);
    tunWriterCloseRequest(writer);
    tunWriterCloseWait(writer);
    require(tunWriterOpen(writer, 1, SIZE_MAX, NULL, discardWriterBatch),
            "failed to open synthetic capacity-one TUN output queue");
}

static void testTunWriterRefusalClassesUseFreshTlsState(void)
{
    /* Down reaches the actual Linux TUN device layer without a published writer
     * generation. A fresh helper starts its sparse TLS sampler at ordinal one. */
    resetReaderFixture(0);
    tun_device_t *tdev = createRawDevice("ww-lifetime-test", false, 1500, NULL, NULL, kDeviceFragmentPreserve);
    require(tdev != NULL, "failed to create down TUN refusal fixture");
    tun_refusal_probe_t down = {.tdev = tdev};
    resetTunLogCapture();
    runFreshTunRefusalThread(&down);
    require(countTunLogSubstring("TunDevice: write failed, device is down") == 1,
            "fresh TUN writer thread did not emit exactly its first Down diagnostic");
    destroyDevice(tdev);

    /* The real wrapper remains UP while its test fixture replaces the large
     * production generation with a capacity-one open one. Full is silent. */
    resetReaderFixture(0);
    tdev = createRunningDevice();
    reopenTunWriterWithCapacityOne(tdev);
    sbuf_t *prefill = sbufCreate(64);
    require(prefill != NULL, "failed to create TUN Full-refusal prefill buffer");
    sbufSetLength(prefill, 64);
    require(queueWriterPacket(tdev, prefill), "failed to prefill capacity-one TUN writer generation");
    tun_refusal_probe_t full = {.tdev = tdev};
    resetTunLogCapture();
    runFreshTunRefusalThread(&full);
    require(tun_log_capture_len == 0, "TUN Full refusal emitted a diagnostic");
    require(bringDownDevice(tdev), "failed to bring down TUN Full-refusal fixture");
    destroyDevice(tdev);
    cancelWriterMessages();
}

static void postOne(tun_device_t *tdev, sbuf_t *buf)
{
    unsigned int before = captured_message_count;
    require(deviceReaderSessionTryPost(tunLinuxReaderSession(tdev), 0, &buf, 1) == kDeviceReaderPostAccepted,
            "worker reader admitted its packet without blocking");
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
    require(atomicLoadExplicit(&session->refcount, memory_order_acquire) == 4,
            "posting retains message, FIFO token and receive generation");

    destroyDevice(tdev);
    require(atomicLoadExplicit(&session->refcount, memory_order_acquire) == 2,
            "device destroy leaves only the FIFO token and pending message references");
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
    for (unsigned restart = 0; restart < 2; ++restart)
    {
        resetCapturedMessages();
        callback_count                   = 0;
        tun_device_t            *tdev    = createRunningReaderDevice();
        device_reader_session_t *session = tunLinuxReaderSession(tdev);
        sbuf_t                  *buf     = bufferpoolGetSmallBuffer(getWorkerBufferPool(0));
        postOne(tdev, buf);
        require(bringDownDevice(tdev), "production bring-down failed");
        require(! quiescenceGateEnter(&session->delivery_gate), "delivery gate accepted entry after bring-down");
        if (restart)
            require(bringUpDevice(tdev), "production restart bring-up failed");
        expected_discarded_buffer = buf;
        expected_discard_count    = 0;
        deliverMessage(0, getCurrentEventWorker());
        require(callback_count == 0, "closed or stale delivery invoked the device callback");
        require(expected_discard_count == 1, "closed or stale FIFO entry was not discarded exactly once");
        expected_discarded_buffer = NULL;
        destroyDevice(tdev);
        resetCapturedMessages();
    }
}

static void testBringUpRollsBackRejectedActivation(void)
{
    for (unsigned int failed_call = 1; failed_call <= 1; failed_call++)
    {
        resetReaderFixture(failed_call);
        tun_device_t *tdev =
            createRawDevice("ww-lifetime-test", false, 1500, NULL, observeReadCallback, kDeviceFragmentPreserve);
        require(tdev != NULL, "activation-failure device create failed");

        device_reader_session_t *session           = tunLinuxReaderSession(tdev);
        uint32_t                 failed_generation = (uint32_t) atomicLoadRelaxed(&session->generation) + 1U;
        require(! bringUpDevice(tdev), "bring-up unexpectedly survived a worker-activation failure");
        require(fake_thread_create_calls == 0, "worker activation failure created a thread");
        require(fake_thread_join_calls == 0, "bring-up rollback joined the wrong number of started threads");
        require(! tundeviceIsUp(tdev), "worker-activation rollback left the device up");
        require(! quiescenceGateIsActive(&session->delivery_gate),
                "worker-activation rollback left the delivery gate open");
        require(atomicLoadExplicit(&session->refcount, memory_order_acquire) == 1,
                "worker-activation rollback leaked a reader-session reference");
        require((uint32_t) atomicLoadRelaxed(&session->generation) == failed_generation,
                "failed bring-up did not stamp exactly one reader generation");

        resetReaderFixture(0);
        require(bringUpDevice(tdev), "device could not restart after worker-activation rollback");
        require((uint32_t) atomicLoadRelaxed(&session->generation) == failed_generation + 1U,
                "restart after rollback did not advance the reader generation");
        require(bringDownDevice(tdev), "restart after worker-activation rollback did not shut down");
        destroyDevice(tdev);
    }
}

static void testWatcherFailureRequestsShutdown(void)
{
    resetReaderFixture(0);
    resetShutdownRequests();
    resetIoInjection();
    tun_device_t *tdev =
        createRawDevice("ww-lifetime-test", false, 1500, NULL, observeReadCallback, kDeviceFragmentPreserve);
    require(tdev != NULL, "watcher-failure device create");
    fail_watcher_registration = true;
    require(bringUpDevice(tdev), "device publishes before queued worker activation");
    require(tunLinuxLifecycleState(tdev) == kTunLifecycleFailed && shutdown_request_calls == 1,
            "worker readiness registration failure requests one orderly shutdown");
    require(bringDownDevice(tdev), "failed watcher generation retires");
    require(watcher_detach_calls == 1 && fake_thread_create_calls == 0 && fake_thread_join_calls == 0,
            "watcher released without auxiliary threads");
    destroyDevice(tdev);
}

static void testNormalStopDoesNotRequestShutdown(void)
{
    resetReaderFixture(0);
    resetShutdownRequests();
    resetIoInjection();
    tun_device_t *tdev         = createRunningReaderDevice();
    wio_cb        old_callback = reader_ready_callback;
    require(bringDownDevice(tdev), "normal stop closes worker readiness");
    require(watcher_detach_calls == 1 && reader_io.userdata == NULL,
            "normal stop detaches the callback root before reclamation");
    old_callback(&reader_io);
    require(tunLinuxLifecycleState(tdev) == kTunLifecycleDown && shutdown_request_calls == 0,
            "late readiness after normal stop remains inert");
    destroyDevice(tdev);
}

/*
 * A permanent read error must stop receive readiness, publish FAILED and
 * request orderly shutdown.
 *
 * Before this, the drain helper reported "other error" and the reader loop
 * ignored it: on a dead-but-readable handle that became an unbounded spin that
 * discarded every packet while tundeviceIsUp() still advertised the device.
 */
static void testPermanentReadErrorFailsTheDevice(int io_errno, const char *label)
{
    discard label;

    resetReaderFixture(0);
    resetShutdownRequests();
    resetIoInjection();

    tun_device_t *tdev =
        createRawDevice("ww-lifetime-test", false, 1500, NULL, observeReadCallback, kDeviceFragmentPreserve);
    require(tdev != NULL, "read-error device create failed");
    require(bringUpDevice(tdev), "read-error device bring-up failed");
    require(tundeviceIsUp(tdev), "bring-up did not publish the device as up");

    // Exactly one device read is expected. A reader that swallows the error
    // asks for a second one and trips the wrap's own assertion.
    const injected_io_result_t reads[] = {{.result = -1, .error = io_errno}};
    armDeviceReads(reads, ARRAY_SIZE(reads));

    runReaderUntilIdle();

    require(observed_read_calls == 1, "a permanent read error did not end the read routine immediately");
    require(! tundeviceIsUp(tdev), "a permanent read error left the device advertised as up");
    require(tunLinuxLifecycleState(tdev) == kTunLifecycleFailed, "a permanent read error did not publish FAILED");
    require(shutdown_request_calls == 1, "a permanent read error did not request exactly one shutdown");
    require(shutdown_request_last_code == 1, "a permanent read error requested the wrong exit code");

    resetIoInjection();
    require(bringDownDevice(tdev), "bring-down after a permanent read error failed");
    destroyDevice(tdev);
}

// EAGAIN yields to the event loop with the device still up. Only the following
// permanent error ends receive readiness. The in-flight check runs on read #2, before the routine has returned.
static void testTransientReadErrorKeepsTheDeviceUp(void)
{
    resetReaderFixture(0);
    resetShutdownRequests();
    resetIoInjection();

    tun_device_t *tdev =
        createRawDevice("ww-lifetime-test", false, 1500, NULL, observeReadCallback, kDeviceFragmentPreserve);
    require(tdev != NULL, "transient-read device create failed");
    require(bringUpDevice(tdev), "transient-read device bring-up failed");

    const injected_io_result_t reads[] = {
        {.result = -1, .error = EAGAIN},
        {.result = -1, .error = EIO},
    };
    armDeviceReads(reads, ARRAY_SIZE(reads));
    in_flight_device     = tdev;
    in_flight_check_call = 2;

    runReaderUntilIdle();

    require(observed_read_calls == 2, "EAGAIN did not yield until another readiness callback");
    require(in_flight_checks_run == 1, "the in-flight recoverable-error check never ran");
    require(tunLinuxLifecycleState(tdev) == kTunLifecycleFailed,
            "the permanent read error after EAGAIN did not publish FAILED");
    require(shutdown_request_calls == 1, "the permanent read error after EAGAIN did not request one shutdown");

    resetIoInjection();
    require(bringDownDevice(tdev), "bring-down after a transient read error failed");
    destroyDevice(tdev);
}

// Queues packets on the current event worker without entering native I/O.
static void queuePacketsForWriter(tun_device_t *tdev, unsigned int count)
{
    for (unsigned int i = 0; i < count; i++)
    {
        sbuf_t *buf = bufferpoolGetSmallBuffer(getWorkerBufferPool(0));
        sbufSetLength(buf, 64);
        require(queueWriterPacket(tdev, buf), "queuing a packet for the writer failed");
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

    resetReaderFixture(0);
    resetShutdownRequests();
    resetIoInjection();

    tun_device_t *tdev = createRunningReaderDevice();
    require(tundeviceIsUp(tdev), "bring-up did not publish the device as up");

    // One armed write, two queued packets: a writer that swallows the error
    // reaches for the second packet and trips the wrap's own assertion.
    const injected_io_result_t writes[] = {{.result = -1, .error = io_errno}};
    armDeviceWrites(writes, ARRAY_SIZE(writes));
    queuePacketsForWriter(tdev, 2);

    runWriterMessages();

    require(observed_write_calls == 1, "a permanent write error did not end the write routine immediately");
    require(! tundeviceIsUp(tdev), "a permanent write error left the device advertised as up");
    require(tunLinuxLifecycleState(tdev) == kTunLifecycleFailed, "a permanent write error did not publish FAILED");
    require(shutdown_request_calls == 1, "a permanent write error did not request exactly one shutdown");
    require(shutdown_request_last_code == 1, "a permanent write error requested the wrong exit code");

    resetIoInjection();
    require(bringDownDevice(tdev), "bring-down after a permanent write error failed");
    destroyDevice(tdev);
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
    resetReaderFixture(0);
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

    runWriterMessages();

    require(observed_write_calls == 3, "a recoverable write error ended the write routine");
    require(in_flight_checks_run == 1, "the in-flight recoverable-error check never ran");
    require(tunLinuxLifecycleState(tdev) == kTunLifecycleFailed,
            "the permanent write error after the recoverable ones did not publish FAILED");
    require(shutdown_request_calls == 1, "the permanent write error did not request exactly one shutdown");

    resetIoInjection();
    require(bringDownDevice(tdev), "bring-down after recoverable write errors failed");
    destroyDevice(tdev);
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
    resetReaderFixture(0);
    tun_device_t *tdev = createRunningReaderDevice();

    fail_interface_down_calls = 1;
    interface_down_attempts   = 0;

    require(! bringDownDevice(tdev), "interface-down failure reported successful cleanup");
    require(tunLinuxLifecycleState(tdev) == kTunLifecycleStopping, "interface-down failure did not retain STOPPING");
    require(fake_thread_join_calls == 0 && watcher_detach_calls == 1,
            "interface-down failure did not detach its watcher");
    require(interface_down_attempts == 1, "interface-down failure did not attempt interface cleanup");
    require(! bringUpDevice(tdev), "bring-up was accepted while interface cleanup remained incomplete");

    require(bringDownDevice(tdev), "interface-down cleanup retry failed");
    require(tunLinuxLifecycleState(tdev) == kTunLifecycleDown, "successful interface-down retry did not publish DOWN");
    require(interface_down_attempts == 2, "cleanup retry did not retry the interface-down operation");
    require(fake_thread_join_calls == 0 && watcher_detach_calls == 1, "cleanup retry repeated watcher release");

    destroyDevice(tdev);
}

static void testPendingWriterMessagesAfterStop(void)
{
    for (unsigned mode = 0; mode < 3; ++mode)
    {
        resetReaderFixture(0);
        resetIoInjection();
        tun_device_t *tdev = createRunningDevice();
        require(fake_thread_create_calls == 0, "write-only TUN created an auxiliary thread");
        writer_batch_count = 4;
        memoryZero(writer_batch_settled, sizeof(writer_batch_settled));
        for (unsigned i = 0; i < writer_batch_count; ++i)
        {
            sbuf_t *buf = sbufCreate(64);
            sbufSetLength(buf, 64);
            writer_batch_buffers[i] = buf;
            require(queueWriterPacket(tdev, buf), "pending writer enqueue failed");
        }
        require(writer_message_count == 1, "TUN did not coalesce the worker flush token");
        require(observed_write_calls == 0 && observed_writev_calls == 0,
                "enqueue-only TUN callback entered native I/O");
        writer_batch_probe = true;
        require(bringDownDevice(tdev), "stop with pending worker output failed");
        for (unsigned i = 0; i < writer_batch_count; ++i)
            require(writer_batch_settled[i] == 1, "stop did not settle queued output exactly once");
        if (mode == 1)
            require(bringUpDevice(tdev), "restart with a stale writer token failed");
        if (mode == 2)
        {
            destroyDevice(tdev);
            testWorkerUnbindWID();
            cancelWriterMessages();
            testWorkerBindWID(0);
        }
        else
        {
            runWriterMessages();
            require(tundeviceIsUp(tdev) == (mode == 1), "stale writer token changed lifecycle");
            destroyDevice(tdev);
        }
        for (unsigned i = 0; i < writer_batch_count; ++i)
            require(writer_batch_settled[i] == 1, "stale token settled an output twice");
        writer_batch_probe = false;
        require(observed_write_calls == 0 && observed_writev_calls == 0,
                "stale writer token wrote to a stopped or restarted device");
    }
}

/*
 * When the worker-0 handoff is unavailable, the documented fallback is the hard
 * abort. abortProgramNow() is _Noreturn, so this runs in a forked child and the
 * parent checks the status the wrap function exits with.
 */
static void testHandoffFailureFallsBackToHardAbort(bool from_writer)
{
    // fork()/waitpid() are wrapped for the device's script-running paths, so
    // this test must reach the real ones to actually spawn a child.
    pid_t child = __real_fork();
    require(child >= 0, "failed to fork the TUN handoff-failure child");

    if (child == 0)
    {
        resetReaderFixture(0);
        resetShutdownRequests();
        shutdown_request_accepts = false;
        hard_abort_is_expected   = true;
        bufferpoolResetThreadOwnership(getWorkerBufferPool(0));

        tun_device_t *tdev =
            createRawDevice("ww-lifetime-test", false, 1500, NULL, observeReadCallback, kDeviceFragmentPreserve);
        if (tdev == NULL)
        {
            _Exit(70);
        }
        if (! bringUpDevice(tdev))
        {
            _Exit(71);
        }

        // The wrapper requests shutdown, is refused, and must hard-abort rather
        // than let the process keep running with a dead TUN device.
        if (from_writer)
        {
            resetIoInjection();
            const injected_io_result_t writes[] = {{.result = -1, .error = EIO}};
            armDeviceWrites(writes, ARRAY_SIZE(writes));
            queuePacketsForWriter(tdev, 1);
            runWriterMessages();
        }
        else
        {
            resetIoInjection();
            const injected_io_result_t reads[] = {{.result = -1, .error = EIO}};
            armDeviceReads(reads, ARRAY_SIZE(reads));
            runReaderUntilIdle();
        }
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
static void testReaderFragmentPolicy(bool normalized, bool trusted_pair, bool corrupt_header)
{
    resetReaderFixture(0);
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
        if (corrupt_header)
            p[10] ^= 1;
    }
    tun_device_t *tdev = createRawDevice("ww-fragment-test",
                                         false,
                                         1500,
                                         NULL,
                                         observeFragmentPacket,
                                         normalized ? kDeviceFragmentReassemble : kDeviceFragmentPreserve);
    require(tdev && ! tundeviceEnableTrustedChecksums(tdev) && active_offload_mask == 0,
            "raw device did not retain default receive/transmit policy");
    if (trusted_pair)
    {
        require(tundeviceEnableTrustedReceiveChecksums(tdev), "raw direct-pair receive trust was unavailable");
        require(! tundeviceEnableTrustedChecksums(tdev) && active_offload_mask == 0,
                "raw direct-pair trust enabled transmit offload");
    }
    require(bringUpDevice(tdev), "fragment backend setup failed");
    const injected_io_result_t reads[] = {{.result = 84, .bytes = packets[1]},
                                          {.result = 84, .bytes = packets[0]},
                                          {.result = -1, .error = EAGAIN},
                                          {.result = -1, .error = EIO}};
    normalized_delivery                = normalized;
    fragment_deliveries                = 0;
    deliver_fragment_batch             = ! corrupt_header || trusted_pair;
    armDeviceReads(reads, ARRAY_SIZE(reads));
    runReaderUntilIdle();
    deliver_fragment_batch  = false;
    const unsigned expected = corrupt_header && ! trusted_pair ? 0U : normalized ? 1U : 2U;
    require(fragment_deliveries == expected, "backend fragment/receive-checksum policy lost/duplicated packets");
    resetIoInjection();
    require(bringDownDevice(tdev), "fragment backend shutdown failed");
    destroyDevice(tdev);
}

enum
{
    kGsoFixtureIpLength     = 43,
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

typedef struct ordinary_checksum_fixture_s
{
    uint8_t  packets[8][80];
    uint32_t lengths[8];
    unsigned count;
    unsigned delivered;
} ordinary_checksum_fixture_t;

static void observeOrdinaryChecksum(tun_device_t *tdev, void *userdata, sbuf_t *buf, wid_t wid)
{
    discard                      tdev;
    ordinary_checksum_fixture_t *fixture = userdata;
    require(currentThreadIsEventWorkerWID(wid), "ordinary checksum delivery used a foreign worker");
    require(fixture->delivered < fixture->count, "unexpected ordinary checksum delivery");
    const unsigned index = fixture->delivered++;
    require(sbufGetLength(buf) == fixture->lengths[index] &&
                memoryEqual(sbufGetRawPtr(buf), fixture->packets[index], fixture->lengths[index]),
            "ordinary/GSO FIFO changed packet bytes, checksum, or order");
    require(sbufGetAllocationCharge(buf) < 65536, "ordinary checksum retained GSO-sized packet storage");
    bufferpoolReuseBuffer(getWorkerBufferPool(wid), buf);
}

static void expectOrdinaryChecksum(ordinary_checksum_fixture_t *fixture, const uint8_t *record, uint32_t length)
{
    const unsigned index = fixture->count++;
    require(index < ARRAY_SIZE(fixture->packets) && length <= sizeof(fixture->packets[index]),
            "ordinary checksum fixture overflow");
    fixture->lengths[index] = length;
    memoryCopy(fixture->packets[index], record + 10, length);
    if ((record[0] & VIRTIO_NET_HDR_F_NEEDS_CSUM) != 0)
    {
        const uint16_t start    = (uint16_t) (record[6] | ((uint16_t) record[7] << 8U));
        const uint16_t field    = start + (uint16_t) (record[8] | ((uint16_t) record[9] << 8U));
        uint16_t       checksum = (uint16_t) ~gsoChecksumWords(record + 10 + start, length - start, 0);
        PUT_BE16(fixture->packets[index] + field, checksum == 0 ? UINT16_MAX : checksum);
    }
}

static void testOrdinaryChecksumWorkerHandoff(bool gso_requested, bool cancel, bool stale)
{
    resetShutdownRequests();
    resetIoInjection();
    resetCapturedMessages();
    resetGsoSetup();
    resetReaderFixture(0);
    ordinary_checksum_fixture_t fixture = {0};
    tun_device_t               *tdev    = tundeviceCreate(
        "ww-lifetime-test", gso_requested, true, 1500, &fixture, observeOrdinaryChecksum, kDeviceFragmentReassemble);
    require(tdev && bringUpDevice(tdev), "ordinary checksum device setup");
    uint8_t record[kGsoFixtureRecordLength];
    makeSmallGsoRecord(record);
    require(tunLinuxOffloadEncodeWrite(record + 10, kGsoFixtureIpLength, record), "ordinary partial fixture seed");
    expectOrdinaryChecksum(&fixture, record, kGsoFixtureIpLength);
    const injected_io_result_t reads[] = {
        {.result = sizeof(record), .bytes = record}, {.result = -1, .error = EAGAIN}, {.result = -1, .error = EIO}};
    armDeviceReads(reads, ARRAY_SIZE(reads));
    drive_worker_delivery        = true;
    gso_deliver_after_read_calls = cancel || stale ? 100 : 2;
    gso_probe_session            = tunLinuxReaderSession(tdev);
    runReaderUntilIdle();
    require(receive_checksum_completions == 0, "ordinary NEEDS_CSUM completion still ran on the reader");
    device_reader_session_t *session = gso_probe_session;
    if (cancel || stale)
    {
        require(fixture.delivered == 0 && queued_checksum_completions == 0 && captured_message_count == 1,
                "ordinary pending checksum completed before worker admission");
        resetIoInjection();
        require(bringDownDevice(tdev), "ordinary pending checksum stop");
        if (stale)
        {
            require(bringUpDevice(tdev), "ordinary pending checksum restart");
            worker_t worker = {.wid = 0};
            deliverMessage(0, &worker);
        }
        else
        {
            deviceReaderSessionRef(session);
            destroyDevice(tdev);
            tdev = NULL;
            testWorkerUnbindWID();
            cleanupMessage(0);
            testWorkerBindWID(0);
        }
        require(fixture.delivered == 0 && queued_checksum_completions == 0,
                "cancelled/stale ordinary work performed checksum or delivery");
    }
    else
    {
        require(fixture.delivered == 1 && queued_checksum_completions == 1,
                "ordinary checksum did not complete once on the destination worker");
    }
    require(atomic_load_explicit(&session->output_packets, memory_order_acquire) == 0 &&
                atomic_load_explicit(&session->output_charge, memory_order_acquire) == 0,
            "ordinary checksum reservation leak");
    if (cancel)
    {
        deviceReaderSessionUnref(session);
    }
    resetIoInjection();
    if (tdev != NULL)
    {
        require(bringDownDevice(tdev), "ordinary checksum final stop");
        destroyDevice(tdev);
    }
    resetCapturedMessages();
}

static void testOrdinaryChecksumMixedFifo(bool gso_requested)
{
    resetShutdownRequests();
    resetIoInjection();
    resetCapturedMessages();
    resetGsoSetup();
    resetReaderFixture(0);
    GSTATE.ram_profile                  = 8;
    ordinary_checksum_fixture_t fixture = {0};
    tun_device_t               *tdev    = tundeviceCreate(
        "ww-lifetime-test", gso_requested, true, 1500, &fixture, observeOrdinaryChecksum, kDeviceFragmentReassemble);
    require(tdev && bringUpDevice(tdev), "mixed ordinary checksum device setup");
    uint8_t ordinary[kGsoFixtureRecordLength], partial[kGsoFixtureRecordLength], aggregate[kGsoFixtureRecordLength];
    makeSmallGsoRecord(ordinary);
    PUT_BE32(ordinary + 10 + 24, 2000);
    require(tunLinuxOffloadEncodeWrite(ordinary + 10, kGsoFixtureIpLength, ordinary), "ordinary fixture seed");
    expectOrdinaryChecksum(&fixture, ordinary, kGsoFixtureIpLength);
    memoryCopy(ordinary + 10, fixture.packets[0], kGsoFixtureIpLength);
    memoryZero(ordinary, 10);
    makeSmallGsoRecord(partial);
    PUT_BE32(partial + 10 + 24, 3000);
    require(tunLinuxOffloadEncodeWrite(partial + 10, kGsoFixtureIpLength, partial), "mixed partial fixture seed");
    expectOrdinaryChecksum(&fixture, partial, kGsoFixtureIpLength);
    makeSmallGsoRecord(aggregate);
    if (! gso_requested)
    {
        require(tunLinuxOffloadEncodeWrite(aggregate + 10, kGsoFixtureIpLength, aggregate), "checksum-only FIFO seed");
        expectOrdinaryChecksum(&fixture, aggregate, kGsoFixtureIpLength);
    }
    else
    {
        for (unsigned part = 0; part < 3; ++part)
        {
            uint8_t  segment[51] = {0};
            uint8_t *ip          = segment + 10;
            memoryCopy(ip, aggregate + 10, 40);
            PUT_BE16(ip + 2, 41);
            PUT_BE16(ip + 4, 0x1234U + part);
            PUT_BE32(ip + 24, 1000U + part);
            ip[33] = part == 2 ? 0x19 : 0x10;
            ip[40] = (uint8_t) ('A' + part);
            PUT_BE16(ip + 10, 0);
            PUT_BE16(ip + 10, (uint16_t) ~gsoChecksumWords(ip, 20, 0));
            uint32_t seed = gsoChecksumWords(ip + 12, 8, 0) + 6U + 21U;
            PUT_BE16(ip + 36, (uint16_t) seed);
            segment[0] = VIRTIO_NET_HDR_F_NEEDS_CSUM;
            segment[6] = 20;
            segment[8] = 16;
            expectOrdinaryChecksum(&fixture, segment, 41);
        }
    }
    uint8_t  udp[41] = {0};
    uint8_t *ip      = udp + 10;
    memoryCopy(ip, aggregate + 10, 20);
    PUT_BE16(ip + 2, 31);
    ip[9] = 17;
    PUT_BE16(ip + 20, 1234);
    PUT_BE16(ip + 22, 53);
    PUT_BE16(ip + 24, 11);
    memoryCopy(ip + 28, "XYZ", 3);
    PUT_BE16(ip + 10, 0);
    PUT_BE16(ip + 10, (uint16_t) ~gsoChecksumWords(ip, 20, 0));
    require(tunLinuxOffloadEncodeWrite(ip, 31, udp), "UDP partial fixture seed");
    expectOrdinaryChecksum(&fixture, udp, 31);
    uint8_t ipv6[73] = {0};
    ip               = ipv6 + 10;
    ip[0]            = 0x60;
    PUT_BE16(ip + 4, 23);
    ip[6]  = 6;
    ip[7]  = 64;
    ip[23] = 1;
    ip[39] = 2;
    memoryCopy(ip + 40, partial + 10 + 20, 20);
    memoryCopy(ip + 60, "UVW", 3);
    PUT_BE16(ip + 56, (uint16_t) (gsoChecksumWords(ip + 8, 32, 0) + 23U + 6U));
    ipv6[0] = VIRTIO_NET_HDR_F_NEEDS_CSUM;
    ipv6[6] = 40;
    ipv6[8] = 16;
    expectOrdinaryChecksum(&fixture, ipv6, 63);
    uint8_t ipv6_udp[61] = {0};
    memoryCopy(ipv6_udp + 10, ipv6 + 10, 40);
    ip = ipv6_udp + 10;
    PUT_BE16(ip + 4, 11);
    ip[6] = 17;
    memoryCopy(ip + 40, udp + 30, 11);
    PUT_BE16(ip + 46, (uint16_t) (gsoChecksumWords(ip + 8, 32, 0) + 17U + 11U));
    ipv6_udp[0] = VIRTIO_NET_HDR_F_NEEDS_CSUM;
    ipv6_udp[6] = 40;
    ipv6_udp[8] = 6;
    expectOrdinaryChecksum(&fixture, ipv6_udp, 51);
    const injected_io_result_t reads[] = {{.result = sizeof(ordinary), .bytes = ordinary},
                                          {.result = sizeof(partial), .bytes = partial},
                                          {.result = sizeof(aggregate), .bytes = aggregate},
                                          {.result = sizeof(udp), .bytes = udp},
                                          {.result = sizeof(ipv6), .bytes = ipv6},
                                          {.result = sizeof(ipv6_udp), .bytes = ipv6_udp},
                                          {.result = -1, .error = EAGAIN},
                                          {.result = -1, .error = EIO}};
    armDeviceReads(reads, ARRAY_SIZE(reads));
    drive_worker_delivery        = true;
    gso_deliver_after_read_calls = 7;
    gso_probe_session            = tunLinuxReaderSession(tdev);
    runReaderUntilIdle();
    require(fixture.delivered == (gso_requested ? 8U : 6U) &&
                queued_checksum_completions == (gso_requested ? 4U : 5U) && receive_checksum_completions == 0 &&
                prepared_gso_segments == (gso_requested ? 3U : 0U) && captured_message_count == 1 &&
                observed_read_calls == ARRAY_SIZE(reads),
            "mixed FIFO lost checksum work, batching, or coalesced worker dispatch");
    require(atomic_load_explicit(&gso_probe_session->output_packets, memory_order_acquire) == 0 &&
                atomic_load_explicit(&gso_probe_session->output_charge, memory_order_acquire) == 0,
            "mixed ordinary checksum reservation leak");
    resetIoInjection();
    require(bringDownDevice(tdev), "mixed ordinary checksum stop");
    destroyDevice(tdev);
    resetCapturedMessages();
    GSTATE.ram_profile = 1;
}

static void testOrdinaryChecksumBudget(bool gso_requested)
{
    resetShutdownRequests();
    resetIoInjection();
    resetCapturedMessages();
    resetGsoSetup();
    resetReaderFixture(0);
    ordinary_checksum_fixture_t fixture = {0};
    tun_device_t               *tdev    = tundeviceCreate(
        "ww-lifetime-test", gso_requested, true, 1500, &fixture, observeOrdinaryChecksum, kDeviceFragmentReassemble);
    require(tdev && bringUpDevice(tdev), "ordinary checksum budget device setup");
    gso_probe_session                      = tunLinuxReaderSession(tdev);
    gso_probe_session->output_packet_limit = 1;
    uint8_t record[kGsoFixtureRecordLength];
    makeSmallGsoRecord(record);
    require(tunLinuxOffloadEncodeWrite(record + 10, kGsoFixtureIpLength, record), "budget partial fixture seed");
    expectOrdinaryChecksum(&fixture, record, kGsoFixtureIpLength);
    expectOrdinaryChecksum(&fixture, record, kGsoFixtureIpLength);
    const injected_io_result_t reads[] = {{.result = sizeof(record), .bytes = record},
                                          {.result = sizeof(record), .bytes = record},
                                          {.result = -1, .error = EAGAIN},
                                          {.result = -1, .error = EIO}};
    armDeviceReads(reads, ARRAY_SIZE(reads));
    drive_worker_delivery        = true;
    gso_deliver_after_read_calls = 3;
    runReaderUntilIdle();
    require(fixture.delivered == 2 && queued_checksum_completions == 2 && receive_checksum_completions == 0 &&
                capacity_resumes == 1,
            "ordinary pending checksum did not resume after one-slot budget pressure");
    require(atomic_load_explicit(&gso_probe_session->output_packets, memory_order_acquire) == 0 &&
                atomic_load_explicit(&gso_probe_session->output_charge, memory_order_acquire) == 0,
            "ordinary checksum budget reservation leak");
    resetIoInjection();
    require(bringDownDevice(tdev), "ordinary checksum budget stop");
    destroyDevice(tdev);
    resetCapturedMessages();
}

static void testOrdinaryChecksumReaderFallback(bool gso_requested, bool reassemble)
{
    resetShutdownRequests();
    resetIoInjection();
    resetCapturedMessages();
    resetGsoSetup();
    resetReaderFixture(0);
    ordinary_checksum_fixture_t fixture = {0};
    tun_device_t               *tdev    = tundeviceCreate("ww-lifetime-test",
                                         gso_requested,
                                         true,
                                         1500,
                                         &fixture,
                                         observeOrdinaryChecksum,
                                         reassemble ? kDeviceFragmentReassemble : kDeviceFragmentPreserve);
    require(tdev && bringUpDevice(tdev), "ordinary checksum fallback device setup");
    uint8_t  generic[43] = {0};
    uint8_t *ip          = generic + 10;
    ip[0]                = 0x45;
    ip[8]                = 64;
    ip[9]                = 253;
    PUT_BE16(ip + 2, 33);
    PUT_BE32(ip + 12, 0x0a000001);
    PUT_BE32(ip + 16, 0x0a000002);
    memoryCopy(ip + 20, "ABCDEFGHIJKLM", 13);
    generic[0] = VIRTIO_NET_HDR_F_NEEDS_CSUM;
    generic[6] = 21;
    generic[8] = 5;
    expectOrdinaryChecksum(&fixture, generic, 33);
    uint8_t fragments[2][46] = {{0}};
    for (unsigned part = 0; part < 2; ++part)
    {
        ip = fragments[part] + 10;
        memoryCopy(ip, generic + 10, 20);
        PUT_BE16(ip + 2, 36);
        PUT_BE16(ip + 4, 42);
        PUT_BE16(ip + 6, part == 0 ? 0x2000 : 2);
        ip[9] = 17;
        for (unsigned byte = 0; byte < 16; ++byte)
        {
            ip[20 + byte] = (uint8_t) (part * 16 + byte);
        }
        PUT_BE16(ip + 10, 0);
        PUT_BE16(ip + 10, (uint16_t) ~gsoChecksumWords(ip, 20, 0));
    }
    fragments[0][0] = VIRTIO_NET_HDR_F_NEEDS_CSUM;
    fragments[0][6] = 20;
    fragments[0][8] = 6;
    if (reassemble)
    {
        ordinary_checksum_fixture_t first = {0};
        expectOrdinaryChecksum(&first, fragments[0], 36);
        uint8_t assembled[62] = {0};
        ip                    = assembled + 10;
        memoryCopy(ip, first.packets[0], 36);
        memoryCopy(ip + 36, fragments[1] + 10 + 20, 16);
        PUT_BE16(ip + 2, 52);
        PUT_BE16(ip + 6, 0);
        PUT_BE16(ip + 10, 0);
        PUT_BE16(ip + 10, (uint16_t) ~gsoChecksumWords(ip, 20, 0));
        expectOrdinaryChecksum(&fixture, assembled, 52);
    }
    else
    {
        expectOrdinaryChecksum(&fixture, fragments[1], 36);
        expectOrdinaryChecksum(&fixture, fragments[0], 36);
    }
    const injected_io_result_t reads[] = {{.result = sizeof(generic), .bytes = generic},
                                          {.result = sizeof(fragments[1]), .bytes = fragments[1]},
                                          {.result = sizeof(fragments[0]), .bytes = fragments[0]},
                                          {.result = -1, .error = EAGAIN},
                                          {.result = -1, .error = EIO}};
    armDeviceReads(reads, ARRAY_SIZE(reads));
    drive_worker_delivery        = true;
    gso_deliver_after_read_calls = 4;
    gso_probe_session            = tunLinuxReaderSession(tdev);
    runReaderUntilIdle();
    require(fixture.delivered == fixture.count && queued_checksum_completions == 0 && receive_checksum_completions == 2,
            "generic/fragment checksum fallback changed reader completion or fragment policy");
    require(atomic_load_explicit(&gso_probe_session->output_packets, memory_order_acquire) == 0 &&
                atomic_load_explicit(&gso_probe_session->output_charge, memory_order_acquire) == 0,
            "ordinary checksum fallback reservation leak");
    resetIoInjection();
    require(bringDownDevice(tdev), "ordinary checksum fallback stop");
    destroyDevice(tdev);
    resetCapturedMessages();
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
    const unsigned int segment = callback_count % 3;
    require(callback_count < gso_expected_segments && sbufGetLength(buf) == 41,
            "GSO worker emitted a wrong-sized segment");
    require(GET_BE16(ip + 2) == 41 && GET_BE16(ip + 4) == 0x1234U + segment && GET_BE32(ip + 24) == 1000U + segment &&
                ip[40] == (uint8_t) ('A' + segment),
            "GSO reader lost sequence, IP ID, or payload order");
    require((ip[33] & 0x19) == (segment == 2 ? 0x19 : 0x10), "GSO reader placed FIN/PSH on a non-final segment");
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

static void observeTrustedRecord(tun_device_t *tdev, void *userdata, sbuf_t *buf, uint8_t wid)
{
    (void) tdev;
    (void) userdata;
    const uint8_t *ip = sbufGetRawPtr(buf);
    require(currentThreadIsEventWorkerWID(wid), "trusted handoff used foreign worker");
    require(gsoChecksumWords(ip, 20, 0) != 0xffff, "trusted handoff repaired the unverified IPv4 checksum");
    require(callback_count < 5 && sbufGetLength(buf) == 43 && ip[40] == 'A' && ip[41] == 'B' &&
                ip[42] == (callback_count == 3 ? ('C' ^ 1) : 'C'),
            "trusted aggregate/ordinary FIFO payload changed");
    require(GET_BE32(ip + 24) == 1000 && ip[33] == 0x19, "intact handoff changed TCP sequence or flags");
    const uint32_t transport_seed = gsoChecksumWords(ip + 12, 8, 0) + 6U + 23U;
    require((gsoChecksumWords(ip + 20, 23, transport_seed) == 0xffff) == (callback_count == 2),
            "private assurance lost or leaked into unmarked traffic");
    ++callback_count;
    bufferpoolReuseBuffer(getWorkerBufferPool(wid), buf);
}

static void testTrustedHandoff(bool gso_requested, bool cancel, bool stale)
{
    resetShutdownRequests();
    resetIoInjection();
    resetCapturedMessages();
    resetGsoSetup();
    resetReaderFixture(0);
    tun_device_t *tdev = tundeviceCreate(
        "ww-lifetime-test", gso_requested, true, 1500, NULL, observeTrustedRecord, kDeviceFragmentReassemble);
    require(tdev && tundeviceEnableTrustedChecksums(tdev), "trusted device setup");
    require(bringUpDevice(tdev), "trusted device startup");
    uint8_t aggregate[kGsoFixtureRecordLength], partial[kGsoFixtureRecordLength], ordinary[kGsoFixtureRecordLength],
        corrupt[kGsoFixtureRecordLength];
    makeSmallGsoRecord(aggregate);
    aggregate[10 + 10] ^= 1;
    require(tunLinuxOffloadEncodeWrite(aggregate + 10, 43, aggregate), "fixture partial seed");
    memoryCopy(partial, aggregate, sizeof(partial));
    if (gso_requested)
    {
        aggregate[1] = VIRTIO_NET_HDR_GSO_TCPV4;
        aggregate[2] = 40;
        aggregate[4] = 1;
    }
    memoryCopy(ordinary, partial, sizeof(ordinary));
    memoryZero(ordinary, 10);
    PUT_BE16(ordinary + 10 + 36, (uint16_t) ~gsoChecksumWords(ordinary + 10 + 20, 23, 0));
    memoryCopy(corrupt, ordinary, sizeof(corrupt));
    corrupt[52] ^= 1;
    const injected_io_result_t reads[] = {{.result = sizeof(aggregate), .bytes = aggregate},
                                          {.result = sizeof(partial), .bytes = partial},
                                          {.result = sizeof(ordinary), .bytes = ordinary},
                                          {.result = sizeof(corrupt), .bytes = corrupt},
                                          {.result = sizeof(partial), .bytes = partial},
                                          {.result = -1, .error = EIO}};
    armDeviceReads(reads, ARRAY_SIZE(reads));
    drive_worker_delivery        = true;
    gso_deliver_after_read_calls = cancel || stale ? 100 : 5;
    gso_probe_session            = tunLinuxReaderSession(tdev);
    callback_count               = 0;
    runReaderUntilIdle();
    device_reader_session_t *session = gso_probe_session;
    if (cancel || stale)
    {
        require(callback_count == 0 && captured_message_count > 0, "trusted cancellation fixture delivered early");
        resetIoInjection();
        require(bringDownDevice(tdev), "trusted pending stop");
        if (stale)
        {
            require(bringUpDevice(tdev), "trusted pending restart");
            worker_t worker = {.wid = 0};
            for (unsigned i = 0; i < captured_message_count; ++i)
                deliverMessage(i, &worker);
            require(callback_count == 0, "stale trusted record delivered");
        }
        else
        {
            deviceReaderSessionRef(session);
            destroyDevice(tdev);
            tdev = NULL;
            testWorkerUnbindWID();
            for (unsigned i = 0; i < captured_message_count; ++i)
                cleanupMessage(i);
            testWorkerBindWID(0);
        }
    }
    else
    {
        require(callback_count == 5 && prepared_gso_segments == 0, "trusted intact/ordinary/corrupt FIFO admission");
    }
    require(atomic_load_explicit(&session->output_packets, memory_order_acquire) == 0 &&
                atomic_load_explicit(&session->output_charge, memory_order_acquire) == 0,
            "trusted reservation leak");
    if (cancel && ! stale)
        deviceReaderSessionUnref(session);
    resetIoInjection();
    if (tdev)
    {
        require(bringDownDevice(tdev), "trusted final stop");
        destroyDevice(tdev);
    }
    resetCapturedMessages();
}

static void observeTrustedOrdinary(tun_device_t *tdev, void *userdata, sbuf_t *buf, wid_t wid)
{
    discard                      tdev;
    ordinary_checksum_fixture_t *fixture = userdata;
    require(currentThreadIsEventWorkerWID(wid) && fixture->delivered < fixture->count, "trusted ordinary delivery");
    const unsigned index = fixture->delivered++;
    require(sbufGetLength(buf) == fixture->lengths[index] &&
                memoryEqual(sbufGetRawPtr(buf), fixture->packets[index], fixture->lengths[index]),
            "trusted ordinary assurance or reader fallback changed bytes/order");
    bufferpoolReuseBuffer(getWorkerBufferPool(wid), buf);
}

static void testTrustedChecksumOnlyFallback(void)
{
    resetShutdownRequests();
    resetIoInjection();
    resetCapturedMessages();
    resetGsoSetup();
    resetReaderFixture(0);
    ordinary_checksum_fixture_t fixture = {0};
    tun_device_t               *tdev    = tundeviceCreate(
        "ww-lifetime-test", false, true, 1500, &fixture, observeTrustedOrdinary, kDeviceFragmentReassemble);
    require(tdev && tundeviceEnableTrustedChecksums(tdev), "trusted checksum-only fallback setup");
    require(bringUpDevice(tdev), "trusted checksum-only fallback startup");
    uint8_t tcp[kGsoFixtureRecordLength];
    makeSmallGsoRecord(tcp);
    uint8_t  udp[41] = {0};
    uint8_t *ip      = udp + 10;
    memoryCopy(ip, tcp + 10, 20);
    ip[9] = 17;
    PUT_BE16(ip + 2, 31);
    PUT_BE16(ip + 20, 1234);
    PUT_BE16(ip + 22, 53);
    PUT_BE16(ip + 24, 11);
    memoryCopy(ip + 28, "XYZ", 3);
    PUT_BE16(ip + 10, 0);
    PUT_BE16(ip + 10, (uint16_t) ~gsoChecksumWords(ip, 20, 0));
    require(tunLinuxOffloadEncodeWrite(ip, 31, udp), "trusted UDP seed");
    /* Matching partial metadata retains seed bytes in private assured work. */
    fixture.lengths[fixture.count] = 31;
    memoryCopy(fixture.packets[fixture.count++], ip, 31);
    uint8_t valid[41];
    memoryCopy(valid, udp, sizeof(valid));
    expectOrdinaryChecksum(&fixture, valid, 31);
    memoryCopy(valid + 10, fixture.packets[1], 31);
    memoryZero(valid, 10);
    valid[0] = VIRTIO_NET_HDR_F_DATA_VALID;
    /* Generic coordinates must still materialize on the reader. */
    require(tunLinuxOffloadEncodeWrite(tcp + 10, 43, tcp), "trusted generic TCP seed");
    tcp[6] = 0;
    tcp[8] = 36;
    expectOrdinaryChecksum(&fixture, tcp, 43);
    uint8_t unmarked[41], corrupt[41], contradictory[41], fragment[41];
    memoryCopy(unmarked, valid, sizeof(unmarked));
    memoryZero(unmarked, 10);
    expectOrdinaryChecksum(&fixture, unmarked, 31);
    memoryCopy(corrupt, unmarked, sizeof(corrupt));
    corrupt[40] ^= 1;
    expectOrdinaryChecksum(&fixture, corrupt, 31);
    memoryCopy(contradictory, udp, sizeof(contradictory));
    contradictory[0] |= VIRTIO_NET_HDR_F_DATA_VALID;
    memoryCopy(fragment, udp, sizeof(fragment));
    PUT_BE16(fragment + 10 + 6, 0x2000);
    const injected_io_result_t reads[] = {{.result = sizeof(udp), .bytes = udp},
                                          {.result = sizeof(valid), .bytes = valid},
                                          {.result = sizeof(tcp), .bytes = tcp},
                                          {.result = sizeof(unmarked), .bytes = unmarked},
                                          {.result = sizeof(corrupt), .bytes = corrupt},
                                          {.result = sizeof(contradictory), .bytes = contradictory},
                                          {.result = sizeof(fragment), .bytes = fragment},
                                          {.result = -1, .error = EIO}};
    armDeviceReads(reads, ARRAY_SIZE(reads));
    drive_worker_delivery        = true;
    gso_deliver_after_read_calls = 7;
    gso_probe_session            = tunLinuxReaderSession(tdev);
    runReaderUntilIdle();
    require(fixture.delivered == 5 && receive_checksum_completions == 1 && queued_checksum_completions == 0 &&
                prepared_gso_segments == 0,
            "trusted checksum-only materialization or receive admission");
    require(atomic_load_explicit(&gso_probe_session->output_packets, memory_order_acquire) == 0 &&
                atomic_load_explicit(&gso_probe_session->output_charge, memory_order_acquire) == 0,
            "trusted checksum-only fallback reservation leak");
    resetIoInjection();
    require(bringDownDevice(tdev), "trusted checksum-only fallback stop");
    destroyDevice(tdev);
    resetCapturedMessages();
}

static void testChecksumOnlyRejectsGso(void)
{
    resetShutdownRequests();
    resetIoInjection();
    resetCapturedMessages();
    tun_device_t        *tdev = createRunningOffloadReaderDevice(observeReadCallback, false);
    uint8_t              records[7][kGsoFixtureRecordLength];
    const uint8_t        types[]  = {VIRTIO_NET_HDR_GSO_TCPV4,
                                     VIRTIO_NET_HDR_GSO_TCPV6,
                                     VIRTIO_NET_HDR_GSO_UDP,
                                     5 /* UDP_L4, absent from older headers */,
                                     VIRTIO_NET_HDR_GSO_ECN,
                                     VIRTIO_NET_HDR_GSO_TCPV4 | VIRTIO_NET_HDR_GSO_ECN};
    injected_io_result_t reads[8] = {0};
    for (unsigned i = 0; i < ARRAY_SIZE(records); ++i)
    {
        makeSmallGsoRecord(records[i]);
        records[i][1] = i < ARRAY_SIZE(types) ? types[i] : VIRTIO_NET_HDR_GSO_NONE;
        reads[i]      = (injected_io_result_t) {.result = sizeof(records[i]), .bytes = records[i]};
    }
    reads[7] = (injected_io_result_t) {.result = -1, .error = EIO};
    armDeviceReads(reads, ARRAY_SIZE(reads));
    drive_worker_delivery        = true;
    gso_deliver_after_read_calls = 7;
    gso_probe_session            = tunLinuxReaderSession(tdev);
    callback_count               = 0;
    runReaderUntilIdle();
    require(callback_count == 1 && captured_message_count == 1 && prepared_gso_segments == 0 &&
                queued_checksum_completions == 0 && receive_checksum_completions == 0,
            "checksum-only reader admitted unexpected GSO work");
    require(atomic_load_explicit(&gso_probe_session->output_packets, memory_order_acquire) == 0 &&
                atomic_load_explicit(&gso_probe_session->output_charge, memory_order_acquire) == 0,
            "unexpected GSO leaked admission credits");
    resetIoInjection();
    require(bringDownDevice(tdev), "checksum-only rejection cleanup");
    destroyDevice(tdev);
    resetCapturedMessages();
}

static void testGsoWorkerSegmentationOwnsAggregate(void)
{
    resetShutdownRequests();
    resetIoInjection();
    resetCapturedMessages();
    tun_device_t *tdev = createRunningOffloadReaderDevice(observeGsoThenOrdinary, true);
    uint8_t       aggregate[kGsoFixtureRecordLength];
    uint8_t       ordinary[kGsoFixtureRecordLength];
    makeSmallGsoRecord(aggregate);
    memoryCopy(ordinary, aggregate, sizeof(ordinary));
    memoryZero(ordinary, 10); /* GSO_NONE, no deferred checksum request. */
    const injected_io_result_t reads[] = {{.result = kGsoFixtureRecordLength, .bytes = aggregate},
                                          {.result = kGsoFixtureRecordLength, .bytes = ordinary},
                                          {.result = -1, .error = EIO}};
    armDeviceReads(reads, ARRAY_SIZE(reads));
    drive_worker_delivery         = true;
    verify_gso_aggregate_transfer = true;
    gso_deliver_after_read_calls  = 2;
    gso_probe_session             = tunLinuxReaderSession(tdev);
    callback_count                = 0;

    runReaderUntilIdle();

    require(callback_count == 3 && prepared_gso_segments == 3 && ordinary_after_gso_deliveries == 1,
            "worker did not segment and deliver its owned aggregate before ordinary traffic");
    require(observed_read_calls == 3 && receive_attempts == 3 && capacity_resumes == 0,
            "scratch-overwrite fixture did not defer worker delivery until after the second read");
    require(atomic_load_explicit(&gso_probe_session->output_packets, memory_order_acquire) == 0 &&
                atomic_load_explicit(&gso_probe_session->output_charge, memory_order_acquire) == 0,
            "worker segmentation leaked aggregate reservations");
    resetIoInjection();
    require(bringDownDevice(tdev), "GSO scratch-overwrite device did not stop");
    destroyDevice(tdev);
    resetCapturedMessages();
}

static void testGsoReaderResumesPendingWithoutTunReadiness(void)
{
    resetShutdownRequests();
    resetIoInjection();
    resetCapturedMessages();
    tun_device_t            *tdev    = createRunningOffloadReaderDevice(observeGsoSegment, true);
    device_reader_session_t *session = tunLinuxReaderSession(tdev);
    session->output_packet_limit     = 2; /* One input plus its reusable output allowance. */
    uint8_t record[kGsoFixtureRecordLength];
    makeSmallGsoRecord(record);
    const injected_io_result_t reads[] = {{.result = -1, .error = EINTR},
                                          {.result = kGsoFixtureRecordLength, .bytes = record},
                                          {.result = kGsoFixtureRecordLength, .bytes = record},
                                          {.result = -1, .error = EIO}};
    armDeviceReads(reads, ARRAY_SIZE(reads));
    drive_worker_delivery        = true;
    gso_probe_session            = session;
    gso_deliver_after_read_calls = 3;
    gso_expected_segments        = 6;
    callback_count               = 0;

    runReaderUntilIdle();

    require(callback_count == 6 && prepared_gso_segments == 6 && observed_read_calls == 4,
            "GSO reader did not retry EINTR or finish repeated aggregates");
    require(capacity_resumes == 1, "pending aggregate required new TUN readiness after capacity returned");
    require(atomic_load_explicit(&session->output_packets, memory_order_acquire) == 0 &&
                atomic_load_explicit(&session->output_charge, memory_order_acquire) == 0,
            "aggregate delivery did not return every reservation");
    require(shutdown_request_calls == 1, "terminal GSO reader error did not request orderly shutdown");
    resetIoInjection();
    require(bringDownDevice(tdev), "GSO reader did not bring down after terminal error");
    destroyDevice(tdev);
    resetCapturedMessages();
}

enum
{
    kSmallMssSegments     = 2051,
    kSmallMss             = 8,
    kSmallMssIpLength     = 40 + kSmallMssSegments * kSmallMss,
    kSmallMssRecordLength = 10 + kSmallMssIpLength
};

static void observeSmallMssThenOrdinary(tun_device_t *tdev, void *userdata, sbuf_t *buf, uint8_t wid)
{
    discard        tdev;
    discard        userdata;
    const uint8_t *ip = sbufGetRawPtr(buf);
    require(currentThreadIsEventWorkerWID(wid), "small-MSS output ran outside its flow worker");
    if (sbufGetLength(buf) == kGsoFixtureIpLength)
    {
        require(callback_count == kSmallMssSegments && ordinary_after_gso_deliveries == 0,
                "ordinary packet overtook a partially segmented aggregate");
        ordinary_after_gso_deliveries++;
    }
    else
    {
        require(callback_count < kSmallMssSegments && sbufGetLength(buf) == 40 + kSmallMss,
                "small-MSS output had an unexpected size or expansion count");
        require(GET_BE32(ip + 24) == 1000 + callback_count * kSmallMss && GET_BE16(ip + 4) == 0x1234 + callback_count,
                "small-MSS continuation lost TCP sequence or IP ID order");
        for (unsigned int i = 0; i < kSmallMss; ++i)
        {
            require(ip[40 + i] == (uint8_t) (callback_count * kSmallMss + i),
                    "small-MSS continuation lost aggregate payload bytes");
        }
        require((ip[33] & 0x19) == (callback_count + 1 == kSmallMssSegments ? 0x19 : 0x10),
                "small-MSS continuation moved FIN/PSH off the final segment");
        require(gsoSegmentChecksumsValid(ip, sbufGetLength(buf)),
                "small-MSS worker published an incomplete IP or TCP checksum");
        require(atomic_load_explicit(&gso_probe_session->output_packets, memory_order_acquire) >= 2 &&
                    atomic_load_explicit(&gso_probe_session->output_charge, memory_order_acquire) <=
                        gso_probe_session->output_charge_limit,
                "small-MSS worker lost aggregate/output reservations or exceeded charge limit");
        callback_count++;
    }
    bufferpoolReuseBuffer(getWorkerBufferPool(wid), buf);
}

static void testGsoSmallMssContinuationPreservesOrdinaryFifo(void)
{
    resetShutdownRequests();
    resetIoInjection();
    resetCapturedMessages();
    tun_device_t *tdev = createRunningOffloadReaderDevice(observeSmallMssThenOrdinary, true);
    uint8_t       aggregate[kSmallMssRecordLength];
    uint8_t       ordinary[kGsoFixtureRecordLength];
    makeSmallGsoRecord(ordinary);
    memoryZero(aggregate, sizeof(aggregate));
    memoryCopy(aggregate, ordinary, 50);
    aggregate[4] = kSmallMss;
    uint8_t *ip  = aggregate + 10;
    PUT_BE16(ip + 2, kSmallMssIpLength);
    PUT_BE16(ip + 10, 0);
    PUT_BE16(ip + 10, (uint16_t) ~gsoChecksumWords(ip, 20, 0));
    for (unsigned int i = 0; i < kSmallMssSegments * kSmallMss; ++i)
    {
        ip[40 + i] = (uint8_t) i;
    }
    memoryZero(ordinary, 10);
    const injected_io_result_t reads[] = {{.result = sizeof(aggregate), .bytes = aggregate},
                                          {.result = sizeof(ordinary), .bytes = ordinary},
                                          {.result = -1, .error = EIO}};
    armDeviceReads(reads, ARRAY_SIZE(reads));
    drive_worker_delivery         = true;
    verify_gso_aggregate_transfer = true;
    gso_deliver_after_read_calls  = 2;
    gso_probe_session             = tunLinuxReaderSession(tdev);
    callback_count                = 0;
    runReaderUntilIdle();
    require(callback_count == kSmallMssSegments && prepared_gso_segments == kSmallMssSegments &&
                ordinary_after_gso_deliveries == 1,
            "worker did not finish an aggregate above2048 segments followed by ordinary input");
    require(gso_messages_delivered >= (kSmallMssSegments + 255) / 256,
            "large aggregate did not yield bounded worker continuations");
    require(atomic_load_explicit(&gso_probe_session->output_charge, memory_order_acquire) == 0 &&
                atomic_load_explicit(&gso_probe_session->output_packets, memory_order_acquire) == 0,
            "small-MSS worker continuation leaked retained aggregate or output capacity");
    resetIoInjection();
    require(bringDownDevice(tdev), "small-MSS continuation device failed to stop");
    destroyDevice(tdev);
    resetCapturedMessages();
}

static void observeGsoByteQuantum(tun_device_t *tdev, void *userdata, sbuf_t *buf, uint8_t wid)
{
    discard            tdev;
    discard            userdata;
    const uint8_t     *ip        = sbufGetRawPtr(buf);
    const unsigned int offset    = (callback_count % 45) * 1460;
    const unsigned int remaining = 65535 - 40 - offset;
    const unsigned int payload   = min(remaining, 1460U);
    require(callback_count < 4 * 45 && sbufGetLength(buf) == 40 + payload && GET_BE32(ip + 24) == 1000 + offset &&
                gsoSegmentChecksumsValid(ip, sbufGetLength(buf)),
            "byte-quantum continuation lost packet geometry, order, or checksum");
    for (unsigned int i = 0; i < payload; ++i)
    {
        require(ip[40 + i] == (uint8_t) (offset + i), "byte-quantum continuation corrupted payload");
    }
    callback_count++;
    bufferpoolReuseBuffer(getWorkerBufferPool(wid), buf);
}

static void testGsoWorkerYieldsAtByteQuantum(void)
{
    resetShutdownRequests();
    resetIoInjection();
    resetCapturedMessages();
    tun_device_t *tdev = createRunningOffloadReaderDevice(observeGsoByteQuantum, true);
    uint8_t       record[10 + 65535];
    makeSmallGsoRecord(record);
    PUT_LE16(record + 4, 1460);
    uint8_t *ip = record + 10;
    PUT_BE16(ip + 2, 65535);
    PUT_BE16(ip + 10, 0);
    PUT_BE16(ip + 10, (uint16_t) ~gsoChecksumWords(ip, 20, 0));
    for (unsigned int i = 0; i < 65535 - 40; ++i)
    {
        ip[40 + i] = (uint8_t) i;
    }
    /* Four full-size records fit the packet quantum but their segmented output
     * exceeds 256 KiB. They also reach the native reader's byte quantum. */
    const injected_io_result_t reads[] = {{.result = sizeof(record), .bytes = record},
                                          {.result = sizeof(record), .bytes = record},
                                          {.result = sizeof(record), .bytes = record},
                                          {.result = sizeof(record), .bytes = record},
                                          {.result = -1, .error = EIO}};
    armDeviceReads(reads, ARRAY_SIZE(reads));
    drive_worker_delivery        = true;
    gso_deliver_after_read_calls = 4;
    gso_probe_session            = tunLinuxReaderSession(tdev);
    callback_count               = 0;
    inside_reader_callback       = true;
    reader_ready_callback(&reader_io);
    inside_reader_callback = false;
    require(observed_read_calls == 4 && callback_count == 0,
            "native reader failed to yield after reaching its byte quantum");
    runReaderUntilIdle();
    require(callback_count == 4 * 45 && prepared_gso_segments == 4 * 45 && gso_messages_delivered >= 2,
            "worker failed to yield repeated full-size aggregates at its byte quantum");
    require(atomic_load_explicit(&gso_probe_session->output_charge, memory_order_acquire) == 0 &&
                atomic_load_explicit(&gso_probe_session->output_packets, memory_order_acquire) == 0,
            "byte-quantum continuation leaked retained work");
    resetIoInjection();
    require(bringDownDevice(tdev), "byte-quantum device failed to stop");
    destroyDevice(tdev);
    resetCapturedMessages();
}

static size_t padding_growth_output_allowance;

static void observeGsoAfterPaddingGrowth(tun_device_t *tdev, void *userdata, sbuf_t *buf, uint8_t wid)
{
    require(sbufGetLeftCapacity(buf) >= 64, "later pool padding change removed original chain headroom");
    require(sbufGetAllocationCharge(buf) <= padding_growth_output_allowance,
            "later pool padding change exceeded prepaid output allocation allowance");
    buffer_pool_fit_t grown_fit;
    require(bufferpoolQueryBestFit(getWorkerBufferPool(wid), sbufGetLength(buf), 64, &grown_fit) &&
                grown_fit.allocation_charge > padding_growth_output_allowance,
            "padding-growth fixture did not exercise dedicated output fallback");
    observeGsoSegment(tdev, userdata, buf, wid);
}

static void testGsoWorkerPoolPaddingGrowth(test_env_t *env)
{
    resetShutdownRequests();
    resetIoInjection();
    resetCapturedMessages();
    master_pool_t *large  = masterpoolCreateWithCapacity(4);
    master_pool_t *medium = masterpoolCreateWithCapacity(4);
    master_pool_t *small  = masterpoolCreateWithCapacity(4);
    master_pool_t *splice = masterpoolCreateWithCapacity(4);
    buffer_pool_t *isolated =
        bufferpoolCreate(large, medium, small, 4, 8192, MEDIUM_BUFFER_SIZE_RAM_HIGH, 4096, 8192, 8192);
    bufferpoolUpdateAllocationPaddings(isolated, 64, 64, 64, 64);
    GSTATE.masterpool_buffer_pools_large  = large;
    GSTATE.masterpool_buffer_pools_medium = medium;
    GSTATE.masterpool_buffer_pools_small  = small;

    env->buffer_pools[0] = isolated;
    buffer_pool_fit_t initial_fit;
    require(bufferpoolQueryBestFit(isolated, 1500, 64, &initial_fit), "initial output allowance query failed");
    padding_growth_output_allowance = initial_fit.allocation_charge;
    tun_device_t *tdev              = createRunningOffloadReaderDevice(observeGsoAfterPaddingGrowth, true);
    /* No allocations have populated this isolated worker pool. A later chain
     * may increase its padding after the TUN cached its own output allowance. */
    bufferpoolUpdateAllocationPaddings(isolated, 8192, 8192, 8192, 8192);
    uint8_t record[kGsoFixtureRecordLength];
    makeSmallGsoRecord(record);
    const injected_io_result_t reads[] = {{.result = sizeof(record), .bytes = record}, {.result = -1, .error = EIO}};
    armDeviceReads(reads, ARRAY_SIZE(reads));
    drive_worker_delivery  = true;
    gso_probe_session      = tunLinuxReaderSession(tdev);
    callback_count         = 0;
    runReaderUntilIdle();
    require(callback_count == 3 && prepared_gso_segments == 3 &&
                atomic_load_explicit(&gso_probe_session->output_charge, memory_order_acquire) == 0 &&
                atomic_load_explicit(&gso_probe_session->output_packets, memory_order_acquire) == 0,
            "later pool padding change lost GSO output or leaked its reservation");
    resetIoInjection();
    require(bringDownDevice(tdev), "padding-growth device failed to stop");
    destroyDevice(tdev);
    env->buffer_pools[0]                  = env->worker_buffer_pool;
    GSTATE.masterpool_buffer_pools_large  = env->large_master;
    GSTATE.masterpool_buffer_pools_medium = env->medium_master;
    GSTATE.masterpool_buffer_pools_small  = env->small_master;

    bufferpoolDestroy(isolated);
    masterpoolMakeEmpty(large);
    masterpoolMakeEmpty(medium);
    masterpoolMakeEmpty(small);
    masterpoolMakeEmpty(splice);
    masterpoolDestroy(large);
    masterpoolDestroy(medium);
    masterpoolDestroy(small);
    masterpoolDestroy(splice);
    resetCapturedMessages();
}

static void testGsoWriterFramingAndPacketOutcomes(bool gso_requested)
{
    resetShutdownRequests();
    resetIoInjection();
    resetTunLogCapture();
    tun_device_t  *tdev      = createRunningOffloadReaderDevice(observeReadCallback, gso_requested);
    const uint16_t lengths[] = {1500, 64, 64, 64};
    for (unsigned int i = 0; i < ARRAY_SIZE(lengths); ++i)
    {
        sbuf_t *buf = bufferpoolGetSmallBuffer(getWorkerBufferPool(0));
        sbufSetLength(buf, lengths[i]);
        memorySet(sbufGetMutablePtr(buf), (int) ('a' + i), lengths[i]);
        require(queueWriterPacket(tdev, buf), "failed to queue a GSO-writer packet");
    }
    const injected_io_result_t writes[] = {{.result = -1, .error = EINTR},
                                           {.result = 1510},
                                           {.result = 73},
                                           {.result = -1, .error = EAGAIN},
                                           {.result = -1, .error = EIO}};
    armDeviceWrites(writes, ARRAY_SIZE(writes));

    runWriterMessages();

    require(observed_writev_calls == 5 && observed_write_calls == 0 && largest_writev_packet == 1500,
            "GSO writer did not frame, retry, and bound writes as packet operations");
    /* The shared limiter was already exercised by the checksum-only run. */
    if (! gso_requested)
        require(countTunLogSubstring("short device write") == 1,
                "offload writer did not diagnose its positive short packet write");
    require(shutdown_request_calls == 1 && tunLinuxLifecycleState(tdev) == kTunLifecycleFailed,
            "GSO writer did not end on a permanent descriptor error");
    resetIoInjection();
    require(bringDownDevice(tdev), "GSO writer did not bring down after terminal error");
    destroyDevice(tdev);
}

static void testTrustedWriterOutcomes(bool gso_requested)
{
    resetShutdownRequests();
    resetIoInjection();
    resetTunLogCapture();
    resetGsoSetup();
    resetReaderFixture(0);
    tun_device_t *tdev = tundeviceCreate(
        "ww-lifetime-test", gso_requested, true, 1500, NULL, observeReadCallback, kDeviceFragmentPreserve);
    require(tdev && tundeviceEnableTrustedChecksums(tdev) && bringUpDevice(tdev), "trusted writer setup");
    for (unsigned i = 0; i < 4; ++i)
    {
        uint8_t record[kGsoFixtureRecordLength];
        makeSmallGsoRecord(record);
        sbuf_t *buf = bufferpoolGetSmallBuffer(getWorkerBufferPool(0));
        memoryCopy(sbufGetMutablePtr(buf), record + 10, 43);
        sbufSetLength(buf, 43);
        require(queueWriterPacket(tdev, buf), "trusted writer queue");
    }
    const injected_io_result_t writes[] = {{.result = -1, .error = EINTR},
                                           {.result = 53},
                                           {.result = 52},
                                           {.result = -1, .error = EAGAIN},
                                           {.result = -1, .error = EIO}};
    armDeviceWrites(writes, ARRAY_SIZE(writes));
    expect_trusted_write = true;
    runWriterMessages();
    expect_trusted_write = false;
    /* The ordinary writer case already consumed the shared rate-limited log.
     * Five exact attempts prove retry and progress past short/transient writes. */
    require(observed_writev_calls == 5, "trusted short write/retry handling");
    require(shutdown_request_calls == 1, "trusted writer permanent-error settlement");
    resetIoInjection();
    require(bringDownDevice(tdev), "trusted writer shutdown");
    destroyDevice(tdev);
}

static void testTrustedRawWriterKeepsCompleteChecksums(void)
{
    resetShutdownRequests();
    resetIoInjection();
    resetGsoSetup();
    resetReaderFixture(0);
    tun_device_t *tdev =
        createRawDevice("ww-lifetime-test", false, 1500, NULL, observeReadCallback, kDeviceFragmentPreserve);
    require(tdev && tundeviceEnableTrustedReceiveChecksums(tdev), "trusted raw writer setup");
    require(! tundeviceEnableTrustedChecksums(tdev) && active_offload_mask == 0,
            "trusted raw writer enabled transmit offload");
    require(bringUpDevice(tdev), "trusted raw writer startup");
    uint8_t record[kGsoFixtureRecordLength];
    makeSmallGsoRecord(record);
    uint8_t       *ip   = record + kTunVirtioHeaderSize;
    const uint32_t seed = gsoChecksumWords(ip + 12, 8, 0) + 6U + kGsoFixtureIpLength - 20U;
    PUT_BE16(ip + 36, (uint16_t) ~gsoChecksumWords(ip + 20, kGsoFixtureIpLength - 20, seed));
    require(gsoSegmentChecksumsValid(ip, kGsoFixtureIpLength), "trusted raw writer checksum fixture");
    sbuf_t *buf = bufferpoolGetSmallBuffer(getWorkerBufferPool(0));
    memoryCopy(sbufGetMutablePtr(buf), ip, kGsoFixtureIpLength);
    sbufSetLength(buf, kGsoFixtureIpLength);
    require(queueWriterPacket(tdev, buf), "trusted raw writer queue");
    const injected_io_result_t writes[] = {{.result = kGsoFixtureIpLength}};
    armDeviceWrites(writes, ARRAY_SIZE(writes));
    expected_raw_write        = ip;
    expected_raw_write_length = kGsoFixtureIpLength;
    runWriterMessages();
    require(observed_write_calls == 1 && observed_writev_calls == 0 && shutdown_request_calls == 0,
            "trusted raw writer used offload framing or failed its write");
    resetIoInjection();
    require(bringDownDevice(tdev), "trusted raw writer shutdown");
    destroyDevice(tdev);
}

static void testWriterBatch(bool gso_requested, unsigned count, unsigned capacity, unsigned fault)
{
    resetShutdownRequests();
    resetIoInjection();
    resetGsoSetup();
    resetReaderFixture(0);
    tun_device_t *tdev = tundeviceCreate(
        "ww-lifetime-test", gso_requested, true, 1500, NULL, observeReadCallback, kDeviceFragmentPreserve);
    require(tdev && tundeviceEnableTrustedChecksums(tdev) && bringUpDevice(tdev), "batch writer setup");
    writer_batch_count  = count;
    writer_batch_offset = writer_batch_calls = writer_batch_aggregates = writer_batch_max = 0;
    writer_batch_fault                                                                    = fault;
    writer_batch_device                                                                   = tdev;
    memoryZero(writer_batch_settled, sizeof(writer_batch_settled));
    for (unsigned i = 0; i < count; ++i)
    {
        sbuf_t  *buf = sbufCreate(capacity);
        uint8_t *ip  = sbufGetMutablePtr(buf);
        memoryZero(ip, 140);
        ip[0]                   = 0x45;
        ip[3]                   = 140;
        ip[4]                   = (uint8_t) (i >> 8);
        ip[5]                   = (uint8_t) i;
        ip[8]                   = 64;
        ip[9]                   = 6;
        ip[12]                  = 10;
        ip[16]                  = 11;
        ip[20]                  = 10;
        ip[22]                  = 11;
        const uint32_t sequence = htonl(i * 100U);
        memoryCopy(ip + 24, &sequence, 4);
        ip[32]                  = 0x50;
        ip[33]                  = 0x10;
        const uint16_t checksum = calcGenericChecksum(ip, 20, 0);
        memoryCopy(ip + 10, &checksum, 2);
        memset(ip + 40, i, 100);
        sbufSetLength(buf, 140);
        writer_batch_buffers[i] = buf;
        require(queueWriterPacket(tdev, buf), "batch queue refused fixture");
    }
    writer_batch_probe = true;
    if (fault == 7)
        require(tundeviceRequestStop(tdev), "stop before deferred batch dispatch");
    runWriterMessages();
    require(bringDownDevice(tdev), "batch bring down");
    for (unsigned i = 0; i < count; ++i)
        require(writer_batch_settled[i] == 1, "batch or worker queue retained buffer after stop");
    writer_batch_probe = false;
    if (fault < 5)
        require(writer_batch_offset == count, "batch lost ordered output progress");
    if (fault == 2)
        require(writer_batch_aggregates == 1 && writer_batch_calls == count + 1,
                "unsupported GSO fallback replay/latch");
    if (capacity > 128 * 1024 && fault == 0)
        require(writer_batch_calls == count && writer_batch_aggregates == 0, "charge/lookahead limit");
    if (gso_requested && count == 130 && capacity == 140 && fault == 0)
        require(writer_batch_calls == 3 && writer_batch_max == 64, "count limit or write reduction");
    if (! gso_requested)
        require(writer_batch_calls == count && writer_batch_aggregates == 0,
                "checksum-only writer coalesced packets or emitted TSO metadata");
    if (fault == 5 || fault == 6 || fault == 8 || fault == 9)
        require(writer_batch_calls == 1, "writer continued after stop/permanent failure");
    if (fault == 7)
        require(writer_batch_calls == 0, "writer emitted after stop before dispatch");
    destroyDevice(tdev);
}

static void testTrustedQueueFallback(void)
{
    resetGsoSetup();
    resetReaderFixture(0);
    fail_worker_queue_once = true;
    tun_device_t *tdev     = tundeviceCreate("ww-lifetime-test", true, true, 1500, NULL, NULL, kDeviceFragmentPreserve);
    require(tdev && ! fail_worker_queue_once && ! tundeviceEnableTrustedChecksums(tdev),
            "queue fallback activated trust");
    require(gso_offload_calls == 2 && raw_setiff_calls == 1,
            "queue failure did not roll back successful offload ioctl");
    destroyDevice(tdev);
}

static void testGsoPendingAggregateSettlesAfterStop(void)
{
    resetShutdownRequests();
    resetIoInjection();
    resetCapturedMessages();
    tun_device_t            *tdev    = createRunningOffloadReaderDevice(observeGsoSegment, true);
    device_reader_session_t *session = tunLinuxReaderSession(tdev);
    session->output_packet_limit     = 2;
    uint8_t record[kGsoFixtureRecordLength];
    makeSmallGsoRecord(record);
    const injected_io_result_t reads[] = {{.result = kGsoFixtureRecordLength, .bytes = record},
                                          {.result = kGsoFixtureRecordLength, .bytes = record}};
    armDeviceReads(reads, ARRAY_SIZE(reads));
    drive_worker_delivery          = true;
    stop_when_receive_blocked      = true;
    gso_deliver_after_read_calls   = 2;
    gso_probe_session              = session;
    require(gso_scratch_buffer != NULL, "GSO receive worker did not allocate scratch storage");
    callback_count = 0;

    runReaderUntilIdle();

    require(observed_read_calls == 2 && callback_count == 0 && prepared_gso_segments == 0 &&
                captured_message_count == 1,
            "reader stop did not retain exactly one queued GSO output");
    require(gso_scratch_destroy_count == 0, "reader exit destroyed device-owned GSO scratch before restart");
    require(atomic_load_explicit(&session->output_packets, memory_order_acquire) == 2 &&
                atomic_load_explicit(&session->output_charge, memory_order_acquire) > 0,
            "reader exit prematurely settled a worker-owned GSO output");

    tracked_session            = session;
    tracked_message_pool       = session->message_pool;
    tracked_session_free_count = 0;
    tracked_pool_destroy_count = 0;
    require(bringDownDevice(tdev), "pending GSO reader did not bring down after exit");
    require(bringUpDevice(tdev), "GSO device did not restart with its retained scratch allocation");
    require(gso_scratch_destroy_count == 0, "GSO scratch was destroyed before the restarted device stopped");
    require(bringDownDevice(tdev), "restarted GSO device did not stop");
    destroyDevice(tdev);
    require(gso_scratch_destroy_count == 0, "device destroy released worker-owned aggregate storage");
    require(tracked_session_free_count == 0, "device destroyed a session with queued GSO output");
    cleanupMessage(0);
    require(gso_scratch_destroy_count == 1, "queued cancellation did not destroy its aggregate exactly once");
    require(tracked_session_free_count == 1 && tracked_pool_destroy_count == 1,
            "queued GSO output cancellation did not settle its session exactly once");
    tracked_session      = NULL;
    tracked_message_pool = NULL;
    resetIoInjection();
    resetCapturedMessages();
}

static void testDnsMutationCleanup(void)
{
    const char *servers[] = {"1.1.1.1"};
    for (unsigned int failure = 0; failure < 2; ++failure)
    {
        command_calls       = 0;
        command_outcomes[0] = failure == 0 ? 0 : 2;
        command_outcomes[1] = 1;
        command_outcomes[2] = 0;
        tun_device_t *tdev  = createRawDevice("ww-lifetime-test", false, 1500, NULL, NULL, kDeviceFragmentPreserve);
        require(tdev != NULL, "DNS fixture create");
        require(! tundeviceSetDnsServers(tdev, servers, 1) && tundeviceDnsNeedsCleanup(tdev),
                "partial/uncertain DNS mutation lost cleanup responsibility");
        if (failure == 0)
        {
            command_calls = 1; /* First revert fails, second succeeds. */
            require(! tundeviceClearDnsServers(tdev) && tundeviceDnsNeedsCleanup(tdev), "failed revert lost ownership");
            require(tundeviceClearDnsServers(tdev) && ! tundeviceDnsNeedsCleanup(tdev), "revert retry failed");
        }
        else
        {
            require(! tundeviceClearDnsServers(tdev) && command_calls == 1,
                    "uncertain DNS result triggered unsafe blanket revert");
        }
        destroyDevice(tdev);
    }
    existing_interface = true;
    command_calls      = 0;
    tun_device_t *tdev = createRawDevice("ww-lifetime-test", false, 1500, NULL, NULL, kDeviceFragmentPreserve);
    require(tdev != NULL, "existing interface fixture");
    require(! raw_attach_exclusive, "raw-IP attachment to an existing interface was lost");
    /* Attached DNS snapshot/restore behavior has its own real-configuration
     * fixture in tun_linux_dns_test.c. Creating an attachment itself is inert. */
    require(command_calls == 0, "attachment changed DNS before policy setup");
    destroyDevice(tdev);
    existing_interface = false;
}

static void observeSingleQueueWorkerOne(tun_device_t *tdev, void *userdata, sbuf_t *buf, uint8_t wid)
{
    discard tdev;
    require(wid == 1 && currentThreadIsEventWorkerWID(1), "single receive queue changed the flow's processing worker");
    require(sbufGetLength(buf) == 28 && memoryEqual(sbufGetRawPtr(buf), userdata, 28),
            "single receive queue changed packet bytes");
    ++callback_count;
    bufferpoolReuseBuffer(getWorkerBufferPool(wid), buf);
}

static void testMultiQueuePreferencePreservesProcessingWorkers(test_env_t *env)
{
    buffer_pool_t *second_pool   = bufferpoolCreate(env->large_master,
                                                  env->medium_master,
                                                  env->small_master,
                                                  16,
                                                  8192,
                                                  MEDIUM_BUFFER_SIZE_RAM_HIGH,
                                                  4096,
                                                  8192,
                                                  8192);
    wloop_t        second_loop   = {.wid = 1};
    buffer_pool_t *pools[2]      = {env->worker_buffer_pool, second_pool};
    wloop_t       *loops[2]      = {env->loops[0], &second_loop};
    GSTATE.workers_count         = 2;
    GSTATE.shortcut_buffer_pools = pools;
    GSTATE.shortcut_loops        = loops;
    GSTATE.workers[1] = (worker_t) {.wid = 1, .has_event_loop = true, .loop = &second_loop, .buffer_pool = second_pool};
    record_queue_preference = true;

    /* Exercise each path that opens/reopens the interface, with both explicit
     * preferences. Disabling multiqueue must survive every framing fallback. */
    for (unsigned preference = 0; preference < 2; ++preference)
    {
        const bool multi_queue_requested = preference != 0;
        for (unsigned scenario = 0; scenario < 9; ++scenario)
        {
            resetGsoSetup();
            resetReaderFixture(0);
            resetTunLogCapture();
            const bool gso_requested = scenario >= 2 && scenario != 7;
            gso_feature_available    = scenario != 0 && scenario != 7;
            if (scenario == 3)
                fail_gso_ioctl_request = TUNSETVNETHDRSZ;
            if (scenario == 4)
                fail_output_budget_once = true;
            if (scenario == 5 || scenario == 6)
            {
                fail_worker_gso_once = true;
                fail_offload_call    = 3;
            }
            if (scenario == 6)
                fail_feature_check = 2;
            existing_interface = scenario == 7;
            refuse_multi_queue = scenario == 8;

            tun_device_t *tdev = tundeviceCreate(
                "ww-lifetime-test", gso_requested, multi_queue_requested, 1500, NULL, NULL, kDeviceFragmentPreserve);
            require(tdev != NULL && getWorkersCount() == 2,
                    "queue preference failed construction or changed the processing worker count");
            const bool retain_offload = scenario == 1 || scenario == 2 || scenario == 5 || scenario == 8;
            require(tundeviceEnableTrustedChecksums(tdev) == retain_offload,
                    "queue preference changed offload negotiation");
            const unsigned expected_opens = scenario == 6 || scenario == 7                      ? 3U
                                            : scenario == 0 || (scenario >= 3 && scenario <= 5) ? 2U
                                                                                                : 1U;
            require(tun_open_calls == expected_opens, "queue preference did not exercise the intended reopen path");
            require(requested_tun_flag_count >= 1, "queue preference skipped interface attachment");
            unsigned multi_queue_attempts = 0;
            for (unsigned i = 0; i < requested_tun_flag_count; ++i)
            {
                if ((requested_tun_flags[i] & IFF_MULTI_QUEUE) != 0)
                    ++multi_queue_attempts;
                require(multi_queue_requested || (requested_tun_flags[i] & IFF_MULTI_QUEUE) == 0,
                        "disabled multiqueue was reenabled while reopening the interface");
            }
            require(! multi_queue_requested || multi_queue_attempts > 0,
                    "enabled multiqueue never requested the kernel flag with two workers");
            require(queue_flag_probes == (multi_queue_requested && ! existing_interface ? 1U : 0U),
                    "queue preference did not control optional multiqueue/steering setup");
            require(countTunLogSubstring("uses 1 worker-owned receive queue(s)") == 1,
                    "single-queue selection/fallback was not published");
            destroyDevice(tdev);
            existing_interface = false;
        }
    }

    resetGsoSetup();
    resetReaderFixture(0);
    resetIoInjection();
    resetShutdownRequests();
    resetCapturedMessages();
    gso_feature_available = false;
    uint8_t packet[28]    = {0x45, 0, 0, 28, 0, 1, 0, 0, 64, 17};
    PUT_BE32(packet + 12, UINT32_C(0x0A000001));
    PUT_BE32(packet + 16, UINT32_C(0x0A000002));
    PUT_BE16(packet + 22, 53);
    PUT_BE16(packet + 24, 8);
    wid_t processing_worker = 0;
    for (uint16_t port = 1; port < 1024; ++port)
    {
        PUT_BE16(packet + 20, port);
        require(deviceFlowAffineWID(packet, sizeof(packet), &processing_worker), "valid flow has no worker");
        if (processing_worker == 1)
            break;
    }
    require(processing_worker == 1, "fixture did not select a different processing worker");
    PUT_BE16(packet + 10, (uint16_t) ~gsoChecksumWords(packet, 20, 0));
    tun_device_t *tdev = tundeviceCreate(
        "ww-lifetime-test", false, false, 1500, packet, observeSingleQueueWorkerOne, kDeviceFragmentPreserve);
    require(tdev != NULL && queue_flag_probes == 0 && bringUpDevice(tdev), "disabled-multiqueue reader startup");
    require(requested_tun_flag_count == 1 && (requested_tun_flags[0] & IFF_MULTI_QUEUE) == 0,
            "disabled-multiqueue reader opened a multiqueue interface");
    const injected_io_result_t reads[] = {{.result = sizeof(packet), .bytes = packet}, {.result = -1, .error = EAGAIN}};
    armDeviceReads(reads, ARRAY_SIZE(reads));
    callback_count = 0;
    runReaderUntilIdle();
    require(captured_message_count == 1 && captured_messages[0].wid == 1 && callback_count == 0,
            "worker-zero receive did not queue the flow to worker one");
    testWorkerBindWID(1);
    deliverMessage(0, getCurrentEventWorker());
    testWorkerBindWID(0);
    require(callback_count == 1 && getWorkersCount() == 2 && tundeviceIsUp(tdev),
            "single-queue mode lost delivery or changed worker availability");
    resetIoInjection();
    require(bringDownDevice(tdev), "single-queue multiworker reader teardown");
    destroyDevice(tdev);
    resetCapturedMessages();

    record_queue_preference      = false;
    GSTATE.workers_count         = 1;
    GSTATE.shortcut_buffer_pools = env->buffer_pools;
    GSTATE.shortcut_loops        = env->loops;
    GSTATE.workers[1]            = (worker_t) {0};
    bufferpoolDestroy(second_pool);
}

static err_t recordTcpAck(struct netif *netif, struct pbuf *packet, const ip4_addr_t *destination)
{
    discard          destination;
    tcp_ack_probe_t *probe = netif->state;
    uint8_t          bytes[40];
    require(pbuf_copy_partial(packet, bytes, sizeof(bytes), 0) == sizeof(bytes) && bytes[9] == IP_PROTO_TCP,
            "TCP fixture output was not an IPv4 TCP packet");
    ++probe->outputs;
    probe->last_ack   = GET_BE32(bytes + 28);
    probe->last_flags = bytes[33];
    return ERR_OK;
}

static err_t initAckNetif(struct netif *netif)
{
    netif->name[0] = 'a';
    netif->name[1] = 'k';
    netif->mtu     = 1500;
    netif->output  = recordTcpAck;
    return ERR_OK;
}

static err_t receiveTcpData(void *argument, struct tcp_pcb *pcb, struct pbuf *packet, err_t error)
{
    tcp_ack_probe_t *probe = argument;
    require(pcb == probe->pcb && error == ERR_OK && packet != NULL, "TCP fixture received unexpected close/error");
    probe->received += packet->tot_len;
    tcp_recved(pcb, packet->tot_len);
    pbuf_free(packet);
    return ERR_OK;
}

static void buildTcpInput(tcp_ack_probe_t *probe, uint8_t *bytes, uint32_t sequence, uint8_t flags, uint16_t payload)
{
    uint8_t pseudo[32 + 1000] = {0};
    memoryZero(bytes, (size_t) 40 + payload);
    bytes[0]  = 0x45;
    bytes[8]  = 64;
    bytes[9]  = IP_PROTO_TCP;
    bytes[12] = bytes[16] = 10;
    bytes[15]             = 2;
    bytes[19]             = 1;
    PUT_BE16(bytes + 2, 40 + payload);
    PUT_BE16(bytes + 20, 80);
    PUT_BE16(bytes + 22, 1234);
    PUT_BE32(bytes + 24, sequence);
    PUT_BE32(bytes + 28, probe->peer_ack);
    bytes[32] = 0x50;
    bytes[33] = flags;
    PUT_BE16(bytes + 34, 65535);
    memset(bytes + 40, 0x5a, payload);
    memoryCopy(pseudo, bytes + 12, 8);
    pseudo[9] = IP_PROTO_TCP;
    PUT_BE16(pseudo + 10, 20 + payload);
    memoryCopy(pseudo + 12, bytes + 20, (size_t) 20 + payload);
    uint16_t checksum = (uint16_t) ~wwLwipChecksum(pseudo, 32 + payload);
    memoryCopy(bytes + 36, &checksum, sizeof(checksum));
    checksum = (uint16_t) ~wwLwipChecksum(bytes, 20);
    memoryCopy(bytes + 10, &checksum, sizeof(checksum));
}

static void deliverTcpInput(tun_device_t *device, void *userdata, sbuf_t *buf, uint8_t wid)
{
    discard           device;
    tcp_ack_probe_t  *probe = userdata;
    ww_lwip_engine_t *previous;
    if (wwLwipEngineJoinReceiveBatch(probe->engine))
        ++probe->batches;
    require(wwLwipEngineEnter(probe->engine, &previous), "TCP fixture input engine entry failed");
    struct pbuf *packet = pbuf_alloc(PBUF_RAW, (u16_t) sbufGetLength(buf), PBUF_RAM);
    require(packet != NULL && pbuf_take(packet, sbufGetRawPtr(buf), (u16_t) sbufGetLength(buf)) == ERR_OK,
            "TCP fixture could not copy its admitted input");
    require(wwLwipEngineInput(probe->engine, packet, &probe->netif) == ERR_OK, "TCP fixture rejected native TUN input");
    wwLwipEngineLeave(probe->engine, previous);
    bufferpoolReuseBuffer(getWorkerBufferPool(wid), buf);
}

static void readTcpBurst(void *context)
{
    discard context;
    runReaderUntilIdle();
}

static void testSameWorkerTunBurstCoalescesTcpAcks(test_env_t *env)
{
    /* Real constructor/read/FIFO paths plus real TCP input and cumulative ACKs.
     * Input joins the generic receive scope; no engine timers run. */
    resetCapturedMessages();
    resetIoInjection();
    resetReaderFixture(0);
    resetGsoSetup();
    wloop_t *saved_loop = env->loops[0];
    wloop_t *loop       = wloopCreate(0, env->worker_buffer_pool, 0);
    require(loop != NULL && globalstateInitializeSecureRandom() && frandGlobalInit() &&
                wCryptoGlobalInit() == kWCryptoOk,
            "TCP receive-burst fixture initialization failed");
    env->loops[0] = getCurrentEventWorker()->loop = loop;
    wwLwipInitializeProtocolState();
    wwLwipEngineSharedInit();
    tcp_ack_probe_t probe = {0};
    probe.engine          = wwLwipEngineCreate(0, loop);
    ww_lwip_engine_t *previous;
    require(probe.engine != NULL && wwLwipEngineEnter(probe.engine, &previous), "TCP fixture engine entry failed");
    ip4_addr_t address, mask, gateway;
    IP4_ADDR(&address, 10, 0, 0, 1);
    IP4_ADDR(&mask, 255, 255, 255, 0);
    ip4_addr_set_zero(&gateway);
    require(netif_add(&probe.netif, &address, &mask, &gateway, &probe, initAckNetif, ip_input) != NULL,
            "TCP fixture netif initialization failed");
    netif_set_up(&probe.netif);
    netif_set_link_up(&probe.netif);
    probe.pcb = tcp_new();
    require(probe.pcb != NULL && tcp_bind_netif(probe.pcb, &probe.netif) == ERR_OK &&
                tcp_bind(probe.pcb, IP_ADDR_ANY, 1234) == ERR_OK,
            "TCP fixture bind failed");
    tcp_arg(probe.pcb, &probe);
    tcp_recv(probe.pcb, receiveTcpData);
    ip_addr_t peer;
    IP_ADDR4(&peer, 10, 0, 0, 2);
    require(tcp_connect(probe.pcb, &peer, 80, NULL) == ERR_OK, "TCP fixture SYN failed");
    probe.peer_ack = probe.pcb->snd_nxt;
    wwLwipEngineLeave(probe.engine, previous);
    sbuf_t *syn_ack = sbufCreate(40);
    buildTcpInput(&probe, sbufGetMutablePtr(syn_ack), 100, TCP_SYN | TCP_ACK, 0);
    sbufSetLength(syn_ack, 40);
    deliverTcpInput(NULL, &probe, syn_ack, 0);
    require(wwLwipEngineEnter(probe.engine, &previous), "TCP fixture handshake entry failed");
    require(probe.pcb->state == ESTABLISHED, "TCP fixture handshake did not establish a connection");
    wwLwipEngineLeave(probe.engine, previous);
    probe.peer_next    = 101;
    probe.outputs      = 0;
    tun_device_t *tdev = createRawDevice("ww-ack-burst", false, 1500, &probe, deliverTcpInput, kDeviceFragmentPreserve);
    require(tdev != NULL && bringUpDevice(tdev), "TCP receive-burst TUN startup failed");
    uint8_t              packets[6][1040];
    injected_io_result_t reads[7] = {0};
    for (unsigned i = 0; i < ARRAY_SIZE(packets); ++i)
    {
        buildTcpInput(&probe, packets[i], probe.peer_next + i * 1000, TCP_ACK, 1000);
        reads[i] = (injected_io_result_t) {.result = sizeof(packets[i]), .bytes = packets[i]};
    }
    reads[6] = (injected_io_result_t) {.result = -1, .error = EAGAIN};
    armDeviceReads(reads, ARRAY_SIZE(reads));
    active_ack_probe = &probe;
    require(wloopInvokeNormalCallback(loop, readTcpBurst, NULL), "TCP native receive callback admission failed");
    require(captured_message_count == 0, "same-worker receive burst queued an avoidable FIFO notification");
    require(probe.received == 6000 && probe.outputs == 1 && probe.last_flags == TCP_ACK &&
                probe.last_ack == probe.peer_next + 6000 && probe.batches == 1,
            "completed native receive burst did not produce one cumulative TCP ACK before returning");
    require(atomicLoadRelaxed(&tunLinuxReaderSession(tdev)->output_packets) == 0,
            "TCP receive-burst fixture retained packet reservations");
    active_ack_probe = NULL;
    resetIoInjection();
    destroyDevice(tdev);
    resetCapturedMessages();
    require(wwLwipEngineEnter(probe.engine, &previous), "TCP fixture cleanup entry failed");
    tcp_abort(probe.pcb);
    netif_remove(&probe.netif);
    wwLwipEngineLeave(probe.engine, previous);
    wwLwipEngineDestroy(probe.engine);
    wwLwipEngineSharedCleanup();
    require(wwLwipShutdown(), "TCP fixture protocol state cleanup failed");
    wCryptoGlobalCleanup();
    frandThreadCleanup();
    frandGlobalCleanup();
    globalstateDestroySecureRandom();
    env->loops[0] = getCurrentEventWorker()->loop = saved_loop;
    wloopDestroy(&loop);
}

int main(void)
{
    testCaseSet("tun_linux_message_lifetime_test");
    test_env_t env;
    envSetup(&env);
    logger_t *logger = loggerCreate();
    require(logger != NULL, "failed to create TUN writer log-capture logger");
    loggerSetHandler(logger, captureTunLog);
    setInternalLogger(logger);
    checkSumInit();
    testSameWorkerTunBurstCoalescesTcpAcks(&env);
    testChecksumOnlyNegotiation();
    testDnsMutationCleanup();
    testGsoNegotiationAndRawFallback();
    testOffloadResourceFallbacks();
    testChecksumOnlyRejectsGso();
    testTrustedChecksumOnlyFallback();
    testTrustedRawWriterKeepsCompleteChecksums();
    testGsoReaderResumesPendingWithoutTunReadiness();
    for (unsigned mode = 0; mode < 2; ++mode)
    {
        const bool gso_requested = mode != 0;
        testOrdinaryChecksumWorkerHandoff(gso_requested, false, false);
        testOrdinaryChecksumWorkerHandoff(gso_requested, true, false);
        testOrdinaryChecksumWorkerHandoff(gso_requested, false, true);
        testOrdinaryChecksumMixedFifo(gso_requested);
        testOrdinaryChecksumBudget(gso_requested);
        testOrdinaryChecksumReaderFallback(gso_requested, true);
        testOrdinaryChecksumReaderFallback(gso_requested, false);
        testTrustedHandoff(gso_requested, false, false);
        testTrustedHandoff(gso_requested, true, false);
        testTrustedHandoff(gso_requested, false, true);
        testGsoWriterFramingAndPacketOutcomes(gso_requested);
        testTrustedWriterOutcomes(gso_requested);
    }
    testGsoWorkerSegmentationOwnsAggregate();
    testGsoSmallMssContinuationPreservesOrdinaryFifo();
    testGsoWorkerYieldsAtByteQuantum();
    testGsoWorkerPoolPaddingGrowth(&env);
    testWriterBatch(true, 1, 140, 0);
    testWriterBatch(true, 3, 140, 0);
    testWriterBatch(true, 130, 140, 0);
    testWriterBatch(true, 3, 140000, 0);
    testWriterBatch(true, 3, 300000, 0);
    testWriterBatch(true, 3, 140000, 5);
    for (unsigned fault = 1; fault <= 9; ++fault)
        testWriterBatch(true, 70, 140, fault);
    testWriterBatch(false, 3, 140, 0);
    testWriterBatch(false, 70, 140, 0);
    testTrustedQueueFallback();
    testGsoPendingAggregateSettlesAfterStop();
    testReaderFragmentPolicy(true, false, false);
    testReaderFragmentPolicy(false, false, false);
    testReaderFragmentPolicy(true, false, true);
    testReaderFragmentPolicy(true, true, true);
    testQueuedCleanupOutlivesDevice();
    testClosedAndStaleDeliveriesDoNotTouchDevice();
    testTunWriterRefusalClassesUseFreshTlsState();
    testBringUpRollsBackRejectedActivation();
    testWatcherFailureRequestsShutdown();
    testNormalStopDoesNotRequestShutdown();
    testPermanentIoErrorsReachTheShutdownWrapper();
    testHandoffFailureFallsBackToHardAbort(false);
    testHandoffFailureFallsBackToHardAbort(true);
    testInterfaceDownFailureRemainsRetryable();
    testPendingWriterMessagesAfterStop();
    testMultiQueuePreferencePreservesProcessingWorkers(&env);
    internaloggerDestroy();
    envTeardown(&env);
    puts("Linux TUN message lifetime tests passed");
    return 0;
}

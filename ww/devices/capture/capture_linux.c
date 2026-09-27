#include "capture_linux_checksum.h"
#include "capture_linux_internal.h"
#include "capture_private.h"
#include "devices/device_flow_affinity.h"
#include "devices/device_fragment_policy.h"
#include "devices/device_pool.h"
#include "generic_pool.h"
#include "global_state.h"
#include "loggers/internal_logger.h"
#include "worker.h"
#include "wproc.h"
#include "wtime.h"
#include <arpa/inet.h>
#include <fcntl.h>
#include <linux/filter.h>
#include <linux/if_ether.h>
#include <linux/ipv6.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_queue.h>
#include <linux/netfilter/xt_bpf.h>
#include <linux/netlink.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include "capture_linux_nfqueue.h"
#include "capture_linux_private.h"
#include "capture_linux_rules.h"

// -----------------------------------------------------------------------------
// Stop-pipe helpers
// -----------------------------------------------------------------------------
//
// The stop pipe lives for the whole lifetime of capture_device_t, so a wake
// token left behind by one BringDown would be consumed by the *next* BringUp's
// reader, which would then exit immediately while the device still reported
// success. Both lifecycle boundaries therefore enforce the same invariant: the
// pipe is empty. Both ends are nonblocking so neither draining nor a corrupted
// or unexpectedly full wake channel can block lifecycle teardown.

// Make one stop-pipe descriptor nonblocking while preserving its other flags.
bool capturedeviceMakeStopPipeNonblocking(int pipe_fd)
{
    int flags = fcntl(pipe_fd, F_GETFL, 0);
    if (flags < 0)
    {
        LOGE("CaptureDevice: failed to read stop pipe flags: %s", strerror(errno));
        return false;
    }
    if ((flags & O_NONBLOCK) != 0)
    {
        return true;
    }
    if (fcntl(pipe_fd, F_SETFL, flags | O_NONBLOCK) < 0)
    {
        LOGE("CaptureDevice: failed to set the stop pipe nonblocking: %s", strerror(errno));
        return false;
    }
    return true;
}

static bool capturedeviceRetryInterrupted(uint32_t *interruptions)
{
    *interruptions += 1U;
    if (*interruptions >= (uint32_t) kCaptureInterruptedRetryBudget)
    {
        errno = EINTR;
        return false;
    }
    return true;
}

// Read the stop pipe until it is empty. Never blocks: the read end is
// nonblocking, so EAGAIN/EWOULDBLOCK is the normal successful terminator. EOF
// means the write end is gone, which is a lifecycle failure rather than an empty
// pipe, and is reported as such.
bool capturedeviceDrainStopPipe(capture_device_t *cdev)
{
    uint32_t interruptions = 0;
    for (;;)
    {
        char    drain_buffer[64];
        ssize_t drained = read(cdev->linux_pipe_fds[0], drain_buffer, sizeof(drain_buffer));
        if (drained > 0)
        {
            continue;
        }
        if (drained == 0)
        {
            LOGE("CaptureDevice: stop pipe reported EOF while draining; its write end is gone");
            return false;
        }
        if (errno == EINTR)
        {
            if (! capturedeviceRetryInterrupted(&interruptions))
            {
                LOGE("CaptureDevice: stop-pipe drain exceeded its interrupted-syscall budget");
                return false;
            }
            continue;
        }
        if (errno == EAGAIN || errno == EWOULDBLOCK)
        {
            return true;
        }
        LOGE("CaptureDevice: failed to drain the stop pipe: %d (%s)", errno, strerror(errno));
        return false;
    }
}

// Write exactly one wake token so a reader blocked in poll() leaves its loop.
static bool capturedeviceWriteStopToken(capture_device_t *cdev)
{
    uint32_t interruptions = 0;
    for (;;)
    {
        ssize_t written = write(cdev->linux_pipe_fds[1], "x", 1);
        if (written == 1)
        {
            return true;
        }
        if (written < 0 && errno == EINTR)
        {
            if (! capturedeviceRetryInterrupted(&interruptions))
            {
                LOGE("CaptureDevice: stop-token delivery exceeded its interrupted-syscall budget");
                return false;
            }
            continue;
        }
        LOGE("CaptureDevice: failed to wake the reader through the stop pipe: wrote %zd, errno %d (%s)",
             written,
             errno,
             strerror(errno));
        return false;
    }
}

static void capturedeviceLogSocketBufferSize(int socket_fd, int option, const char *name)
{
    int       actual = 0;
    socklen_t len    = sizeof(actual);

    if (getsockopt(socket_fd, SOL_SOCKET, option, &actual, &len) != 0)
    {
        LOGW("CaptureDevice: failed to read actual %s: %s", name, strerror(errno));
        return;
    }

    LOGD("CaptureDevice: actual %s is %d bytes", name, actual);
}

static void capturedeviceDisableQueue(capture_device_t *cdev, const char *reason)
{
    pthread_mutex_lock(&cdev->reader_state_mutex);
    const bool was_restartable = cdev->queue_restartable;
    cdev->queue_restartable    = false;

    int  socket_fd = -1;
    bool deferred  = false;
    if (cdev->reader_thread_joinable && cdev->socket >= 0)
    {
        // The reader may still be using the numeric descriptor it copied
        // during its readiness handshake. Let its wrapper close the queue only
        // after the routine returns, so close()+FD reuse cannot redirect a
        // later poll/recvmsg/verdict to an unrelated object.
        cdev->close_queue_on_reader_exit = true;
        deferred                         = true;
    }
    else
    {
        socket_fd    = cdev->socket;
        cdev->socket = -1;
    }
    pthread_mutex_unlock(&cdev->reader_state_mutex);

    if (! was_restartable && socket_fd < 0 && ! deferred)
    {
        return;
    }
    if (deferred)
    {
        LOGW("CaptureDevice: queue %u will close when its reader exits after %s", cdev->queue_number, reason);
        return;
    }
    if (socket_fd >= 0 && close(socket_fd) != 0)
    {
        LOGE("CaptureDevice: failed to close NFQUEUE socket while making queue %u fail-open: %s",
             cdev->queue_number,
             strerror(errno));
    }

    LOGW("CaptureDevice: queue %u is closed and the device is non-restartable after %s", cdev->queue_number, reason);
}

static void captureDeliverPacket(void *device, sbuf_t *buf, wid_t wid)
{
    capture_device_t *cdev = device;
    cdev->read_event_callback(cdev, cdev->userdata, buf, wid);
}

bool captureLinuxReaderPublishReady(capture_device_t *cdev, int *reader_socket)
{
    if (cdev == NULL || reader_socket == NULL)
    {
        return false;
    }

    pthread_mutex_lock(&cdev->reader_state_mutex);
    const bool ready = ! cdev->reader_stop_requested &&
                       captureLifecycleIsActive(captureLifecycleLoad(&cdev->lifecycle)) &&
                       atomicLoadRelaxed(&cdev->running) && ! cdev->reader_failed && cdev->socket >= 0;
    if (ready)
    {
        *reader_socket     = cdev->socket;
        cdev->reader_ready = true;
        pthread_cond_broadcast(&cdev->reader_state_changed);
    }
    pthread_mutex_unlock(&cdev->reader_state_mutex);
    return ready;
}

static WTHREAD_ROUTINE(capturedeviceReaderThreadMain) // NOLINT
{
    assert(! currentThreadHasRegisteredWID());
    capture_device_t *cdev = userdata;
    discard           cdev->routine_reader(cdev);

    capture_lifecycle_state_t failed_from      = kCaptureLifecycleDown;
    bool                      lifecycle_failed = false;
    pthread_mutex_lock(&cdev->reader_state_mutex);
    /*
     * The mutex acquisition order decides whether Stop or reader exit won.
     * `running` is only a loop hint and cannot provide a "fresh" classification
     * of an exit racing the lifecycle owner.
     */
    const bool unexpected_exit = ! cdev->reader_stop_requested;
    cdev->reader_ready         = false;
    if (unexpected_exit)
    {
        lifecycle_failed                 = captureLifecycleTransitionToFailed(&cdev->lifecycle, &failed_from);
        cdev->reader_failed              = true;
        cdev->queue_restartable          = false;
        cdev->close_queue_on_reader_exit = cdev->socket >= 0;
        atomicStoreRelaxed(&cdev->capture_active, false);
        atomicStoreRelaxed(&cdev->up, false);
        atomicStoreRelaxed(&cdev->running, false);
    }

    const bool close_queue = cdev->close_queue_on_reader_exit;
    int        socket_fd   = -1;
    if (close_queue)
    {
        socket_fd                        = cdev->socket;
        cdev->socket                     = -1;
        cdev->close_queue_on_reader_exit = false;
    }

    // The routine has returned, so its copied descriptor is no longer in use.
    // Close before broadcasting failure/exit state to the lifecycle owner.
    if (socket_fd >= 0 && close(socket_fd) != 0)
    {
        LOGE("CaptureDevice: failed to close NFQUEUE socket after reader exit for queue %u: %s",
             cdev->queue_number,
             strerror(errno));
    }
    pthread_cond_broadcast(&cdev->reader_state_changed);
    pthread_mutex_unlock(&cdev->reader_state_mutex);

    if (close_queue)
    {
        LOGW("CaptureDevice: queue %u closed after its reader stopped using the descriptor", cdev->queue_number);
    }
    if (unexpected_exit)
    {
        LOGE("CaptureDevice: reader exited unexpectedly; queue %u was closed to make remaining rules fail-open",
             cdev->queue_number);
    }
    if (lifecycle_failed && failed_from == kCaptureLifecycleUp && ! requestProgramShutdown(1))
    {
        abortProgramNow(1);
    }
    return 0;
}

static void capturedeviceDeactivate(capture_device_t *cdev)
{
    // These atomics carry mode/status values only; the reader mutex owns the
    // reader lifecycle and descriptor publication.
    atomicStoreRelaxed(&cdev->capture_active, false);
    atomicStoreRelaxed(&cdev->up, false);
    deviceReaderSessionEnd(cdev->reader_session);
}

static bool capturedeviceStopReader(capture_device_t *cdev)
{
    captureLifecycleTransitionToStopping(&cdev->lifecycle);

    pthread_mutex_lock(&cdev->reader_state_mutex);
    cdev->reader_stop_requested = true;
    const bool      joinable    = cdev->reader_thread_joinable;
    const wthread_t thread      = cdev->read_thread;
    pthread_mutex_unlock(&cdev->reader_state_mutex);

    const bool was_running = atomicExchangeExplicit(&cdev->running, false, memory_order_relaxed);

    bool result = true;
    if (joinable)
    {
        if (was_running)
        {
            result = capturedeviceWriteStopToken(cdev);
        }

        // Safe to join even when the wake write above failed: the reader's poll
        // is bounded and re-checks `running`, so it leaves on its own.
        const bool joined = safeThreadJoin(thread);
        result            = joined && result;

        if (joined)
        {
            pthread_mutex_lock(&cdev->reader_state_mutex);
            cdev->reader_thread_joinable = false;
            cdev->reader_ready           = false;
            // Captured before the pending-close branch below can clear it, so the
            // drain runs on both paths: the queue socket is still open either way.
            const int drain_fd = cdev->socket;
            // Defensive fallback: every lifecycle-created reader runs through
            // the wrapper above, but after join it is safe for this owner to
            // finish any still-pending close without risking descriptor reuse.
            int socket_fd = -1;
            if (cdev->close_queue_on_reader_exit)
            {
                socket_fd                        = cdev->socket;
                cdev->socket                     = -1;
                cdev->close_queue_on_reader_exit = false;
            }
            pthread_mutex_unlock(&cdev->reader_state_mutex);

            // Close, join, retire: End poisons the fragment generation but
            // leaves its staged reader buffers alone, because the reader still
            // owned this pool. Only here does the lifecycle thread own it.
            bufferpoolResetThreadOwnership(cdev->reader_buffer_pool);
            deviceReaderSessionRetireGenerationBuffers(cdev->reader_session);

            // Must precede the close below: closing the queue socket makes the
            // kernel drop whatever is still enqueued.
            if (drain_fd >= 0)
            {
                const uint64_t teardown_deadline_us =
                    (uint64_t) getHRTimeUs() + (uint64_t) kNetfilterIoDeadlineMs * 1000U;
                const bool drain_ok = capturedeviceDrainResidualQueue(cdev, drain_fd, teardown_deadline_us);
                result              = drain_ok && result;
                if (! drain_ok)
                {
                    capturedeviceDisableQueue(cdev, "residual queue drain failure");
                }
            }

            if (socket_fd >= 0 && close(socket_fd) != 0)
            {
                LOGE("CaptureDevice: failed to close NFQUEUE socket after joining queue %u reader: %s",
                     cdev->queue_number,
                     strerror(errno));
            }
        }
        else
        {
            // The reader may still own both the queue descriptor and stop pipe.
            // Do not close, clear joinability, or drain anything until a later
            // teardown attempt successfully joins it.
            return false;
        }
    }

    // Only after joining does the lifecycle owner have exclusive pipe access.
    result = capturedeviceDrainStopPipe(cdev) && result;
    return result;
}

bool capturedeviceReaderOperational(capture_device_t *cdev)
{
    pthread_mutex_lock(&cdev->reader_state_mutex);
    const bool operational = captureLifecycleIsActive(captureLifecycleLoad(&cdev->lifecycle)) &&
                             cdev->reader_thread_joinable && cdev->reader_ready && ! cdev->reader_failed &&
                             ! cdev->reader_stop_requested && cdev->queue_restartable && cdev->socket >= 0 &&
                             atomicLoadRelaxed(&cdev->running);
    pthread_mutex_unlock(&cdev->reader_state_mutex);
    return operational;
}

static bool capturedeviceStartReader(capture_device_t *cdev)
{
    /*
     * Device bring-up/creation runs on an event worker even though the reader
     * and writer threads it manages stay unregistered. Read that worker's pool
     * geometry once here and copy it onto the device-owned pools; the auxiliary
     * threads never touch worker-local state themselves.
     */
    buffer_pool_t *worker_pool = getCurrentEventWorkerBufferPool();

    devicePoolUpdatePadding(cdev->reader_buffer_pool, worker_pool);

    capturedeviceDeactivate(cdev);
    pthread_mutex_lock(&cdev->reader_state_mutex);
    assert(! cdev->reader_thread_joinable);
    cdev->reader_ready               = false;
    cdev->reader_failed              = false;
    cdev->reader_stop_requested      = false;
    cdev->close_queue_on_reader_exit = false;
    pthread_mutex_unlock(&cdev->reader_state_mutex);

    if (deviceReaderSessionBegin(cdev->reader_session) == 0)
    {
        LOGE("CaptureDevice: failed to open reader delivery generation");
        return false;
    }
    atomicStoreRelaxed(&cdev->running, true);
    wthread_error_t error = threadCreate(&cdev->read_thread, capturedeviceReaderThreadMain, cdev);
    if (UNLIKELY(error != kWThreadErrorNone))
    {
        LOGE("CaptureDevice: failed to create reader thread: error %u (%s)", error, strerror((int) error));
        atomicStoreRelaxed(&cdev->running, false);
        capturedeviceDeactivate(cdev);
        return false;
    }

    pthread_mutex_lock(&cdev->reader_state_mutex);
    cdev->reader_thread_joinable      = true;
    const unsigned long long deadline = getTimeOfDayMS() + kCaptureReaderReadyTimeoutMs;
    while (! cdev->reader_ready && ! cdev->reader_failed)
    {
        const unsigned long long now = getTimeOfDayMS();
        if (now >= deadline)
        {
            break;
        }
        const unsigned long long remaining = deadline - now;
        const unsigned int wait_ms = remaining > (unsigned long long) UINT_MAX ? UINT_MAX : (unsigned int) remaining;
        discard            condvarWaitFor(&cdev->reader_state_changed, &cdev->reader_state_mutex, wait_ms);
    }
    const bool ready = cdev->reader_ready && ! cdev->reader_failed;
    if (! ready && ! cdev->reader_failed)
    {
        cdev->reader_failed = true;
    }
    pthread_mutex_unlock(&cdev->reader_state_mutex);

    if (! ready)
    {
        LOGE("CaptureDevice: reader failed or did not become ready within %u ms",
             (unsigned int) kCaptureReaderReadyTimeoutMs);
        capturedeviceDeactivate(cdev);
        discard capturedeviceStopReader(cdev);
        capturedeviceDisableQueue(cdev, "reader readiness failure");
        return false;
    }

    return true;
}

static bool capturedeviceActivate(capture_device_t *cdev)
{
    pthread_mutex_lock(&cdev->reader_state_mutex);
    const bool can_activate = cdev->reader_thread_joinable && cdev->reader_ready && ! cdev->reader_failed &&
                              ! cdev->reader_stop_requested && cdev->queue_restartable && cdev->socket >= 0 &&
                              atomicLoadRelaxed(&cdev->running) &&
                              captureLifecycleTransitionStartingToUp(&cdev->lifecycle);
    if (can_activate)
    {
        atomicStoreRelaxed(&cdev->up, true);
        atomicStoreRelaxed(&cdev->capture_active, true);
    }
    pthread_mutex_unlock(&cdev->reader_state_mutex);
    return can_activate;
}

static void capturedeviceRollbackStartup(capture_device_t *cdev)
{
    captureLifecycleTransitionToStopping(&cdev->lifecycle);
    capturedeviceDeactivate(cdev);
    const bool cleanup_complete = capturedeviceRemoveInstalledRules(cdev);
    if (! cleanup_complete)
    {
        LOGE("CaptureDevice: startup rollback left rules pending or unknown for %u capture ranges",
             capturedevicePendingRangeCount(cdev));
    }
    if (capturedevicePendingRangeCount(cdev) != 0)
    {
        // Request closure before stopping. The inactive reader keeps accepting
        // packets until it exits, then its wrapper closes the queue without any
        // close()+descriptor-reuse race.
        capturedeviceDisableQueue(cdev, "unresolved startup rollback");
    }
    const bool reader_stop_ok = capturedeviceStopReader(cdev);
    pthread_mutex_lock(&cdev->reader_state_mutex);
    const bool reader_joinable = cdev->reader_thread_joinable;
    pthread_mutex_unlock(&cdev->reader_state_mutex);
    if (! reader_stop_ok)
    {
        LOGE("CaptureDevice: reader shutdown during startup rollback was incomplete");
    }
    if (! reader_joinable)
    {
        captureLifecycleTransitionStoppingToDown(&cdev->lifecycle);
    }
}

bool capturedeviceIsUp(const capture_device_t *cdev)
{
    assert(cdev != NULL);
    return atomicLoadExplicit(&cdev->up, memory_order_relaxed);
}

bool caputredeviceBringUp(capture_device_t *cdev)
{
    capturedeviceDeactivate(cdev);

    // Pending rules while no reader is running must never keep targeting a bound
    // queue. Close first, retry cleanup, and refuse restart even if that retry
    // succeeds because the NFQUEUE socket cannot be safely reconstructed here.
    if (capturedevicePendingRangeCount(cdev) != 0)
    {
        capturedeviceDisableQueue(cdev, "pending cleanup at bring-up");
        if (! capturedeviceRemoveInstalledRules(cdev))
        {
            LOGE("CaptureDevice: refusing to bring up %s while rules for %u capture ranges remain pending or unknown",
                 cdev->name,
                 capturedevicePendingRangeCount(cdev));
            return false;
        }
    }

    pthread_mutex_lock(&cdev->reader_state_mutex);
    const bool restartable = cdev->queue_restartable && cdev->socket >= 0 && ! cdev->reader_thread_joinable;
    pthread_mutex_unlock(&cdev->reader_state_mutex);
    if (! restartable)
    {
        LOGE("CaptureDevice: refusing to bring up %s because its queue or reader lifecycle is not restartable",
             cdev->name);
        return false;
    }

    if (! capturedeviceDrainStopPipe(cdev))
    {
        LOGE("CaptureDevice: refusing to bring up %s because its stop pipe could not be drained", cdev->name);
        return false;
    }

    if (! captureLifecycleTransitionDownToStarting(&cdev->lifecycle))
    {
        LOGE("CaptureDevice: device cannot be started in current lifecycle state");
        return false;
    }

    if (! capturedeviceStartReader(cdev))
    {
        captureLifecycleTransitionToStopping(&cdev->lifecycle);
        pthread_mutex_lock(&cdev->reader_state_mutex);
        const bool reader_joinable = cdev->reader_thread_joinable;
        pthread_mutex_unlock(&cdev->reader_state_mutex);
        if (! reader_joinable)
        {
            captureLifecycleTransitionStoppingToDown(&cdev->lifecycle);
        }
        return false;
    }

    // When enabled, exempt incoming traffic only after its INPUT capture rules
    // and reader exist. Rollback removes every rule actually installed.
    if (! capturedeviceInstallRuleKind(cdev, false) ||
        (cdev->bypass_conntrack && ! capturedeviceInstallRuleKind(cdev, true)) || ! capturedeviceActivate(cdev))
    {
        capturedeviceRollbackStartup(cdev);
        return false;
    }

    assert(capturedevicePendingRangeCount(cdev) == cdev->capture_range_count);
    LOGI("CaptureDevice: device %s is now up", cdev->name);
    return true;
}

bool capturedeviceRequestStop(capture_device_t *cdev)
{
    captureLifecycleTransitionToStopping(&cdev->lifecycle);
    atomicStoreRelaxed(&cdev->capture_active, false);
    atomicStoreRelaxed(&cdev->up, false);
    deviceReaderSessionEndRequest(cdev->reader_session);
    return true;
}

bool caputredeviceBringDown(capture_device_t *cdev)
{
    captureLifecycleTransitionToStopping(&cdev->lifecycle);

    // From this point every newly received packet is accepted back to the host
    // stack while rules are removed. The raw writer may remain up until this
    // function returns.
    capturedeviceDeactivate(cdev);

    // Keep the reader consuming and accepting while iptables cleanup may block.
    bool result = capturedeviceRemoveInstalledRules(cdev);

    if (capturedevicePendingRangeCount(cdev) != 0)
    {
        // Request closure before stopping. The inactive reader keeps accepting
        // packets until its routine returns, then its wrapper closes the queue.
        capturedeviceDisableQueue(cdev, "incomplete rule cleanup during bring-down");
        result = false;
    }

    const bool reader_stop_ok = capturedeviceStopReader(cdev);
    result                    = reader_stop_ok && result;

    pthread_mutex_lock(&cdev->reader_state_mutex);
    const bool reader_joinable = cdev->reader_thread_joinable;
    pthread_mutex_unlock(&cdev->reader_state_mutex);
    if (! reader_joinable)
    {
        captureLifecycleTransitionStoppingToDown(&cdev->lifecycle);
        LOGI("CaptureDevice: device %s is now down", cdev->name);
    }

    return result;
}

capture_device_t *caputredeviceCreate(const char *name, const ipmask_t *capture_ranges, uint32_t capture_range_count,
                                      bool skip_sysctl, bool bypass_conntrack,
                                      const capture_protocol_filter_t *protocol_filter, void *userdata,
                                      CaptureReadEventHandle cb, device_fragment_policy_t fragment_policy)
{
    if (capture_ranges == NULL || capture_range_count == 0)
    {
        LOGE("CaptureDevice: no capture ranges configured");
        return NULL;
    }

    /* Best-effort kernel tuning; capture startup must continue if a sysctl fails. */
    capturedeviceApplySysctls(skip_sysctl);

    int socket_netfilter = socket(AF_NETLINK, SOCK_RAW, NETLINK_NETFILTER);
    if (socket_netfilter < 0)
    {
        LOGE("CaptureDevice: unable to create a netfilter socket");
        return NULL;
    }

    struct sockaddr_nl nl_addr;
    memoryZero(&nl_addr, sizeof(nl_addr));
    nl_addr.nl_family = AF_NETLINK;
    nl_addr.nl_pid    = 0;

    if (bind(socket_netfilter, (struct sockaddr *) &nl_addr, sizeof(nl_addr)) != 0)
    {
        LOGE("CaptureDevice: unable to bind netfilter socket to current process");
        close(socket_netfilter);
        return NULL;
    }

    int flags = fcntl(socket_netfilter, F_GETFL, 0);
    if (flags < 0)
    {
        const int saved_errno = errno;
        LOGE("CaptureDevice: failed to get NFQUEUE socket flags for O_NONBLOCK: %s", strerror(saved_errno));
        close(socket_netfilter);
        errno = saved_errno;
        return NULL;
    }
    if (fcntl(socket_netfilter, F_SETFL, flags | O_NONBLOCK) < 0)
    {
        const int saved_errno = errno;
        LOGE("CaptureDevice: failed to set O_NONBLOCK on NFQUEUE socket: %s", strerror(saved_errno));
        close(socket_netfilter);
        errno = saved_errno;
        return NULL;
    }

    // Best-effort: avoid ENOBUFS notifications waking us up.
    {
        int one = 1;
        if (setsockopt(socket_netfilter, SOL_NETLINK, NETLINK_NO_ENOBUFS, &one, sizeof(one)) < 0)
        {
            LOGW("CaptureDevice: failed to set NETLINK_NO_ENOBUFS: %s", strerror(errno));
        }
    }

    if (! netfilterSetConfig(socket_netfilter, NFQNL_CFG_CMD_PF_UNBIND, 0, PF_INET))
    {
        LOGE("CaptureDevice: unable to unbind netfilter from PF_INET");
        close(socket_netfilter);
        return NULL;
    }
    if (! netfilterSetConfig(socket_netfilter, NFQNL_CFG_CMD_PF_BIND, 0, PF_INET))
    {
        LOGE("CaptureDevice: unable to bind netfilter to PF_INET");
        close(socket_netfilter);
        return NULL;
    }
    uint16_t selected_queue_number = 0;
    if (! capturedeviceChooseQueueNumber(&selected_queue_number))
    {
        close(socket_netfilter);
        return NULL;
    }
    int queue_number = selected_queue_number;

    size_t capture_cidrs_size;
    if (! memoryTryComputeArraySize(capture_range_count, sizeof(char *), &capture_cidrs_size))
    {
        LOGE("CaptureDevice: capture range vector is too large");
        close(socket_netfilter);
        return NULL;
    }
    char **capture_cidrs = memoryAllocateZero(capture_cidrs_size);
    if (UNLIKELY(capture_cidrs == NULL))
    {
        LOGE("CaptureDevice: failed to allocate capture range vector");
        close(socket_netfilter);
        return NULL;
    }

    for (uint32_t i = 0; i < capture_range_count; ++i)
    {
        capture_cidrs[i] = capturedeviceFormatCidrString(&capture_ranges[i]);
        if (capture_cidrs[i] == NULL)
        {
            LOGE("CaptureDevice: failed to format capture range");
            close(socket_netfilter);
            capturedeviceFreeCidrs(capture_cidrs, capture_range_count);
            return NULL;
        }
    }

    if (! netfilterSetConfig(socket_netfilter, NFQNL_CFG_CMD_BIND, queue_number, 0))
    {
        LOGE("CaptureDevice: unable to bind netfilter to queue number %u", queue_number);
        close(socket_netfilter);
        capturedeviceFreeCidrs(capture_cidrs, capture_range_count);
        return NULL;
    }

    uint32_t range = kMaxAllowedPacketLength;
    if (! netfilterSetParams(socket_netfilter, queue_number, NFQNL_COPY_PACKET, range))
    {
        LOGE("CaptureDevice: unable to set netfilter into copy packet mode with maximum "
             "packet payload copy size %u",
             range);

        close(socket_netfilter);
        capturedeviceFreeCidrs(capture_cidrs, capture_range_count);
        return NULL;
    }
    if (! netfilterSetQueueLength(socket_netfilter, queue_number, kNetfilterQueueLen))
    {
        LOGE("CaptureDevice: unable to set netfilter queue maximum length to %u", kNetfilterQueueLen);

        close(socket_netfilter);
        capturedeviceFreeCidrs(capture_cidrs, capture_range_count);
        return NULL;
    }
    int rcvbuf_size = kNetfilterSocketRecvBuffer;
    if (setsockopt(socket_netfilter, SOL_SOCKET, SO_RCVBUF, &rcvbuf_size, sizeof(rcvbuf_size)) < 0)
    {
        LOGE("CaptureDevice: failed to set SO_RCVBUF: %s", strerror(errno));
        close(socket_netfilter);
        capturedeviceFreeCidrs(capture_cidrs, capture_range_count);
        return NULL;
    }
    capturedeviceLogSocketBufferSize(socket_netfilter, SO_RCVBUF, "SO_RCVBUF");

    /*
     * Device bring-up/creation runs on an event worker even though the reader
     * and writer threads it manages stay unregistered. Read that worker's pool
     * geometry once here and copy it onto the device-owned pools; the auxiliary
     * threads never touch worker-local state themselves.
     */
    buffer_pool_t *worker_pool = getCurrentEventWorkerBufferPool();

    buffer_pool_t *reader_bpool = devicePoolCreate(worker_pool, 0);
    if (UNLIKELY(reader_bpool == NULL))
    {
        LOGE("CaptureDevice: failed to construct reader buffer pool");
        close(socket_netfilter);
        capturedeviceFreeCidrs(capture_cidrs, capture_range_count);
        return NULL;
    }
    if (UNLIKELY(bufferpoolGetSmallBufferSize(reader_bpool) < kNetfilterReadBufferSize))
    {
        LOGE("CaptureDevice: Linux capture requires small buffers of at least %u bytes, configured size is %u",
             kNetfilterReadBufferSize,
             bufferpoolGetSmallBufferSize(reader_bpool));
        close(socket_netfilter);
        capturedeviceFreeCidrs(capture_cidrs, capture_range_count);
        bufferpoolDestroy(reader_bpool);
        return NULL;
    }

    uint64_t rule_token = fastRand64();

    size_t rule_states_size;
    if (! memoryTryComputeArraySize(capture_range_count, sizeof(capture_range_rule_states_t), &rule_states_size))
    {
        bufferpoolDestroy(reader_bpool);
        close(socket_netfilter);
        capturedeviceFreeCidrs(capture_cidrs, capture_range_count);
        return NULL;
    }
    capture_range_rule_states_t *rule_states = memoryAllocateZero(rule_states_size);
    capture_device_t     *cdev        = memoryAllocate(sizeof(capture_device_t));
    if (UNLIKELY(rule_states == NULL || cdev == NULL))
    {
        memoryFree(rule_states);
        memoryFree(cdev);
        bufferpoolDestroy(reader_bpool);
        close(socket_netfilter);
        capturedeviceFreeCidrs(capture_cidrs, capture_range_count);
        return NULL;
    }

    char *device_name = stringDuplicate(name);
    if (UNLIKELY(device_name == NULL))
    {
        memoryFree(rule_states);
        memoryFree(cdev);
        bufferpoolDestroy(reader_bpool);
        close(socket_netfilter);
        capturedeviceFreeCidrs(capture_cidrs, capture_range_count);
        return NULL;
    }

    *cdev = (capture_device_t) {.name                   = device_name,
                                .running                = false,
                                .up                     = false,
                                .routine_reader         = captureLinuxReadRoutine,
                                .socket                 = socket_netfilter,
                                .queue_number           = queue_number,
                                .read_event_callback    = cb,
                                .userdata               = userdata,
                                .reader_session         = NULL,
                                .netfilter_queue_number = queue_number,
                                .capture_cidrs          = capture_cidrs,
                                .capture_range_count    = capture_range_count,
                                .bypass_conntrack       = bypass_conntrack,
                                .rule_states            = rule_states,
                                .rule_token             = rule_token,
                                .queue_restartable      = true,
                                .reader_buffer_pool     = reader_bpool};
    captureLinuxBuildProtocolFilter(protocol_filter, cdev->protocol_filter);
    atomic_init(&cdev->lifecycle, kCaptureLifecycleDown);
    if (pthread_mutex_init(&cdev->reader_state_mutex, NULL) != 0)
    {
        LOGE("CaptureDevice: failed to initialize reader state mutex");
        memoryFree(cdev->name);
        capturedeviceFreeCidrs(cdev->capture_cidrs, cdev->capture_range_count);
        memoryFree(cdev->rule_states);
        bufferpoolDestroy(cdev->reader_buffer_pool);
        close(cdev->socket);
        memoryFree(cdev);
        return NULL;
    }
    if (pthread_cond_init(&cdev->reader_state_changed, NULL) != 0)
    {
        LOGE("CaptureDevice: failed to initialize reader state condition variable");
        pthread_mutex_destroy(&cdev->reader_state_mutex);
        memoryFree(cdev->name);
        capturedeviceFreeCidrs(cdev->capture_cidrs, cdev->capture_range_count);
        memoryFree(cdev->rule_states);
        bufferpoolDestroy(cdev->reader_buffer_pool);
        close(cdev->socket);
        memoryFree(cdev);
        return NULL;
    }
    if (pipe(cdev->linux_pipe_fds) != 0)
    {
        LOGE("CaptureDevice: failed to create pipe for linux_pipe_fds");
        pthread_cond_destroy(&cdev->reader_state_changed);
        pthread_mutex_destroy(&cdev->reader_state_mutex);
        memoryFree(cdev->name);
        capturedeviceFreeCidrs(cdev->capture_cidrs, cdev->capture_range_count);
        memoryFree(cdev->rule_states);
        bufferpoolDestroy(cdev->reader_buffer_pool);
        close(cdev->socket);
        memoryFree(cdev);
        return NULL;
    }

    // Both ends are nonblocking. The read side makes lifecycle draining safe;
    // the write side ensures wake delivery can fail observably instead of
    // blocking before the reader join. The reader also observes `running` on a
    // bounded poll, so one best-effort token is sufficient.
    if (! capturedeviceMakeStopPipeNonblocking(cdev->linux_pipe_fds[0]) ||
        ! capturedeviceMakeStopPipeNonblocking(cdev->linux_pipe_fds[1]))
    {
        close(cdev->linux_pipe_fds[0]);
        close(cdev->linux_pipe_fds[1]);
        pthread_cond_destroy(&cdev->reader_state_changed);
        pthread_mutex_destroy(&cdev->reader_state_mutex);
        memoryFree(cdev->name);
        capturedeviceFreeCidrs(cdev->capture_cidrs, cdev->capture_range_count);
        memoryFree(cdev->rule_states);
        bufferpoolDestroy(cdev->reader_buffer_pool);
        close(cdev->socket);
        memoryFree(cdev);
        return NULL;
    }

    cdev->reader_session = deviceReaderSessionCreate(
        RAM_PROFILE * 2, kMaxReadDistributeQueueSize, cdev, captureDeliverPacket, reader_bpool, fragment_policy);
    if (UNLIKELY(cdev->reader_session == NULL))
    {
        LOGE("CaptureDevice: failed to allocate reader session");
        close(cdev->linux_pipe_fds[0]);
        close(cdev->linux_pipe_fds[1]);
        pthread_cond_destroy(&cdev->reader_state_changed);
        pthread_mutex_destroy(&cdev->reader_state_mutex);
        memoryFree(cdev->name);
        capturedeviceFreeCidrs(cdev->capture_cidrs, cdev->capture_range_count);
        memoryFree(cdev->rule_states);
        bufferpoolDestroy(cdev->reader_buffer_pool);
        close(cdev->socket);
        memoryFree(cdev);
        return NULL;
    }

    /* Queue-number ownership is published only with the complete device. */
    GSTATE.capturedevice_queue_start_number = (uint16_t) ((uint32_t) selected_queue_number + 1U);

    return cdev;
}

void capturedeviceDestroy(capture_device_t *cdev)
{
    pthread_mutex_lock(&cdev->reader_state_mutex);
    const bool reader_joinable = cdev->reader_thread_joinable;
    pthread_mutex_unlock(&cdev->reader_state_mutex);
    deviceReaderSessionEnd(cdev->reader_session);
    if (captureLifecycleLoad(&cdev->lifecycle) != kCaptureLifecycleDown || atomicLoadRelaxed(&cdev->up) ||
        reader_joinable)
    {
        discard caputredeviceBringDown(cdev);
    }

    pthread_mutex_lock(&cdev->reader_state_mutex);
    const bool reader_still_joinable = cdev->reader_thread_joinable;
    pthread_mutex_unlock(&cdev->reader_state_mutex);
    if (reader_still_joinable)
    {
        LOGF("CaptureDevice: refusing to destroy device while reader ownership remains");
        abortProgramNow(1);
    }

    if (capturedevicePendingRangeCount(cdev) != 0)
    {
        // A down device has no reader. Close before the final cleanup attempt so
        // any still-installed NFQUEUE rule is fail-open throughout that bounded retry.
        capturedeviceDisableQueue(cdev, "pending cleanup during destruction");
        discard capturedeviceRemoveInstalledRules(cdev);
    }
    const uint32_t pending_range_count = capturedevicePendingRangeCount(cdev);
    if (pending_range_count != 0)
    {
        LOGE("CaptureDevice: closing queue %u with rules for %u capture ranges still pending or outcome-unknown; "
             "--queue-bypass covers remaining NFQUEUE rules only. Remaining WWCAP_NOTRACK rules must be removed "
             "from raw PREROUTING to restore tracking",
             cdev->queue_number,
             pending_range_count);
    }

    pthread_mutex_lock(&cdev->reader_state_mutex);
    const int socket_fd = cdev->socket;
    cdev->socket        = -1;
    pthread_mutex_unlock(&cdev->reader_state_mutex);
    if (socket_fd >= 0)
    {
        close(socket_fd);
    }
    memoryFree(cdev->name);
    capturedeviceFreeCidrs(cdev->capture_cidrs, cdev->capture_range_count);
    memoryFree(cdev->rule_states);
    deviceReaderSessionRetireProducerBuffers(cdev->reader_session);
    bufferpoolDestroy(cdev->reader_buffer_pool);
    deviceReaderSessionUnref(cdev->reader_session);
    close(cdev->linux_pipe_fds[0]);
    close(cdev->linux_pipe_fds[1]);
    pthread_cond_destroy(&cdev->reader_state_changed);
    pthread_mutex_destroy(&cdev->reader_state_mutex);
    memoryFree(cdev);
}

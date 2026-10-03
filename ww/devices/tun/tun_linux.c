#include "devices/device_flow_affinity.h"
#include "devices/device_pool.h"
#include "devices/device_reader_session.h"
#include "devices/device_writer_channel.h"
#include "devices/tun/tun_io_error.h"
#include "devices/tun/tun_lifecycle.h"
#ifdef OS_LINUX
#include "devices/tun/tun_linux_gso_limits.h"
#include "devices/tun/tun_linux_offload.h"
#endif
#include "generic_pool.h"
#include "global_state.h"
#include "loggers/internal_logger.h"
#include "loggers/log_rate_limiter.h"
#include "tun.h"
#include "tun_linux_internal.h"
#include "watomic.h"
#include "wchan.h"
#include "wplatform.h"
#include "wproc.h"
#include "wthread.h"
#include "wtime.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <net/if.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <poll.h>
#include <sys/ioctl.h>

#ifdef OS_LINUX
#include <linux/if.h>
#include <linux/if_tun.h>
#include <linux/ipv6.h>
#elif defined(OS_BSD)
#include <net/if.h>
#include <net/if_tun.h>
#else
#error "Unsupported OS"
#endif

#include "tun_linux_private.h"

#ifdef OS_LINUX
bool tundeviceEnableTrustedChecksums(tun_device_t *tdev)
{
    assert(tdev != NULL && tunLifecycleLoad(&tdev->lifecycle) == kTunLifecycleDown);
    assert(! tdev->reader_joinable && ! tdev->writer_joinable);
    if (! tdev->checksum_offload_enabled)
    {
        return false;
    }
    assert(tdev->offload_scratch != NULL && tdev->reader_session->worker_queues != NULL);
    assert(deviceReaderSessionOutputWakeFd(tdev->reader_session) >= 0);
    deviceFragAffinityTrustIpv4HeaderChecksum(tdev->reader_session->frag_affinity);
    tdev->trusted_checksums = true;
    return true;
}
#endif

bool tundeviceIsUp(const tun_device_t *tdev)
{
    return tdev != NULL && tunLifecycleLoad(&tdev->lifecycle) == kTunLifecycleUp;
}

static bool tunSetNonBlocking(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0)
    {
        LOGW("TunDevice: failed to get fd flags for O_NONBLOCK: %s", strerror(errno));
        return false;
    }

    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0)
    {
        LOGW("TunDevice: failed to set O_NONBLOCK: %s", strerror(errno));
        return false;
    }

    return true;
}

static bool tunSetCloseOnExec(int fd)
{
    int flags = fcntl(fd, F_GETFD, 0);
    return flags >= 0 && fcntl(fd, F_SETFD, flags | FD_CLOEXEC) == 0;
}

static bool tunCreateStopPipe(int fds[2])
{
#if defined(OS_LINUX)
    if (pipe2(fds, O_NONBLOCK | O_CLOEXEC) == 0)
    {
        return true;
    }
    if (errno != ENOSYS && errno != EINVAL)
    {
        return false;
    }
#endif
    if (pipe(fds) != 0)
    {
        return false;
    }
    if (tunSetNonBlocking(fds[0]) && tunSetNonBlocking(fds[1]) && tunSetCloseOnExec(fds[0]) &&
        tunSetCloseOnExec(fds[1]))
    {
        return true;
    }
    discard close(fds[0]);
    discard close(fds[1]);
    fds[0] = -1;
    fds[1] = -1;
    return false;
}

bool tundeviceGetLuid(tun_device_t *tdev, uint64_t *out)
{
    discard tdev;
    *out = 0;
    return false;
}

static void tundeviceCloseLifetimeGates(tun_device_t *tdev)
{
    deviceWriterChannelClose(&tdev->writer_channel);
    deviceReaderSessionEndRequest(tdev->reader_session);
}

static void tundeviceRetireReaderGeneration(tun_device_t *tdev)
{
    if (! tdev->reader_generation_open)
    {
        return;
    }
    bufferpoolResetThreadOwnership(tdev->reader_buffer_pool);
    deviceReaderSessionRetireGenerationBuffers(tdev->reader_session);
    tdev->reader_generation_open = false;
}

static bool tundeviceSignalReaderStop(tun_device_t *tdev)
{
    if (! tdev->reader_joinable)
    {
        return true;
    }

    ssize_t write_res;
    do
    {
        write_res = write(tdev->linux_pipe_fds[1], "x", 1);
    } while (write_res < 0 && errno == EINTR);

    return write_res == 1 || (write_res < 0 && (errno == EAGAIN || errno == EWOULDBLOCK));
}

static void tundeviceDrainStopPipe(tun_device_t *tdev)
{
    struct pollfd fd = {.fd = tdev->linux_pipe_fds[0], .events = POLLIN};

    for (;;)
    {
        int ret = poll(&fd, 1, 0);
        if (ret < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }
            LOGW("TunDevice: failed to poll stop pipe while draining: %s", strerror(errno));
            return;
        }

        if (ret == 0 || ! (fd.revents & POLLIN))
        {
            return;
        }

        char    buf[64];
        ssize_t read_res = read(tdev->linux_pipe_fds[0], buf, sizeof(buf));
        if (read_res < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }
            LOGW("TunDevice: failed to drain stop pipe: %s", strerror(errno));
            return;
        }

        if (read_res == 0)
        {
            return;
        }
    }
}

// Unassign IP address from TUN device
/*
 * Single place where an unexpected TUN I/O thread exit becomes process policy.
 * Keep this behaviorally identical to the tun_darwin.c and tun_windows.c copies.
 *
 * A device I/O routine that returns while the lifecycle is STARTING or UP was
 * not asked to stop: it hit a real error (poll failure, EOF, an unrecoverable
 * write). Such exits used to leave the device published as healthy while reads
 * had silently stopped and writes piled into a channel nobody drains.
 *
 * The routine has already returned, so it has released or transferred every
 * buffer it owned, and this wrapper owns no locks. That is what makes it the
 * correct point to request shutdown: requestProgramShutdown() returns, the
 * wrapper returns, and worker 0 is then free to join this thread.
 *
 * Deliberately NOT done here: closing channels, waking the peer,
 * tundeviceBringDown(), pre-down scripts, route/DNS restoration, or joining
 * threads. A device thread that did any of those would eventually join itself.
 * The lifecycle coordinator reaches all of it through the quiesce/wait hooks.
 */
static void tundeviceNoteUnexpectedThreadExit(tun_device_t *tdev, const char *which)
{
    tun_lifecycle_state_t failed_from;
    if (! tunLifecycleTransitionToFailed(&tdev->lifecycle, &failed_from))
    {
        // Either normal teardown already moved the device to STOPPING (this
        // routine returned because it was asked to), or the peer thread already
        // published the failure. Neither case logs or requests again.
        return;
    }

    LOGE("TunDevice: %s thread for device %s exited unexpectedly; the device is no longer usable", which, tdev->name);

    /*
     * STARTING -> FAILED is a startup failure: tundeviceBringUp() observes the
     * failed publication, rolls back what it owns and returns false, and the
     * main-thread TunDevice::onStart path decides what happens next. Requesting
     * shutdown from here would race that synchronous rollback.
     *
     * UP -> FAILED is an already published device losing a required I/O thread
     * at runtime. The packet chain cannot continue correctly, so this is
     * process-fatal: request the orderly, worker-0-owned shutdown.
     */
    if (failed_from == kTunLifecycleUp && ! requestProgramShutdown(1))
    {
        abortProgramNow(1);
    }
}

static WTHREAD_ROUTINE(tundeviceReaderThreadMain) // NOLINT
{
    assert(! currentThreadHasRegisteredWID());
    tun_device_t *tdev = userdata;
    discard       tdev->routine_reader(tdev);
    tundeviceNoteUnexpectedThreadExit(tdev, "reader");
    return 0;
}

static WTHREAD_ROUTINE(tundeviceWriterThreadMain) // NOLINT
{
    assert(! currentThreadHasRegisteredWID());
    tun_device_t *tdev = userdata;
    discard       tdev->routine_writer(tdev);
    tundeviceNoteUnexpectedThreadExit(tdev, "writer");
    return 0;
}

// Bring TUN device up
bool tundeviceBringUp(tun_device_t *tdev)
{
    if (! tunLifecycleTransitionDownToStarting(&tdev->lifecycle))
    {
        LOGE("TunDevice: device cannot be started in current lifecycle state");
        return false;
    }

    /*
     * Device bring-up/creation runs on an event worker even though the reader
     * and writer threads it manages stay unregistered. Read that worker's pool
     * geometry once here and copy it onto the device-owned pools; the auxiliary
     * threads never touch worker-local state themselves.
     */
    buffer_pool_t *worker_pool = getCurrentEventWorkerBufferPool();

    devicePoolUpdatePadding(tdev->reader_buffer_pool, worker_pool);

    devicePoolUpdatePadding(tdev->writer_buffer_pool, worker_pool);

    if (! deviceWriterChannelOpen(&tdev->writer_channel, kTunWriteChannelQueueMax))
    {
        LOGE("TunDevice: failed to open writer channel");
        tunLifecycleTransitionStoppingToDown(&tdev->lifecycle);
        return false;
    }
    if (deviceReaderSessionBegin(tdev->reader_session) == 0)
    {
        LOGE("TunDevice: failed to open reader delivery generation");
        deviceWriterChannelClose(&tdev->writer_channel);
        discard deviceWriterChannelRetireCurrent(&tdev->writer_channel);
        tunLifecycleTransitionStoppingToDown(&tdev->lifecycle);
        return false;
    }
    tdev->reader_generation_open = true;

    if (! tunSetStateByName(tdev->name, true))
    {
        LOGE("TunDevice: error bringing device %s up", tdev->name);
        tundeviceCloseLifetimeGates(tdev);
        deviceReaderSessionEndWait(tdev->reader_session);
        tundeviceRetireReaderGeneration(tdev);
        discard deviceWriterChannelRetireCurrent(&tdev->writer_channel);
        tunLifecycleTransitionStoppingToDown(&tdev->lifecycle);
        return false;
    }

    if (tdev->read_event_callback != NULL)
    {
        tundeviceDrainStopPipe(tdev);
        wthread_error_t error = threadCreate(&tdev->read_thread, tundeviceReaderThreadMain, tdev);
        if (UNLIKELY(error != kWThreadErrorNone))
        {
            LOGE("TunDevice: failed to create reader thread: error %u (%s)", error, strerror((int) error));
            goto rollback;
        }
        tdev->reader_joinable = true;

        if (tunLifecycleLoad(&tdev->lifecycle) == kTunLifecycleFailed)
        {
            goto rollback;
        }
    }

    wthread_error_t error = threadCreate(&tdev->write_thread, tundeviceWriterThreadMain, tdev);
    if (UNLIKELY(error != kWThreadErrorNone))
    {
        LOGE("TunDevice: failed to create writer thread: error %u (%s)", error, strerror((int) error));
        goto rollback;
    }

    tdev->writer_joinable = true;

    if (! tunLifecycleTransitionStartingToUp(&tdev->lifecycle))
    {
        LOGE("TunDevice: an I/O thread failed during startup");
        goto rollback;
    }

    LOGI("TunDevice: device %s is now up", tdev->name);
    return true;

rollback:
    tunLifecycleTransitionToStopping(&tdev->lifecycle);
    tundeviceCloseLifetimeGates(tdev);
    discard tundeviceSignalReaderStop(tdev);
    deviceReaderSessionEndWait(tdev->reader_session);

    bool rollback_ok = tunSetStateByName(tdev->name, false);
    if (! rollback_ok)
    {
        LOGE("TunDevice: error restoring %s down after startup failure", tdev->name);
    }

    if (tdev->reader_joinable)
    {
        if (safeThreadJoin(tdev->read_thread))
        {
            tundeviceDrainStopPipe(tdev);
            tdev->reader_joinable = false;
        }
        else
        {
            LOGE("TunDevice: failed to join reader during startup rollback");
            rollback_ok = false;
        }
    }
    if (! tdev->reader_joinable)
    {
        tundeviceRetireReaderGeneration(tdev);
    }
    if (tdev->writer_joinable)
    {
        if (safeThreadJoin(tdev->write_thread))
        {
            tdev->writer_joinable = false;
            bufferpoolResetThreadOwnership(tdev->writer_buffer_pool);
        }
        else
        {
            LOGE("TunDevice: failed to join writer during startup rollback");
            rollback_ok = false;
        }
    }

    if (! tdev->reader_joinable && ! tdev->writer_joinable && ! deviceWriterChannelRetireCurrent(&tdev->writer_channel))
    {
        rollback_ok = false;
    }

    if (rollback_ok)
    {
        tunLifecycleTransitionStoppingToDown(&tdev->lifecycle);
    }
    return false;
}

bool tundeviceRequestStop(tun_device_t *tdev)
{
    tunLifecycleTransitionToStopping(&tdev->lifecycle);
    tundeviceCloseLifetimeGates(tdev);

    return tundeviceSignalReaderStop(tdev);
}

// Bring TUN device down
bool tundeviceBringDown(tun_device_t *tdev)
{
    // A previous interface-down failure retains STOPPING after the threads and
    // channel have been released. Keep retrying until that last owned operation
    // succeeds and DOWN can be published.
    if (tunLifecycleLoad(&tdev->lifecycle) == kTunLifecycleDown && ! tdev->reader_joinable && ! tdev->writer_joinable &&
        ! deviceWriterChannelHasCurrent(&tdev->writer_channel))
    {
        return true;
    }

    bool bring_down_ok = tundeviceRequestStop(tdev);
    deviceReaderSessionEndWait(tdev->reader_session);

    if (! tunSetStateByName(tdev->name, false))
    {
        LOGE("TunDevice: error bringing %s down", tdev->name);
        bring_down_ok = false;
    }
    else
    {
        LOGI("TunDevice: device %s is now down", tdev->name);
    }

    if (tdev->reader_joinable)
    {
        if (safeThreadJoin(tdev->read_thread))
        {
            tundeviceDrainStopPipe(tdev);
            tdev->reader_joinable = false;
        }
        else
        {
            LOGE("TunDevice: failed to join reader thread; retaining reader resources");
            bring_down_ok = false;
        }
    }
    if (! tdev->reader_joinable)
    {
        tundeviceRetireReaderGeneration(tdev);
    }
    if (tdev->writer_joinable)
    {
        if (safeThreadJoin(tdev->write_thread))
        {
            tdev->writer_joinable = false;
            bufferpoolResetThreadOwnership(tdev->writer_buffer_pool);
        }
        else
        {
            LOGE("TunDevice: failed to join writer thread; retaining writer resources");
            bring_down_ok = false;
        }
    }

    if (! tdev->reader_joinable && ! tdev->writer_joinable && ! deviceWriterChannelRetireCurrent(&tdev->writer_channel))
    {
        bring_down_ok = false;
    }

    if (bring_down_ok)
    {
        tunLifecycleTransitionStoppingToDown(&tdev->lifecycle);
    }

    return bring_down_ok;
}

#ifdef OS_LINUX
typedef enum tun_linux_open_result_e
{
    kTunLinuxOpenOk = 0,
    kTunLinuxOpenOffloadUnavailable,
    kTunLinuxOpenNameConflict,
    kTunLinuxOpenFailure
} tun_linux_open_result_t;

static tun_linux_open_result_t tunLinuxCapabilityFailure(int error)
{
    return error == EINVAL || error == EOPNOTSUPP || error == ENOTTY || error == ENOSYS
               ? kTunLinuxOpenOffloadUnavailable
               : kTunLinuxOpenFailure;
}

static tun_linux_open_result_t tunLinuxOpenAttempt(const char *name, bool checksum_setup, bool gso_requested,
                                                   bool exclusive, uint16_t mtu, int *out_fd, struct ifreq *out_ifr,
                                                   bool *out_gso_enabled, const char **out_reason, int *out_errno)
{
    assert(! gso_requested || checksum_setup);
    *out_gso_enabled = false;
    int fd = open("/dev/net/tun", O_RDWR);
    if (fd < 0)
    {
        *out_reason = "opening /dev/net/tun";
        *out_errno  = errno;
        return kTunLinuxOpenFailure;
    }

    if (checksum_setup)
    {
        unsigned int features       = 0;
        const int    feature_result = ioctl(fd, TUNGETFEATURES, &features);
        if (feature_result < 0 || (features & IFF_VNET_HDR) == 0)
        {
            *out_reason = "IFF_VNET_HDR capability check";
            *out_errno  = feature_result < 0 ? errno : EOPNOTSUPP;
            close(fd);
            return tunLinuxCapabilityFailure(*out_errno);
        }
    }

    struct ifreq ifr;
    memoryZero(&ifr, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI | (checksum_setup ? IFF_VNET_HDR : 0) | (exclusive ? IFF_TUN_EXCL : 0);
    if (*name)
    {
        stringCopyN(ifr.ifr_name, name, IFNAMSIZ);
        ifr.ifr_name[IFNAMSIZ - 1] = '\0';
    }

    if (ioctl(fd, TUNSETIFF, (void *) &ifr) < 0)
    {
        const int saved_errno = errno;
        *out_reason           = "TUNSETIFF";
        *out_errno            = saved_errno;
        close(fd);
        if (saved_errno == EBUSY || saved_errno == EEXIST)
        {
            return kTunLinuxOpenNameConflict;
        }
        return checksum_setup ? tunLinuxCapabilityFailure(saved_errno) : kTunLinuxOpenFailure;
    }

    if (checksum_setup)
    {
        int header_size   = kTunVirtioHeaderSize;
        int little_endian = 1;
        if (ioctl(fd, TUNSETVNETHDRSZ, &header_size) < 0)
        {
            *out_reason = "TUNSETVNETHDRSZ";
            *out_errno  = errno;
            close(fd);
            return tunLinuxCapabilityFailure(*out_errno);
        }
        if (ioctl(fd, TUNSETVNETLE, &little_endian) < 0)
        {
            *out_reason = "TUNSETVNETLE";
            *out_errno  = errno;
            close(fd);
            return tunLinuxCapabilityFailure(*out_errno);
        }
        if (ioctl(fd, TUNSETOFFLOAD, (unsigned long) TUN_F_CSUM) < 0)
        {
            *out_reason = "TUNSETOFFLOAD(CSUM)";
            *out_errno  = errno;
            close(fd);
            return tunLinuxCapabilityFailure(*out_errno);
        }
        if (gso_requested)
        {
            /* Successful calls replace the mask. Linux validates an upgrade
             * before publishing it, so rejection preserves CSUM-only mode. */
            if (ioctl(fd, TUNSETOFFLOAD, (unsigned long) (TUN_F_CSUM | TUN_F_TSO4)) == 0)
            {
                *out_gso_enabled = true;
            }
            else
            {
                const int upgrade_errno = errno;
                LOGW("TunDevice: %s TCPv4 GSO upgrade unavailable (errno %d: %s); retaining checksum-only offload",
                     ifr.ifr_name,
                     upgrade_errno,
                     strerror(upgrade_errno));
            }
        }
    }
    if (*out_gso_enabled)
    {
        uint32_t active_max_segments = 0;
        if (tunLinuxGsoMaxSegmentsConfigure(ifr.ifr_name, kTunLinuxRequestedGsoMaxSegments, &active_max_segments))
        {
            LOGI("TunDevice: %s kernel GSO max segments set to %u", ifr.ifr_name, active_max_segments);
        }
        else
        {
            const int limit_errno = errno;
            LOGW("TunDevice: %s could not set/verify kernel GSO max segments %u (active %u; errno %d: %s); "
                 "continuing with bounded reader output",
                 ifr.ifr_name,
                 kTunLinuxRequestedGsoMaxSegments,
                 active_max_segments,
                 limit_errno,
                 strerror(limit_errno));
        }
    }

    if (! tunSetMtuByName(ifr.ifr_name, mtu))
    {
        *out_reason = "setting MTU";
        *out_errno  = errno;
        close(fd);
        return kTunLinuxOpenFailure;
    }
    if (! tunSetNonBlocking(fd))
    {
        *out_reason = "setting nonblocking I/O";
        *out_errno  = errno;
        close(fd);
        return kTunLinuxOpenFailure;
    }

    *out_fd  = fd;
    *out_ifr = ifr;
    return kTunLinuxOpenOk;
}
#endif

tun_device_t *tundeviceCreate(const char *name, bool gso_requested, uint16_t mtu, void *userdata, TunReadEventHandle cb,
                              device_fragment_policy_t fragment_policy)
{
    if (mtu <= 16)
    {
        LOGE("TunDevice: Invalid MTU size: %u", mtu);
        return NULL;
    }

    struct ifreq ifr;
#ifdef OS_BSD
    discard gso_requested;
    int     fd = -1;

    // Open the TUN device
    char tun_path[64];
    snprintf(tun_path, sizeof(tun_path), "/dev/%s", name);
    if ((fd = open(tun_path, O_RDWR)) < 0)
    {
        LOGE("TunDevice: opening %s failed", tun_path);
        return NULL;
    }

    // Prepare the ifreq structure to configure the TUN device
    memoryZero(&ifr, sizeof(ifr));
    strncpy(ifr.ifr_name, name, IFNAMSIZ - 1);
    ifr.ifr_name[IFNAMSIZ - 1] = '\0';

    // Set the interface flags (IFF_UP to bring the interface up)
    ifr.ifr_flags = IFF_UP;

    // Configure the TUN device using ioctl
    if (ioctl(fd, SIOCSIFFLAGS, &ifr) < 0)
    {
        LOGE("TunDevice: ioctl(SIOCSIFFLAGS) failed");
        close(fd);
        return NULL;
    }

    if (! tunSetMtuByName(ifr.ifr_name, mtu))
    {
        close(fd);
        return NULL;
    }

    // The reader drains until EAGAIN after every readiness notification, so a
    // blocking descriptor cannot be published safely.
    if (! tunSetNonBlocking(fd))
    {
        close(fd);
        return NULL;
    }

#else
    int                     fd                    = -1;
    bool                    interface_preexisting = false;
    bool                    gso_enabled           = false;
    bool                    checksum_offload_enabled = false;
    const char             *reason                = NULL;
    int                     failure_errno         = 0;
    tun_linux_open_result_t result =
        tunLinuxOpenAttempt(name, true, gso_requested, true, mtu, &fd, &ifr, &gso_enabled, &reason, &failure_errno);
    if (result == kTunLinuxOpenOk)
    {
        checksum_offload_enabled = true;
    }
    else
    {
        if (result == kTunLinuxOpenOffloadUnavailable)
        {
            LOGW(
                "TunDevice: checksum offload setup unavailable for %s at %s (errno %d: %s); falling back to raw-IP TUN",
                name,
                reason,
                failure_errno,
                strerror(failure_errno));
        }
        if (result == kTunLinuxOpenFailure || (gso_requested && result == kTunLinuxOpenNameConflict))
        {
            LOGE("TunDevice: cannot open %s: %s (errno %d: %s)", name, reason, failure_errno, strerror(failure_errno));
            return NULL;
        }
        result = tunLinuxOpenAttempt(name, false, false, true, mtu, &fd, &ifr, &gso_enabled, &reason, &failure_errno);
        if (! gso_requested && result == kTunLinuxOpenNameConflict)
        {
            /* Preserve raw-IP attachment support, but only an exclusive open
             * proves ownership of a fresh interface's resolver baseline. */
            interface_preexisting = true;
            result =
                tunLinuxOpenAttempt(name, false, false, false, mtu, &fd, &ifr, &gso_enabled, &reason, &failure_errno);
        }
        if (result != kTunLinuxOpenOk)
        {
            LOGE("TunDevice: raw-IP TUN setup failed for %s at %s (errno %d: %s)",
                 name,
                 reason,
                 failure_errno,
                 strerror(failure_errno));
            return NULL;
        }
    }
#endif

    /*
     * Device bring-up/creation runs on an event worker even though the reader
     * and writer threads it manages stay unregistered. Read that worker's pool
     * geometry once here and copy it onto the device-owned pools; the auxiliary
     * threads never touch worker-local state themselves.
     */
    buffer_pool_t *worker_pool = getCurrentEventWorkerBufferPool();

    buffer_pool_t *reader_bpool = devicePoolCreate(worker_pool, mtu);
    if (UNLIKELY(reader_bpool == NULL))
    {
        LOGE("TunDevice: failed to construct reader buffer pool");
        close(fd);
        return NULL;
    }

    buffer_pool_t *writer_bpool = devicePoolCreate(worker_pool, mtu);
    if (UNLIKELY(writer_bpool == NULL))
    {
        LOGE("TunDevice: failed to construct writer buffer pool");
        bufferpoolDestroy(reader_bpool);
        close(fd);
        return NULL;
    }

    tun_device_t *tdev = memoryAllocate(sizeof(tun_device_t));
    if (UNLIKELY(tdev == NULL))
    {
        bufferpoolDestroy(reader_bpool);
        bufferpoolDestroy(writer_bpool);
        close(fd);
        return NULL;
    }

    char *device_name = stringDuplicate(ifr.ifr_name);
    if (UNLIKELY(device_name == NULL))
    {
        memoryFree(tdev);
        bufferpoolDestroy(reader_bpool);
        bufferpoolDestroy(writer_bpool);
        close(fd);
        return NULL;
    }

    *tdev = (tun_device_t) {.name                = device_name,
                            .routine_reader      = routineReadFromTun,
                            .routine_writer      = routineWriteToTun,
                            .handle              = fd,
                            .read_event_callback = cb,
                            .userdata            = userdata,
                            .reader_session      = NULL,
                            .reader_buffer_pool  = reader_bpool,
                            .writer_buffer_pool  = writer_bpool,
                            .mtu                 = mtu,
#ifdef OS_LINUX
                            .checksum_offload_enabled = checksum_offload_enabled,
                            .gso_enabled              = gso_enabled,
                            .offload_scratch          = NULL,
                            .interface_preexisting    = interface_preexisting
#else
                            .gso_enabled = false
#endif
    };
    atomic_init(&tdev->lifecycle, kTunLifecycleDown);
#ifdef OS_LINUX
    atomic_init(&tdev->gso_generated_segments, 0);
    atomic_init(&tdev->gso_intact_aggregates, 0);
#endif
    deviceWriterChannelInit(&tdev->writer_channel);
    tdev->reader_session = deviceReaderSessionCreate(
        RAM_PROFILE * 2, kMaxReadDistributeQueueSize, tdev, tunDeliverPacket, reader_bpool, fragment_policy);
    if (UNLIKELY(tdev->reader_session == NULL))
    {
        LOGE("TunDevice: failed to allocate reader session");
        discard deviceWriterChannelDestroy(&tdev->writer_channel);
        memoryFree(tdev->name);
        bufferpoolDestroy(tdev->reader_buffer_pool);
        bufferpoolDestroy(tdev->writer_buffer_pool);
        close(tdev->handle);
        memoryFree(tdev);
        return NULL;
    }

#ifdef OS_LINUX
    bool offload_fallback = false;
    if (tdev->checksum_offload_enabled)
    {
        devicePoolUpdatePadding(tdev->reader_buffer_pool, worker_pool);
        const uint16_t    padding = bufferpoolGetLargeBufferPadding(tdev->reader_buffer_pool);
        buffer_pool_fit_t scratch_fit;
        if (! bufferpoolQueryBestFit(tdev->reader_buffer_pool,
                                     kTunOffloadPacketStorageCapacity,
                                     max(padding, (uint16_t) kTunVirtioHeaderSize),
                                     &scratch_fit))
        {
            LOGW("TunDevice: offload receive scratch geometry unavailable for %s; falling back to raw-IP TUN",
                 tdev->name);
            offload_fallback = true;
        }
        else if ((tdev->offload_scratch =
                      sbufTryCreateWithPadding(scratch_fit.payload_capacity, scratch_fit.left_padding)) == NULL)
        {
            LOGW("TunDevice: offload receive scratch unavailable for %s; falling back to raw-IP TUN", tdev->name);
            offload_fallback = true;
        }
        else if (UNLIKELY(sbufGetLeftCapacity(tdev->offload_scratch) < kTunVirtioHeaderSize ||
                          sbufGetMaximumWriteableSize(tdev->offload_scratch) < kTunOffloadPacketStorageCapacity))
        {
            LOGF("TunDevice: offload scratch allocation violates required geometry");
            abortProgramNow(1);
        }
        else if (! tunConfigureWorkerOffload(tdev))
        {
            const int budget_errno = errno;
            LOGW("TunDevice: offload worker-budget setup failed for %s (errno %d: %s); falling back to raw-IP TUN",
                 tdev->name,
                 budget_errno,
                 strerror(budget_errno));
            offload_fallback = true;
        }
        else if (tdev->gso_enabled && ! tunConfigureWorkerGso(tdev))
        {
            LOGW("TunDevice: %s GSO output allowance unavailable; disabling TCPv4 segmentation", tdev->name);
            if (ioctl(tdev->handle, TUNSETOFFLOAD, (unsigned long) TUN_F_CSUM) == 0)
            {
                tdev->gso_enabled = false;
            }
            else
            {
                const int downgrade_errno = errno;
                LOGW("TunDevice: %s checksum-only downgrade failed (errno %d: %s); reopening device",
                     tdev->name,
                     downgrade_errno,
                     strerror(downgrade_errno));
                close(tdev->handle);
                tdev->handle = -1;
                result       = tunLinuxOpenAttempt(tdev->name,
                                             true,
                                             false,
                                             true,
                                             mtu,
                                             &tdev->handle,
                                             &ifr,
                                             &tdev->gso_enabled,
                                             &reason,
                                             &failure_errno);
                if (result == kTunLinuxOpenOffloadUnavailable)
                {
                    offload_fallback = true;
                }
                else if (result != kTunLinuxOpenOk)
                {
                    LOGE("TunDevice: checksum-only reopen failed for %s at %s (errno %d: %s)",
                         tdev->name,
                         reason,
                         failure_errno,
                         strerror(failure_errno));
                    goto fail_after_session;
                }
            }
            memoryZero(tdev->gso_output_charge, sizeof(tdev->gso_output_charge));
        }
    }
    if (offload_fallback)
    {
        if (tdev->offload_scratch != NULL)
        {
            sbufDestroy(tdev->offload_scratch);
            tdev->offload_scratch = NULL;
        }
        if (tdev->handle >= 0)
        {
            close(tdev->handle);
        }
        tdev->handle        = -1;
        int          raw_fd = -1;
        struct ifreq raw_ifr;
        result = tunLinuxOpenAttempt(
            tdev->name, false, false, true, mtu, &raw_fd, &raw_ifr, &tdev->gso_enabled, &reason, &failure_errno);
        if (result != kTunLinuxOpenOk)
        {
            LOGE("TunDevice: raw-IP fallback failed for %s at %s (errno %d: %s)",
                 name,
                 reason,
                 failure_errno,
                 strerror(failure_errno));
            goto fail_after_session;
        }
        tdev->handle                   = raw_fd;
        tdev->gso_enabled              = false;
        tdev->checksum_offload_enabled = false;
        LOGI("TunDevice: %s opened with raw IP after offload setup fallback", tdev->name);
    }
#endif

    if (! tunCreateStopPipe(tdev->linux_pipe_fds))
    {
        LOGE("TunDevice: failed to create pipe for linux_pipe_fds");
        goto fail_after_session;
    }

#ifdef OS_LINUX
    assert(! tdev->gso_enabled || tdev->checksum_offload_enabled);
    LOGI("TunDevice: %s configured framing: %s (GSO requested: %s)",
         tdev->name,
         tdev->gso_enabled                ? "TCPv4 GSO with checksum offload"
         : tdev->checksum_offload_enabled ? "checksum-only offload"
                                          : "raw IP",
         gso_requested ? "yes" : "no");
#endif

    return tdev;

fail_after_session:
    memoryFree(tdev->name);
#ifdef OS_LINUX
    if (tdev->offload_scratch != NULL)
    {
        sbufDestroy(tdev->offload_scratch);
    }
#endif
    deviceReaderSessionRetireProducerBuffers(tdev->reader_session);
    bufferpoolDestroy(tdev->reader_buffer_pool);
    bufferpoolDestroy(tdev->writer_buffer_pool);
    deviceReaderSessionUnref(tdev->reader_session);
    if (tdev->handle >= 0)
    {
        close(tdev->handle);
    }
    memoryFree(tdev);
    return NULL;
}
// Destroy TUN device
void tundeviceDestroy(tun_device_t *tdev)
{
    // Unconditional: bring-down is a no-op when nothing is owned, and gating this
    // on readiness would skip cleanup after a thread died on its own.
    if (! tundeviceBringDown(tdev))
    {
        /*
         * Category D: interface cleanup did not complete, so the validity of the
         * remaining device state is unknown and continuing to free it would be a
         * use-after-free risk. Hard-abort with an explicit diagnostic rather than
         * trying to run more cleanup.
         */
        LOGF("TunDevice: refusing to destroy device while interface cleanup is incomplete");
        abortProgramNow(1);
    }
    /*
     * Device destruction follows worker/lwIP shutdown, so no producer can
     * retain a generation pointer while retired queues are reclaimed.
     */
    if (! deviceWriterChannelDestroy(&tdev->writer_channel))
    {
        LOGF("TunDevice: refusing to destroy a published writer generation");
        abortProgramNow(1);
    }
    memoryFree(tdev->name);
#ifdef OS_LINUX
    tunLinuxDnsDropSnapshot(tdev);
    if (tdev->offload_scratch != NULL)
    {
        sbufDestroy(tdev->offload_scratch);
    }
#endif
    deviceReaderSessionRetireProducerBuffers(tdev->reader_session);
    bufferpoolDestroy(tdev->reader_buffer_pool);
    bufferpoolDestroy(tdev->writer_buffer_pool);
    close(tdev->handle);
    close(tdev->linux_pipe_fds[0]);
    close(tdev->linux_pipe_fds[1]);
    deviceReaderSessionUnref(tdev->reader_session);
    memoryFree(tdev);
}

#if defined(OS_LINUX)

device_reader_session_t *tunLinuxReaderSession(tun_device_t *tdev)
{
    return tdev->reader_session;
}

buffer_pool_t *tunLinuxWriterBufferPool(tun_device_t *tdev)
{
    return tdev->writer_buffer_pool;
}

device_writer_channel_t *tunLinuxWriterChannel(tun_device_t *tdev)
{
    return &tdev->writer_channel;
}

void tunLinuxSetReaderRoutine(tun_device_t *tdev, wthread_routine routine)
{
    tdev->routine_reader = routine;
}

void tunLinuxSetWriterRoutine(tun_device_t *tdev, wthread_routine routine)
{
    tdev->routine_writer = routine;
}

tun_lifecycle_state_t tunLinuxLifecycleState(const tun_device_t *tdev)
{
    return tunLifecycleLoad(&tdev->lifecycle);
}

#endif

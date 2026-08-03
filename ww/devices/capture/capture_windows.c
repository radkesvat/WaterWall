#include "capture.h"
#include "capture_windows_lifetime.h"

#include "buffer_pool.h"
#include "devices/device_flow_affinity.h"
#include "global_state.h"
#include "managers/windivert_manager.h"
#include "master_pool.h"
#include "wloop.h"
#include "worker.h"
#include "wplatform.h"

#include "loggers/internal_logger.h"

static uint8_t capturedeviceIpv4MaskPrefixLength(const ip_addr_t *mask)
{
    uint32_t mask_host = lwip_ntohl(mask->u_addr.ip4.addr);
    uint8_t  prefix    = 0;

    while ((mask_host & 0x80000000U) != 0)
    {
        ++prefix;
        mask_host <<= 1U;
    }

    return prefix;
}

static void capturedeviceFormatIpv4(uint32_t addr_host, char *dest, size_t dest_len)
{
    stringNPrintf(dest,
                  dest_len,
                  "%u.%u.%u.%u",
                  (addr_host >> 24U) & 0xFFU,
                  (addr_host >> 16U) & 0xFFU,
                  (addr_host >> 8U) & 0xFFU,
                  addr_host & 0xFFU);
}

static char *capturedeviceBuildWinDivertFilter(const ipmask_t *ranges, uint32_t range_count)
{
    size_t filter_len = 10U; // "ip and (" + ")" + NUL

    for (uint32_t i = 0; i < range_count; ++i)
    {
        filter_len += 80U;
    }

    char  *filter = memoryAllocate(filter_len);
    size_t offset = 0;

    offset += (size_t) stringNPrintf(filter + offset, filter_len - offset, "ip and (");

    for (uint32_t i = 0; i < range_count; ++i)
    {
        const uint32_t ip_host   = lwip_ntohl(ranges[i].ip.u_addr.ip4.addr);
        const uint32_t mask_host = lwip_ntohl(ranges[i].mask.u_addr.ip4.addr);
        const uint32_t min_host  = ip_host & mask_host;
        const uint32_t max_host  = min_host | ~mask_host;

        char min_ip[16];
        char max_ip[16];

        capturedeviceFormatIpv4(min_host, min_ip, sizeof(min_ip));
        capturedeviceFormatIpv4(max_host, max_ip, sizeof(max_ip));

        if (i > 0)
        {
            offset += (size_t) stringNPrintf(filter + offset, filter_len - offset, " or ");
        }

        if (capturedeviceIpv4MaskPrefixLength(&ranges[i].mask) == 32)
        {
            offset += (size_t) stringNPrintf(filter + offset, filter_len - offset, "ip.SrcAddr == %s", min_ip);
        }
        else
        {
            offset += (size_t) stringNPrintf(
                filter + offset, filter_len - offset, "(ip.SrcAddr >= %s and ip.SrcAddr <= %s)", min_ip, max_ip);
        }
    }

    stringNPrintf(filter + offset, filter_len - offset, ")");

    return filter;
}

static void captureDeliverPacket(void *device, sbuf_t *buf, wid_t wid)
{
    capture_device_t *cdev = device;
    cdev->read_event_callback(cdev, cdev->userdata, buf, wid);
}

static void distributePacketPayload(capture_device_t *cdev, sbuf_t *buf)
{
    deviceFlowAffinityPostBatch(cdev->reader_session, &buf, 1);
}
static WTHREAD_ROUTINE(routineReadFromCapture) // NOLINT
{
    capture_device_t *cdev = userdata;
    sbuf_t           *buf;
    UINT              read_packet_len = 0;
    HANDLE            handle          = cdev->handle;

    assert(handle != NULL && handle != INVALID_HANDLE_VALUE);

    while (captureLifecycleIsActive(captureLifecycleLoad(&cdev->lifecycle)))
    {
        buf = bufferpoolGetSmallBuffer(cdev->reader_buffer_pool);

        buf = sbufReserveSpace(buf, kMaxAllowedPacketLength);

        if (! windivertRecv(handle, sbufGetMutablePtr(buf), kMaxAllowedPacketLength, &read_packet_len, NULL))
        {
            DWORD recv_error = GetLastError();
            bufferpoolReuseBuffer(cdev->reader_buffer_pool, buf);

            if (recv_error == ERROR_NO_DATA)
            {
                LOGD("CaptureDevice: receive was shut down, exiting read routine");
                break;
            }

            if (! captureLifecycleIsActive(captureLifecycleLoad(&cdev->lifecycle)))
            {
                break;
            }

            LOGE("CaptureDevice: terminal packet read failure on device %s: error %lu", cdev->name, recv_error);
            break;
        }

        if (! captureLifecycleIsActive(captureLifecycleLoad(&cdev->lifecycle)))
        {
            bufferpoolReuseBuffer(cdev->reader_buffer_pool, buf);
            break;
        }

        if (UNLIKELY(read_packet_len == 0))
        {
            bufferpoolReuseBuffer(cdev->reader_buffer_pool, buf);
            LOGW("CaptureDevice: read packet with length 0");
            continue;
        }

        sbufSetLength(buf, read_packet_len);

        if (UNLIKELY(sbufGetLength(buf) > kMaxAllowedPacketLength))
        {
            // we are capturing packets and this can happen, so we just log it
            LOGW("CaptureDevice: ReadThread: discarded a packet -> size %d exceeds kMaxAllowedPacketLength %d",
                 sbufGetLength(buf),
                 kMaxAllowedPacketLength);

            bufferpoolReuseBuffer(cdev->reader_buffer_pool, buf);
            continue;
        }

        distributePacketPayload(cdev, buf);
    }

    return 0;
}

static void capturedeviceNoteUnexpectedReaderExit(capture_device_t *cdev)
{
    capture_lifecycle_state_t failed_from;
    if (! captureLifecycleTransitionToFailed(&cdev->lifecycle, &failed_from))
    {
        return;
    }

    atomicStoreRelaxed(&cdev->running, false);
    atomicStoreRelaxed(&cdev->up, false);
    LOGE("CaptureDevice: reader thread for device %s exited unexpectedly; the device is no longer usable", cdev->name);

    if (failed_from == kCaptureLifecycleUp && ! requestProgramShutdown(1))
    {
        abortProgramNow(1);
    }
}

static WTHREAD_ROUTINE(capturedeviceReaderThreadMain) // NOLINT
{
    // Auxiliary device thread: it must stay unregistered and use only
    // device-owned pools/channels, posting work to explicit event workers.
    assert(! currentThreadHasRegisteredWID());
    capture_device_t *cdev = userdata;
    discard           cdev->routine_reader(cdev);
    capturedeviceNoteUnexpectedReaderExit(cdev);
    return 0;
}

static bool capturedeviceHasHandle(const void *context)
{
    const capture_device_t *cdev = context;
    return cdev->handle != NULL && cdev->handle != INVALID_HANDLE_VALUE;
}

static bool capturedeviceReaderMayBeRunning(const void *context)
{
    const capture_device_t *cdev = context;
    return cdev->read_thread != NULL && ! cdev->reader_exit_confirmed;
}

static bool capturedeviceHasReader(const void *context)
{
    const capture_device_t *cdev = context;
    return cdev->read_thread != NULL;
}

static bool capturedeviceHasLiveResources(const capture_device_t *cdev)
{
    return captureLifecycleLoad(&cdev->lifecycle) != kCaptureLifecycleDown ||
           atomicLoadExplicit(&(cdev->up), memory_order_relaxed) || capturedeviceHasHandle(cdev) ||
           capturedeviceHasReader(cdev);
}

static void capturedeviceBeginShutdown(void *context)
{
    capture_device_t *cdev = context;

    captureLifecycleTransitionToStopping(&cdev->lifecycle);

    // These atomics carry loop/status values only. Thread creation/join and the
    // reader-session gate publish and reclaim the associated resources.
    atomicStoreRelaxed(&cdev->running, false);
    atomicStoreRelaxed(&cdev->up, false);
    deviceReaderSessionEnd(cdev->reader_session);
}

static bool capturedeviceShutdownHandle(void *context)
{
    capture_device_t *cdev = context;
    if (! capturedeviceHasHandle(cdev))
    {
        return true;
    }

    if (! windivertShutdown(cdev->handle, WINDIVERT_SHUTDOWN_BOTH))
    {
        DWORD last_error = GetLastError();
        LOGE("CaptureDevice: failed to shut down WinDivert handle: error %lu", last_error);
        return false;
    }

    return true;
}

static capture_windows_join_result_e capturedeviceJoinReader(void *context)
{
    capture_device_t *cdev = context;
    if (cdev->read_thread == NULL)
    {
        cdev->reader_exit_confirmed = false;
        return kCaptureWindowsJoinResultStopped;
    }

    if (! cdev->reader_exit_confirmed)
    {
        DWORD thread_id = GetThreadId(cdev->read_thread);
        if (thread_id == 0)
        {
            DWORD last_error = GetLastError();
            LOGE("CaptureDevice: failed to identify reader thread: error %lu", last_error);
            return kCaptureWindowsJoinResultNotStopped;
        }

        if (GetCurrentThreadId() == thread_id)
        {
            LOGE("CaptureDevice: cannot join reader thread from the same thread");
            return kCaptureWindowsJoinResultNotStopped;
        }

        DWORD wait_result = WaitForSingleObject(cdev->read_thread, INFINITE);
        if (wait_result != WAIT_OBJECT_0)
        {
            DWORD last_error = wait_result == WAIT_FAILED ? GetLastError() : ERROR_INVALID_FUNCTION;
            LOGE("CaptureDevice: failed to join reader thread, wait result: %lu, error: %lu", wait_result, last_error);
            return kCaptureWindowsJoinResultNotStopped;
        }

        cdev->reader_exit_confirmed = true;
    }

    if (! CloseHandle(cdev->read_thread))
    {
        DWORD last_error = GetLastError();
        LOGE("CaptureDevice: reader exited but its thread handle could not be closed: error %lu", last_error);
        return kCaptureWindowsJoinResultStoppedHandleReleaseFailed;
    }

    cdev->read_thread           = NULL;
    cdev->reader_exit_confirmed = false;
    bufferpoolResetThreadOwnership(cdev->reader_buffer_pool);
    return kCaptureWindowsJoinResultStopped;
}

static bool capturedeviceCloseHandle(void *context)
{
    capture_device_t *cdev = context;
    if (! capturedeviceHasHandle(cdev))
    {
        return true;
    }

    HANDLE handle = cdev->handle;
    if (! windivertClose(handle))
    {
        DWORD last_error = GetLastError();
        LOGE("CaptureDevice: failed to close WinDivert handle: error %lu", last_error);
        return false;
    }

    cdev->handle = NULL;
    return true;
}

static const capture_windows_lifetime_ops_t capture_lifetime_ops = {
    .begin_shutdown        = capturedeviceBeginShutdown,
    .has_handle            = capturedeviceHasHandle,
    .has_reader            = capturedeviceHasReader,
    .reader_may_be_running = capturedeviceReaderMayBeRunning,
    .shutdown_handle       = capturedeviceShutdownHandle,
    .join_reader           = capturedeviceJoinReader,
    .close_handle          = capturedeviceCloseHandle,
};

bool caputredeviceBringUp(capture_device_t *cdev)
{
    if (capturedeviceHasLiveResources(cdev))
    {
        LOGE("CaptureDevice: device is already up or shutdown is incomplete");
        return false;
    }
    if (! captureLifecycleTransitionDownToStarting(&cdev->lifecycle))
    {
        LOGE("CaptureDevice: device cannot be started in current lifecycle state");
        return false;
    }

    HANDLE handle = windivertOpen(cdev->filter, WINDIVERT_LAYER_NETWORK, 0, WINDIVERT_FLAG_RECV_ONLY);
    if (handle == NULL || handle == INVALID_HANDLE_VALUE)
    {
        DWORD last_error = GetLastError();
        LOGE("CaptureDevice: Failed to open WinDivert handle: error %lu", last_error);
        captureLifecycleTransitionStoppingToDown(&cdev->lifecycle);
        return false;
    }
    cdev->handle = handle;

    /*
     * Device bring-up/creation runs on an event worker even though the reader
     * and writer threads it manages stay unregistered. Read that worker's pool
     * geometry once here and copy it onto the device-owned pools; the auxiliary
     * threads never touch worker-local state themselves.
     */
    buffer_pool_t *worker_pool = getCurrentEventWorkerBufferPool();

    bufferpoolUpdateAllocationPaddings(cdev->reader_buffer_pool,
                                       bufferpoolGetLargeBufferPadding(worker_pool),
                                       bufferpoolGetSmallBufferPadding(worker_pool));

    cdev->reader_exit_confirmed = false;
    if (deviceReaderSessionBegin(cdev->reader_session) == 0)
    {
        LOGE("CaptureDevice: failed to open reader delivery generation");
        captureLifecycleTransitionToStopping(&cdev->lifecycle);
        if (captureWindowsLifetimeRollbackOpen(cdev, &capture_lifetime_ops))
        {
            captureLifecycleTransitionStoppingToDown(&cdev->lifecycle);
        }
        return false;
    }
    atomicStoreRelaxed(&cdev->running, true);

    wthread_error_t error = threadCreate(&cdev->read_thread, capturedeviceReaderThreadMain, cdev);
    if (error != kWThreadErrorNone)
    {
        atomicStoreRelaxed(&cdev->running, false);
        deviceReaderSessionEnd(cdev->reader_session);
        captureLifecycleTransitionToStopping(&cdev->lifecycle);
        LOGE("CaptureDevice: failed to create reader thread: error %u", error);

        if (captureWindowsLifetimeRollbackOpen(cdev, &capture_lifetime_ops))
        {
            captureLifecycleTransitionStoppingToDown(&cdev->lifecycle);
        }
        else
        {
            LOGE("CaptureDevice: failed to roll back WinDivert handle after reader-thread creation failure");
        }
        return false;
    }

    /*
     * Publish the compatibility status before the lifecycle CAS. If the reader
     * wins STARTING -> FAILED, both it and this rollback clear `up`; if this CAS
     * wins, any later UP -> FAILED reader exit clears it after publication.
     */
    atomicStoreRelaxed(&cdev->up, true);
    if (! captureLifecycleTransitionStartingToUp(&cdev->lifecycle))
    {
        atomicStoreRelaxed(&cdev->up, false);
        LOGE("CaptureDevice: reader thread failed during startup");
        captureLifecycleTransitionToStopping(&cdev->lifecycle);
        if (captureWindowsLifetimeShutdown(cdev, &capture_lifetime_ops))
        {
            captureLifecycleTransitionStoppingToDown(&cdev->lifecycle);
        }
        else
        {
            LOGE("CaptureDevice: reader-startup rollback is incomplete; retained resources require a shutdown retry");
        }
        return false;
    }

    LOGI("CaptureDevice: device %s is now up", cdev->name);
    return true;
}

bool caputredeviceBringDown(capture_device_t *cdev)
{
    if (! capturedeviceHasLiveResources(cdev))
    {
        return true;
    }

    captureLifecycleTransitionToStopping(&cdev->lifecycle);
    if (! captureWindowsLifetimeShutdown(cdev, &capture_lifetime_ops))
    {
        return false;
    }

    captureLifecycleTransitionStoppingToDown(&cdev->lifecycle);
    LOGI("CaptureDevice: device %s is now down", cdev->name);
    return true;
}

capture_device_t *caputredeviceCreate(const char *name, const ipmask_t *capture_ranges, uint32_t capture_range_count,
                                      void *userdata, CaptureReadEventHandle cb)
{
    if (capture_ranges == NULL || capture_range_count == 0)
    {
        LOGE("CaptureDevice: no capture ranges configured");
        return NULL;
    }

    if (! windivertManagerEnsureLoaded())
    {
        LOGE("CaptureDevice: failed to load WinDivert");
        return NULL;
    }

    /*
     * Device bring-up/creation runs on an event worker even though the reader
     * and writer threads it manages stay unregistered. Read that worker's pool
     * geometry once here and copy it onto the device-owned pools; the auxiliary
     * threads never touch worker-local state themselves.
     */
    buffer_pool_t *worker_pool = getCurrentEventWorkerBufferPool();

    buffer_pool_t *reader_bpool = bufferpoolCreate(GSTATE.masterpool_buffer_pools_large,
                                                   GSTATE.masterpool_buffer_pools_small,
                                                   RAM_PROFILE,
                                                   bufferpoolGetLargeBufferSize(worker_pool),
                                                   bufferpoolGetSmallBufferSize(worker_pool)

    );

    capture_device_t *cdev = memoryAllocate(sizeof(capture_device_t));

    *cdev = (capture_device_t) {.name                  = stringDuplicate(name),
                                .running               = false,
                                .up                    = false,
                                .routine_reader        = routineReadFromCapture,
                                .handle                = NULL,
                                .read_thread           = NULL,
                                .reader_exit_confirmed = false,
                                .read_event_callback   = cb,
                                .userdata              = userdata,
                                .reader_session        = NULL,
                                .reader_buffer_pool    = reader_bpool};
    atomic_init(&cdev->lifecycle, kCaptureLifecycleDown);

    cdev->filter         = capturedeviceBuildWinDivertFilter(capture_ranges, capture_range_count);
    cdev->reader_session = deviceReaderSessionCreate(RAM_PROFILE * 2, 1, cdev, captureDeliverPacket, reader_bpool);

    return cdev;
}

void capturedeviceDestroy(capture_device_t *cdev)
{
    if (capturedeviceHasLiveResources(cdev))
    {
        if (! caputredeviceBringDown(cdev))
        {
            LOGF("CaptureDevice: refusing to destroy device while the reader may still own resources");
            abortProgramNow(1);
        }
    }

    assert(! capturedeviceHasHandle(cdev));
    assert(cdev->read_thread == NULL);
    assert(! cdev->reader_exit_confirmed);
    assert(captureLifecycleLoad(&cdev->lifecycle) == kCaptureLifecycleDown);
    deviceReaderSessionEnd(cdev->reader_session);

    memoryFree(cdev->name);
    memoryFree(cdev->filter);
    bufferpoolDestroy(cdev->reader_buffer_pool);
    deviceReaderSessionUnref(cdev->reader_session);

    memoryFree(cdev);
}

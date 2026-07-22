#include "capture.h"
#include "capture_windows_lifetime.h"

#include "buffer_pool.h"
#include "global_state.h"
#include "managers/windivert_manager.h"
#include "master_pool.h"
#include "wloop.h"
#include "worker.h"
#include "wplatform.h"

#include "loggers/internal_logger.h"

enum
{
    kCaptureWriteChannelQueueMax = 128
};

struct msg_event
{
    capture_device_t *cdev;
    sbuf_t           *buf;
};

static pool_item_t *allocCaptureMsgPoolHandle(void *userdata)
{
    discard userdata;
    return memoryAllocate(sizeof(struct msg_event));
}

static void destroyCaptureMsgPoolHandle(master_pool_item_t *item)
{
    memoryFree(item);
}

static void cleanupCaptureMessage(struct msg_event *msg)
{
    if (msg == NULL)
    {
        return;
    }

    sbufDestroy(msg->buf);
    masterpoolReuseItems(msg->cdev->reader_message_pool, (void **) &msg, 1);
}

static void cleanupPostedCaptureMessage(void *arg1, void *arg2, void *arg3)
{
    struct msg_event *msg = arg1;
    discard           arg2;
    discard           arg3;

    cleanupCaptureMessage(msg);
}

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

static void localThreadMessageReceived(void *worker, void *arg1, void *arg2, void *arg3)
{
    struct msg_event *msg = arg1;
    wid_t             wid = ((worker_t *) worker)->wid;
    discard           arg2;
    discard           arg3;

    msg->cdev->read_event_callback(msg->cdev, msg->cdev->userdata, msg->buf, wid);

    masterpoolReuseItems(msg->cdev->reader_message_pool, (void **) &msg, 1);
}

static void distributePacketPayload(capture_device_t *cdev, wid_t target_wid, sbuf_t *buf)
{
    if (UNLIKELY(isApplicationTerminating() || GSTATE.shortcut_loops == NULL))
    {
        bufferpoolReuseBuffer(cdev->reader_buffer_pool, buf);
        return;
    }

    struct msg_event *msg;
    masterpoolGetItems(cdev->reader_message_pool, (const void **) &(msg), 1, cdev);

    *msg = (struct msg_event) {.cdev = cdev, .buf = buf};

    sendWorkerMessageForceQueueWithCleanup(
        target_wid, localThreadMessageReceived, cleanupPostedCaptureMessage, msg, NULL, NULL);
}
static WTHREAD_ROUTINE(routineReadFromCapture) // NOLINT
{
    capture_device_t *cdev = userdata;
    sbuf_t           *buf;
    UINT              read_packet_len = 0;
    HANDLE            handle          = cdev->handle;

    assert(handle != NULL && handle != INVALID_HANDLE_VALUE);

    while (atomicLoadExplicit(&(cdev->running), memory_order_relaxed))
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

            if (! atomicLoadExplicit(&(cdev->running), memory_order_relaxed))
            {
                break;
            }

            LOGE("CaptureDevice: failed to read packet from capture device: error %lu", recv_error);
            continue;
        }

        if (! atomicLoadExplicit(&(cdev->running), memory_order_relaxed))
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

        distributePacketPayload(cdev, getNextDistributionWID(), buf);
    }

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
    return atomicLoadExplicit(&(cdev->up), memory_order_relaxed) || capturedeviceHasHandle(cdev) ||
           capturedeviceHasReader(cdev);
}

static void capturedeviceBeginShutdown(void *context)
{
    capture_device_t *cdev = context;

    atomicStoreExplicit(&(cdev->running), false, memory_order_release);
    atomicStoreExplicit(&(cdev->up), false, memory_order_relaxed);
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

    HANDLE handle = windivertOpen(cdev->filter, WINDIVERT_LAYER_NETWORK, 0, WINDIVERT_FLAG_RECV_ONLY);
    if (handle == NULL || handle == INVALID_HANDLE_VALUE)
    {
        DWORD last_error = GetLastError();
        LOGE("CaptureDevice: Failed to open WinDivert handle: error %lu", last_error);
        return false;
    }
    cdev->handle = handle;

    bufferpoolUpdateAllocationPaddings(cdev->reader_buffer_pool,
                                       bufferpoolGetLargeBufferPadding(getWorkerBufferPool(getWID())),
                                       bufferpoolGetSmallBufferPadding(getWorkerBufferPool(getWID())));

    cdev->reader_exit_confirmed = false;
    atomicStoreExplicit(&(cdev->running), true, memory_order_release);

    cdev->read_thread = threadCreate(cdev->routine_reader, cdev);
    if (cdev->read_thread == NULL)
    {
        DWORD last_error = GetLastError();
        atomicStoreExplicit(&(cdev->running), false, memory_order_release);
        LOGE("CaptureDevice: failed to create reader thread: error %lu", last_error);

        if (! captureWindowsLifetimeRollbackOpen(cdev, &capture_lifetime_ops))
        {
            LOGE("CaptureDevice: failed to roll back WinDivert handle after reader-thread creation failure");
        }
        return false;
    }

    atomicStoreExplicit(&(cdev->up), true, memory_order_release);
    LOGI("CaptureDevice: device %s is now up", cdev->name);
    return true;
}

bool caputredeviceBringDown(capture_device_t *cdev)
{
    if (! capturedeviceHasLiveResources(cdev))
    {
        return true;
    }

    if (! captureWindowsLifetimeShutdown(cdev, &capture_lifetime_ops))
    {
        return false;
    }

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

    buffer_pool_t *reader_bpool = bufferpoolCreate(GSTATE.masterpool_buffer_pools_large,
                                                   GSTATE.masterpool_buffer_pools_small,
                                                   RAM_PROFILE,
                                                   bufferpoolGetLargeBufferSize(getWorkerBufferPool(getWID())),
                                                   bufferpoolGetSmallBufferSize(getWorkerBufferPool(getWID()))

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
                                .reader_message_pool   = masterpoolCreateWithCapacity(RAM_PROFILE * 2),
                                .reader_buffer_pool    = reader_bpool};

    cdev->filter = capturedeviceBuildWinDivertFilter(capture_ranges, capture_range_count);

    masterpoolInstallCallBacks(cdev->reader_message_pool, allocCaptureMsgPoolHandle, destroyCaptureMsgPoolHandle);

    return cdev;
}

void capturedeviceDestroy(capture_device_t *cdev)
{
    if (capturedeviceHasLiveResources(cdev))
    {
        if (! caputredeviceBringDown(cdev))
        {
            LOGF("CaptureDevice: refusing to destroy device while the reader may still own resources");
            terminateProgram(1);
        }
    }

    assert(! capturedeviceHasHandle(cdev));
    assert(cdev->read_thread == NULL);
    assert(! cdev->reader_exit_confirmed);

    memoryFree(cdev->name);
    memoryFree(cdev->filter);
    bufferpoolDestroy(cdev->reader_buffer_pool);
    masterpoolMakeEmpty(cdev->reader_message_pool);
    masterpoolDestroy(cdev->reader_message_pool);

    memoryFree(cdev);
}

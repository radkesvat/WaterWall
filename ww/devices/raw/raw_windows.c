#include "raw_private.h"

#include "buffer_pool.h"
#include "devices/device_packet_checksum.h"
#include "global_state.h"
#include "managers/windivert_manager.h"
#include "raw_windows_send_policy.h"

#include "loggers/internal_logger.h"
#include "loggers/log_rate_limiter.h"

enum
{
    kRawWriteQueueMax = 256
};

#ifdef ERROR_DATA_NOT_ACCEPTED
static_assert(kRawWindowsErrorDataNotAccepted == ERROR_DATA_NOT_ACCEPTED,
              "the raw writer's ERROR_DATA_NOT_ACCEPTED value drifted from Win32");
#endif
static_assert(kRawWindowsErrorHostUnreachable == ERROR_HOST_UNREACHABLE,
              "the raw writer's ERROR_HOST_UNREACHABLE value drifted from Win32");
static_assert(kRawWindowsErrorRetry == ERROR_RETRY, "the raw writer's ERROR_RETRY value drifted from Win32");

/* Each event worker owns its native operation while the writer gate is open.
 * CloseWait transfers exclusive ownership to the lifecycle coordinator. */
struct raw_native_writer_s
{
    OVERLAPPED         overlapped;
    WINDIVERT_ADDRESS  address;
    HANDLE             event;
    PTP_WAIT           wait;
    raw_writer_lane_t *lane;
    sbuf_t            *pending_buffer;
    log_rate_limiter_t discard_log_limiter;
    uint64_t           oversized_packet_total;
    uint64_t           packet_local_send_error_total;
    uint32_t           last_discard_error;
};

typedef enum rawdevice_discard_reason_e
{
    kRawDeviceDiscardOversized,
    kRawDeviceDiscardPacketLocalSendError
} rawdevice_discard_reason_t;

static void rawdeviceLogDiscards(raw_native_writer_t *native, wid_t wid, log_rate_limiter_report_t report)
{
    if (! report.should_log)
        return;
    LOGW("RawDevice: worker %u discarded %llu packet(s) over %llums "
         "(total=%llu, exceeding kMaxAllowedPacketLength=%u: %llu, "
         "packet-local WinDivertSendEx errors=%llu, last error=%u)",
         (unsigned int) wid,
         LLU(report.events),
         LLU(report.elapsed_ms),
         LLU(report.total),
         (unsigned int) kMaxAllowedPacketLength,
         LLU(native->oversized_packet_total),
         LLU(native->packet_local_send_error_total),
         native->last_discard_error);
}

static void rawdeviceRecordDiscard(raw_native_writer_t *native, wid_t wid, rawdevice_discard_reason_t reason,
                                   DWORD send_error)
{
    if (reason == kRawDeviceDiscardOversized)
        native->oversized_packet_total++;
    else
    {
        native->packet_local_send_error_total++;
        native->last_discard_error = (uint32_t) send_error;
    }
    rawdeviceLogDiscards(native, wid, logRateLimiterRecord(&native->discard_log_limiter, kRawDiscardReportIntervalMs));
}

static VOID CALLBACK rawdeviceWriteCompleted(PTP_CALLBACK_INSTANCE instance, PVOID context, PTP_WAIT wait,
                                             TP_WAIT_RESULT result)
{
    discard              instance;
    discard              wait;
    discard              result;
    raw_native_writer_t *native = context;
    /* A threadpool callback is a foreign notification root. The shared helper
     * retains its generation for the owner-worker message, including refusal. */
    discard rawWriterNotify(native->lane);
}

static bool rawdeviceWriteFailed(raw_device_t *rdev, DWORD error)
{
    raw_lifecycle_state_t failed_from;
    if (! rawLifecycleTransitionToFailed(&rdev->lifecycle, &failed_from))
        return false;
    LOGE("RawDevice: terminal WinDivertSendEx failure on device %s: error %lu", rdev->name, error);
    return failed_from == kRawLifecycleUp;
}

static raw_writer_batch_result_t rawdeviceWriteBatch(void *context, worker_t *worker, raw_writer_lane_t *lane,
                                                     sbuf_t **buffers, size_t count)
{
    raw_device_t        *rdev   = context;
    raw_native_writer_t *native = &rdev->writer_states[worker->wid];
    size_t               sent   = 0;
    if (native->lane == NULL)
        native->lane = lane;
    else
        assert(native->lane == lane);

    while (sent < count && rawLifecycleIsActive(rawLifecycleLoad(&rdev->lifecycle)))
    {
        sbuf_t *buf        = buffers[sent];
        DWORD   send_error = ERROR_SUCCESS;
        if (native->pending_buffer != NULL)
        {
            assert(native->pending_buffer == buf);
            DWORD completed;
            if (! GetOverlappedResult(rdev->handle, &native->overlapped, &completed, FALSE))
            {
                send_error = GetLastError();
                if (send_error == ERROR_IO_INCOMPLETE)
                    return (raw_writer_batch_result_t) {sent, kRawWriterBatchBlocked};
            }
            native->pending_buffer = NULL;
        }
        else
        {
            const uint32_t packet_len = sbufGetLength(buf);
            if (UNLIKELY(packet_len > kMaxAllowedPacketLength))
            {
                rawdeviceRecordDiscard(native, worker->wid, kRawDeviceDiscardOversized, 0);
                bufferpoolReuseBuffer(worker->buffer_pool, buf);
                sent++;
                continue;
            }

            /* A set flag asserts the bytes already contain a valid checksum.
             * Leave unproven checksums clear for WinDivert to calculate. */
            const device_packet_checksum_validity_t validity =
                deviceIpv4ChecksumValidity(sbufGetRawPtr(buf), packet_len);
            native->address = (WINDIVERT_ADDRESS) {
                .Layer       = WINDIVERT_LAYER_NETWORK,
                .Outbound    = 1,
                .IPChecksum  = validity.ipv4 ? 1 : 0,
                .TCPChecksum = validity.tcp ? 1 : 0,
                .UDPChecksum = validity.udp ? 1 : 0,
            };
            if (! ResetEvent(native->event))
            {
                send_error = GetLastError();
            }
            else
            {
                native->overlapped = (OVERLAPPED) {.hEvent = native->event};
                if (! windivertSendEx(rdev->handle,
                                      sbufGetRawPtr(buf),
                                      packet_len,
                                      NULL,
                                      &native->address,
                                      sizeof(native->address),
                                      &native->overlapped))
                    send_error = GetLastError();
                if (send_error == ERROR_IO_PENDING)
                {
                    /* Queue ownership includes this buffer until completion.
                     * Arm after submission: the manual-reset event preserves a
                     * completion that raced the SendEx return. */
                    native->pending_buffer = buf;
                    SetThreadpoolWait(native->wait, native->event, NULL);
                    return (raw_writer_batch_result_t) {sent, kRawWriterBatchBlocked};
                }
            }
        }

        bufferpoolReuseBuffer(worker->buffer_pool, buf);
        sent++;
        if (send_error == ERROR_SUCCESS)
            continue;
        if (rawWindowsClassifySendError(send_error) == kRawWindowsSendDiscardPacket)
        {
            rawdeviceRecordDiscard(native, worker->wid, kRawDeviceDiscardPacketLocalSendError, send_error);
            continue;
        }
        if (rawdeviceWriteFailed(rdev, send_error))
            return (raw_writer_batch_result_t) {sent, kRawWriterBatchFailed};
        break;
    }

    /* An admitted notification can overlap stop. A pending kernel operation
     * must remain in the FIFO until stop_worker cancels and settles it. */
    if (native->pending_buffer != NULL)
        return (raw_writer_batch_result_t) {sent, kRawWriterBatchBlocked};
    /* A different worker or the lifecycle owner may already have stopped the
     * device. Unsubmitted ownership can be discarded now. */
    while (sent < count)
        bufferpoolReuseBuffer(worker->buffer_pool, buffers[sent++]);
    return (raw_writer_batch_result_t) {sent, kRawWriterBatchContinue};
}

static void rawdeviceStopWriter(void *context, wid_t wid)
{
    raw_device_t        *rdev   = context;
    raw_native_writer_t *native = &rdev->writer_states[wid];

    /* The helper closed and quiesced submission before calling us. Disarm and
     * join foreign notification roots before releasing their lane association. */
    if (native->wait != NULL)
    {
        SetThreadpoolWait(native->wait, NULL, NULL);
        WaitForThreadpoolWaitCallbacks(native->wait, TRUE);
    }
    if (native->pending_buffer != NULL)
    {
        if (! CancelIoEx(rdev->handle, &native->overlapped) && GetLastError() != ERROR_NOT_FOUND)
            LOGW("RawDevice: failed to cancel pending native write, error %lu", GetLastError());
        DWORD completed;
        if (! GetOverlappedResult(rdev->handle, &native->overlapped, &completed, TRUE))
        {
            const DWORD error = GetLastError();
            if (error == ERROR_IO_INCOMPLETE || error == ERROR_INVALID_HANDLE)
            {
                LOGF("RawDevice: cannot confirm native write retirement, error %lu", error);
                abortProgramNow(1);
            }
        }
        /* Completion, including ERROR_OPERATION_ABORTED, returns kernel
         * ownership. CloseWait will now discard the still-queued sbuf. */
        native->pending_buffer = NULL;
    }
    if (native->wait != NULL)
    {
        CloseThreadpoolWait(native->wait);
        native->wait = NULL;
    }
    if (native->event != NULL)
    {
        CloseHandle(native->event);
        native->event = NULL;
    }
    rawdeviceLogDiscards(native, wid, logRateLimiterFlush(&native->discard_log_limiter));
}

static void rawdeviceFreeWriterStates(raw_device_t *rdev)
{
    memoryFree(rdev->writer_states);
    rdev->writer_states       = NULL;
    rdev->writer_worker_count = 0;
}

bool rawdeviceIsUp(const raw_device_t *rdev)
{
    return rdev != NULL && rawLifecycleLoad(&rdev->lifecycle) == kRawLifecycleUp;
}

static bool rawdeviceShouldLogRefusal(void)
{
    static thread_local uint32_t refusal_count;
    const uint32_t               ordinal = ++refusal_count;
    return ordinal == 1 || (ordinal & (ordinal - 1U)) == 0;
}

bool rawdeviceWrite(raw_device_t *rdev, sbuf_t *buf)
{
    assert(sbufGetLength(buf) >= sizeof(struct ip_hdr));
    if (UNLIKELY(! rawdeviceIsUp(rdev)))
    {
        if (rawdeviceShouldLogRefusal())
            LOGE("RawDevice: write failed, device is not up");
        return false;
    }
    switch (rawWriterTrySend(&rdev->writer, buf))
    {
    case kRawWriterSendOk:
        return true;
    case kRawWriterSendDown:
    case kRawWriterSendClosed:
        if (rawdeviceShouldLogRefusal())
            LOGE("RawDevice: write failed, output admission was closed");
        return false;
    case kRawWriterSendFull:
        return false;
    }
    return false;
}

bool rawdeviceBringUp(raw_device_t *rdev)
{
    discard getCurrentWorker();
    if (! rawLifecycleTransitionDownToStarting(&rdev->lifecycle))
    {
        LOGE("RawDevice: device cannot be started in current lifecycle state");
        return false;
    }
    rdev->writer_worker_count = getWorkersCount();
    rdev->writer_states       = memoryAllocateZero(rdev->writer_worker_count * sizeof(rdev->writer_states[0]));
    for (size_t i = 0; i < rdev->writer_worker_count; ++i)
    {
        raw_native_writer_t *native = &rdev->writer_states[i];
        native->event               = CreateEventW(NULL, TRUE, FALSE, NULL);
        if (native->event == NULL)
            goto fail;
        native->wait = CreateThreadpoolWait(rawdeviceWriteCompleted, native, NULL);
        if (native->wait == NULL)
            goto fail;
    }
    if (! rawWriterOpen(&rdev->writer, kRawWriteQueueMax, 0, rdev, rawdeviceWriteBatch, rawdeviceStopWriter))
        goto fail;
    if (! rawLifecycleTransitionStartingToUp(&rdev->lifecycle))
    {
        rawWriterCloseRequest(&rdev->writer);
        rawWriterCloseWait(&rdev->writer);
        rawdeviceFreeWriterStates(rdev);
        rawLifecycleTransitionStoppingToDown(&rdev->lifecycle);
        return false;
    }
    LOGI("RawDevice: device %s is now up", rdev->name);
    return true;

fail:
    LOGE("RawDevice: failed to initialize worker output, error %lu", GetLastError());
    for (size_t i = 0; i < rdev->writer_worker_count; ++i)
        rawdeviceStopWriter(rdev, (wid_t) i);
    rawdeviceFreeWriterStates(rdev);
    rawLifecycleTransitionStoppingToDown(&rdev->lifecycle);
    return false;
}

void rawdeviceRequestStop(raw_device_t *rdev)
{
    rawLifecycleTransitionToStopping(&rdev->lifecycle);
    rawWriterCloseRequest(&rdev->writer);
}

bool rawdeviceBringDown(raw_device_t *rdev)
{
    rawdeviceRequestStop(rdev);
    rawWriterCloseWait(&rdev->writer);
    rawdeviceFreeWriterStates(rdev);
    rawLifecycleTransitionStoppingToDown(&rdev->lifecycle);
    return true;
}

raw_device_t *rawdeviceCreate(const char *name, uint32_t mark, bool bypass_conntrack, void *userdata)
{
    discard getCurrentWorker();
    discard bypass_conntrack;
    if (! windivertManagerEnsureLoaded())
        return NULL;
    HANDLE handle = windivertOpen("false", WINDIVERT_LAYER_NETWORK, 0, WINDIVERT_FLAG_SEND_ONLY);
    if (handle == INVALID_HANDLE_VALUE)
    {
        LOGE("RawDevice: failed to open WinDivert handle: error %lu", GetLastError());
        return NULL;
    }
    raw_device_t *rdev = memoryAllocateZero(sizeof(*rdev));
    rdev->name         = stringDuplicate(name);
    rdev->handle       = handle;
    rdev->mark         = mark;
    rdev->userdata     = userdata;
    atomic_init(&rdev->lifecycle, kRawLifecycleDown);
    rawWriterInit(&rdev->writer);
    return rdev;
}

void rawdeviceDestroy(raw_device_t *rdev)
{
    discard rawdeviceBringDown(rdev);
    rawWriterDestroy(&rdev->writer);
    windivertShutdown(rdev->handle, WINDIVERT_SHUTDOWN_BOTH);
    if (! windivertClose(rdev->handle))
    {
        LOGF("RawDevice: failed to close its retired WinDivert handle, error %lu", GetLastError());
        abortProgramNow(1);
    }
    memoryFree(rdev->name);
    memoryFree(rdev);
}

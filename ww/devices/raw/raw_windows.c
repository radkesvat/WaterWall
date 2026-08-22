#include "raw.h"

#include "buffer_pool.h"
#include "devices/device_frag_affinity.h"
#include "global_state.h"
#include "managers/windivert_manager.h"
#include "master_pool.h"
#include "raw_windows_send_policy.h"
#include "wchan.h"
#include "wloop.h"
#include "worker.h"
#include "wplatform.h"

#include "loggers/internal_logger.h"

enum
{
    kMasterMessagePoolsbufGetLeftCapacity = 64,
    kRawWriteChannelQueueMax              = 256
};

#ifdef ERROR_DATA_NOT_ACCEPTED
static_assert(kRawWindowsErrorDataNotAccepted == ERROR_DATA_NOT_ACCEPTED,
              "the raw writer's ERROR_DATA_NOT_ACCEPTED value drifted from Win32");
#endif
static_assert(kRawWindowsErrorHostUnreachable == ERROR_HOST_UNREACHABLE,
              "the raw writer's ERROR_HOST_UNREACHABLE value drifted from Win32");
static_assert(kRawWindowsErrorRetry == ERROR_RETRY, "the raw writer's ERROR_RETRY value drifted from Win32");

typedef enum rawdevice_discard_reason_e
{
    kRawDeviceDiscardOversized,
    kRawDeviceDiscardPacketLocalSendError
} rawdevice_discard_reason_t;

static void rawdeviceRecordDiscard(raw_device_t *rdev, rawdevice_discard_reason_t reason, unsigned long send_error)
{
    if (reason == kRawDeviceDiscardOversized)
    {
        rdev->oversized_packet_total++;
    }
    else
    {
        rdev->packet_local_send_error_total++;
        rdev->last_discard_error = (uint32_t) send_error;
    }

    log_rate_limiter_report_t report = logRateLimiterRecord(&rdev->discard_log_limiter, kRawDiscardReportIntervalMs);
    if (! report.should_log)
    {
        return;
    }

    LOGW("RawDevice: discarded %llu packet(s) over %llums "
         "(total=%llu, exceeding kMaxAllowedPacketLength=%u: %llu, "
         "packet-local WinDivertSend errors=%llu, last error=%u)",
         LLU(report.events),
         LLU(report.elapsed_ms),
         LLU(report.total),
         (unsigned int) kMaxAllowedPacketLength,
         LLU(rdev->oversized_packet_total),
         LLU(rdev->packet_local_send_error_total),
         rdev->last_discard_error);
}

static void rawdeviceReportPendingDiscards(raw_device_t *rdev)
{
    log_rate_limiter_report_t report = logRateLimiterFlush(&rdev->discard_log_limiter);
    if (! report.should_log)
    {
        return;
    }

    LOGW("RawDevice: discarded %llu packet(s) before writer exit "
         "(total=%llu, exceeding kMaxAllowedPacketLength=%u: %llu, "
         "packet-local WinDivertSend errors=%llu, last error=%u)",
         LLU(report.events),
         LLU(report.total),
         (unsigned int) kMaxAllowedPacketLength,
         LLU(rdev->oversized_packet_total),
         LLU(rdev->packet_local_send_error_total),
         rdev->last_discard_error);
}

static WTHREAD_ROUTINE(routineWriteToRaw) // NOLINT
{
    raw_device_t     *rdev = userdata;
    sbuf_t           *buf;
    struct wchan_s   *writer_channel = deviceWriterChannelGetConsumerChannel(&rdev->writer_channel);
    WINDIVERT_ADDRESS addr           = {
                  .Layer      = WINDIVERT_LAYER_NETWORK,
                  .Outbound   = 1,
                  .IPChecksum = 1,
    };

    while (rawLifecycleIsActive(rawLifecycleLoad(&rdev->lifecycle)))
    {
        if (! chanRecv(writer_channel, (void **) &buf))
        {
            LOGD("RawDevice: routine write will exit due to channel closed");
            break;
        }

        uint32_t packet_len = sbufGetLength(buf);
        if (UNLIKELY(packet_len > kMaxAllowedPacketLength))
        {
            rawdeviceRecordDiscard(rdev, kRawDeviceDiscardOversized, 0);
            bufferpoolReuseBuffer(rdev->writer_buffer_pool, buf);
            continue;
        }

        /*
         * WinDivert reads a set checksum-valid bit as an assertion that the
         * checksum in the packet is already correct, and skips computing it.
         * Deriving that from structure - "it is IPv4, so the IP checksum is
         * fine" - asserts something the bytes were never asked about, and a
         * packet a node emitted with a stale or unset checksum then leaves the
         * host uncorrected. A cleared bit costs one driver-side computation and
         * is always accepted, so anything unproven stays clear.
         */
        const device_packet_checksum_validity_t validity = deviceIpv4ChecksumValidity(sbufGetRawPtr(buf), packet_len);

        addr.IPChecksum  = validity.ipv4 ? 1 : 0;
        addr.TCPChecksum = validity.tcp ? 1 : 0;
        addr.UDPChecksum = validity.udp ? 1 : 0;

        if (! windivertSend(rdev->handle, sbufGetRawPtr(buf), packet_len, NULL, &addr))
        {
            const unsigned long send_error = GetLastError();
            bufferpoolReuseBuffer(rdev->writer_buffer_pool, buf);

            if (rawWindowsClassifySendError(send_error) == kRawWindowsSendDiscardPacket)
            {
                rawdeviceRecordDiscard(rdev, kRawDeviceDiscardPacketLocalSendError, send_error);
                continue;
            }

            LOGE("RawDevice: terminal WinDivertSend failure on device %s: error %lu", rdev->name, send_error);
            break;
        }
        bufferpoolReuseBuffer(rdev->writer_buffer_pool, buf);
    }

    rawdeviceReportPendingDiscards(rdev);
    return 0;
}

static void rawdeviceNoteUnexpectedWriterExit(raw_device_t *rdev)
{
    raw_lifecycle_state_t failed_from;
    if (! rawLifecycleTransitionToFailed(&rdev->lifecycle, &failed_from))
    {
        return;
    }

    LOGE("RawDevice: writer thread for device %s exited unexpectedly; the device is no longer usable", rdev->name);

    if (failed_from == kRawLifecycleUp && ! requestProgramShutdown(1))
    {
        abortProgramNow(1);
    }
}

static WTHREAD_ROUTINE(rawdeviceWriterThreadMain) // NOLINT
{
    // Auxiliary device thread: it must stay unregistered and use only
    // device-owned pools/channels, posting work to explicit event workers.
    assert(! currentThreadHasRegisteredWID());
    raw_device_t *rdev = userdata;
    discard       rdev->routine_writer(rdev);
    rawdeviceNoteUnexpectedWriterExit(rdev);
    return 0;
}

bool rawdeviceIsUp(const raw_device_t *rdev)
{
    return rdev != NULL && rawLifecycleLoad(&rdev->lifecycle) == kRawLifecycleUp;
}

/* Failure-only TLS sampler: overload and shutdown bursts do not need one log
 * record per rejected packet, and successful writes never execute this code. */
static bool rawdeviceShouldLogRefusal(void)
{
    static thread_local uint32_t refusal_count;
    const uint32_t               ordinal = ++refusal_count;

    return ordinal == 1 || (ordinal & (ordinal - 1U)) == 0;
}

bool rawdeviceWrite(raw_device_t *rdev, sbuf_t *buf)
{
    assert(sbufGetLength(buf) > sizeof(struct ip_hdr));

    if (UNLIKELY(! rawdeviceIsUp(rdev)))
    {
        if (rawdeviceShouldLogRefusal())
        {
            LOGE("RawDevice: write failed, device is not up");
        }
        return false;
    }

    switch (deviceWriterChannelTrySend(&rdev->writer_channel, buf))
    {
    case kDeviceWriterSendOk:
        return true;
    case kDeviceWriterSendDown:
        if (rawdeviceShouldLogRefusal())
        {
            LOGE("RawDevice: write failed, device is down");
        }
        return false;
    case kDeviceWriterSendClosed:
        if (rawdeviceShouldLogRefusal())
        {
            LOGE("RawDevice: write failed, channel was closed");
        }
        return false;
    case kDeviceWriterSendFull:
        return false;
    }

    return false;
}

bool rawdeviceBringUp(raw_device_t *rdev)
{
    if (rdev->writer_joinable || deviceWriterChannelHasCurrent(&rdev->writer_channel))
    {
        LOGE("RawDevice: previous writer ownership has not been released");
        return false;
    }
    if (! rawLifecycleTransitionDownToStarting(&rdev->lifecycle))
    {
        LOGE("RawDevice: device cannot be started in current lifecycle state");
        return false;
    }

    /*
     * Device bring-up/creation runs on an event worker even though the reader
     * and writer threads it manages stay unregistered. Read that worker's pool
     * geometry once here and copy it onto the device-owned pools; the auxiliary
     * threads never touch worker-local state themselves.
     */
    buffer_pool_t *worker_pool = getCurrentEventWorkerBufferPool();

    bufferpoolUpdateAllocationPaddings(rdev->writer_buffer_pool,
                                       bufferpoolGetLargeBufferPadding(worker_pool),
                                       bufferpoolGetSmallBufferPadding(worker_pool));

    if (! deviceWriterChannelOpen(&rdev->writer_channel, kRawWriteChannelQueueMax))
    {
        LOGE("RawDevice: failed to open writer channel");
        rawLifecycleTransitionStoppingToDown(&rdev->lifecycle);
        return false;
    }

    // wthread_error_t read_error = threadCreate(&rdev->read_thread, rdev->routine_reader, rdev);

    wthread_error_t error = threadCreate(&rdev->write_thread, rawdeviceWriterThreadMain, rdev);
    if (UNLIKELY(error != kWThreadErrorNone))
    {
        LOGE("RawDevice: failed to create writer thread: error %u", error);
        deviceWriterChannelClose(&rdev->writer_channel);
        discard deviceWriterChannelRetireCurrent(&rdev->writer_channel);
        rawLifecycleTransitionStoppingToDown(&rdev->lifecycle);
        return false;
    }

    rdev->writer_joinable = true;
    if (! rawLifecycleTransitionStartingToUp(&rdev->lifecycle))
    {
        LOGE("RawDevice: writer thread failed during startup");
        goto rollback;
    }

    LOGI("RawDevice: device %s is now up", rdev->name);
    return true;

rollback:
    rawLifecycleTransitionToStopping(&rdev->lifecycle);
    deviceWriterChannelClose(&rdev->writer_channel);

    bool rollback_ok = true;
    if (rdev->writer_joinable)
    {
        if (safeThreadJoin(rdev->write_thread))
        {
            rdev->writer_joinable = false;
            bufferpoolResetThreadOwnership(rdev->writer_buffer_pool);
        }
        else
        {
            LOGE("RawDevice: failed to join writer during startup rollback");
            rollback_ok = false;
        }
    }
    if (! rdev->writer_joinable && ! deviceWriterChannelRetireCurrent(&rdev->writer_channel))
    {
        rollback_ok = false;
    }
    if (rollback_ok)
    {
        rawLifecycleTransitionStoppingToDown(&rdev->lifecycle);
    }
    return false;
}

void rawdeviceRequestStop(raw_device_t *rdev)
{
    rawLifecycleTransitionToStopping(&rdev->lifecycle);
    deviceWriterChannelClose(&rdev->writer_channel);
}

bool rawdeviceBringDown(raw_device_t *rdev)
{
    if (rawLifecycleLoad(&rdev->lifecycle) == kRawLifecycleDown && ! rdev->writer_joinable &&
        ! deviceWriterChannelHasCurrent(&rdev->writer_channel))
    {
        LOGE("RawDevice: device is already down");
        return true;
    }

    rawdeviceRequestStop(rdev);

    bool bring_down_ok = true;
    if (rdev->writer_joinable)
    {
        if (safeThreadJoin(rdev->write_thread))
        {
            rdev->writer_joinable = false;
            bufferpoolResetThreadOwnership(rdev->writer_buffer_pool);
        }
        else
        {
            LOGE("RawDevice: failed to join writer thread; retaining writer resources");
            bring_down_ok = false;
        }
    }
    if (! rdev->writer_joinable && ! deviceWriterChannelRetireCurrent(&rdev->writer_channel))
    {
        bring_down_ok = false;
    }

    if (bring_down_ok)
    {
        rawLifecycleTransitionStoppingToDown(&rdev->lifecycle);
        LOGI("RawDevice: device %s is now down", rdev->name);
    }

    return bring_down_ok;
}

raw_device_t *rawdeviceCreate(const char *name, uint32_t mark, void *userdata)
{
    if (! windivertManagerEnsureLoaded())
    {
        LOGE("RawDevice: failed to load WinDivert");
        return NULL;
    }

    HANDLE handle = windivertOpen("false", WINDIVERT_LAYER_NETWORK, 0, WINDIVERT_FLAG_SEND_ONLY);
    if (handle == INVALID_HANDLE_VALUE)
    {
        // Handle error
        LOGE("RawDevice: Failed to open WinDivert handle: error %lu", GetLastError());
        return FALSE;
    }

    /*
     * Device bring-up/creation runs on an event worker even though the reader
     * and writer threads it manages stay unregistered. Read that worker's pool
     * geometry once here and copy it onto the device-owned pools; the auxiliary
     * threads never touch worker-local state themselves.
     */
    buffer_pool_t *worker_pool = getCurrentEventWorkerBufferPool();

    buffer_pool_t *writer_bpool = bufferpoolCreate(GSTATE.masterpool_buffer_pools_large,
                                                   GSTATE.masterpool_buffer_pools_small,
                                                   RAM_PROFILE,
                                                   bufferpoolGetLargeBufferSize(worker_pool),
                                                   bufferpoolGetSmallBufferSize(worker_pool)

    );
    if (UNLIKELY(writer_bpool == NULL))
    {
        LOGE("RawDevice: failed to construct writer buffer pool");
        windivertClose(handle);
        return NULL;
    }

    raw_device_t *rdev = memoryAllocate(sizeof(raw_device_t));
    if (UNLIKELY(rdev == NULL))
    {
        bufferpoolDestroy(writer_bpool);
        windivertClose(handle);
        return NULL;
    }

    char *device_name = stringDuplicate(name);
    if (UNLIKELY(device_name == NULL))
    {
        memoryFree(rdev);
        bufferpoolDestroy(writer_bpool);
        windivertClose(handle);
        return NULL;
    }

    *rdev = (raw_device_t) {.name               = device_name,
                            .routine_writer     = routineWriteToRaw,
                            .handle             = handle,
                            .mark               = mark,
                            .userdata           = userdata,
                            .writer_buffer_pool = writer_bpool,
                            .writer_joinable    = false};
    atomic_init(&rdev->lifecycle, kRawLifecycleDown);
    deviceWriterChannelInit(&rdev->writer_channel);

    return rdev;
}

void rawdeviceDestroy(raw_device_t *rdev)
{

    if (rawLifecycleLoad(&rdev->lifecycle) != kRawLifecycleDown || rdev->writer_joinable ||
        deviceWriterChannelHasCurrent(&rdev->writer_channel))
    {
        if (! rawdeviceBringDown(rdev))
        {
            LOGF("RawDevice: refusing to destroy device while writer ownership remains");
            abortProgramNow(1);
        }
    }
    /*
     * Node destruction runs after all worker and lwIP producer contexts have
     * stopped, so retired queue generations can finally be reclaimed.
     */
    if (! deviceWriterChannelDestroy(&rdev->writer_channel))
    {
        LOGF("RawDevice: refusing to destroy a published writer generation");
        abortProgramNow(1);
    }
    memoryFree(rdev->name);
    bufferpoolDestroy(rdev->writer_buffer_pool);
    windivertShutdown(rdev->handle, WINDIVERT_SHUTDOWN_BOTH);
    windivertClose(rdev->handle);
    memoryFree(rdev);
}

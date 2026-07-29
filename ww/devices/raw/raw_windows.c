#include "raw.h"

#include "buffer_pool.h"
#include "global_state.h"
#include "managers/windivert_manager.h"
#include "master_pool.h"
#include "wchan.h"
#include "wloop.h"
#include "worker.h"
#include "wplatform.h"
#include "wtime.h"

#include "loggers/internal_logger.h"

enum
{
    kMasterMessagePoolsbufGetLeftCapacity = 64,
    kRawWriteChannelQueueMax              = 256
};

static void rawdeviceRecordOversizedDiscard(raw_device_t *rdev)
{
    unsigned long long now_ms = getTimeOfDayMS();

    rdev->discarded_packet_total++;
    rdev->discarded_packet_suppressed++;
    rdev->oversized_packet_total++;

    if (rdev->discard_last_report_ms == 0)
    {
        rdev->discard_last_report_ms = now_ms;
        return;
    }

    unsigned long long elapsed_ms = now_ms - rdev->discard_last_report_ms;
    if (elapsed_ms < 1000)
    {
        return;
    }

    LOGW("RawDevice: discarded %llu oversized packet(s) over %llums "
         "(total=%llu, exceeding kMaxAllowedPacketLength=%u: %llu)",
         LLU(rdev->discarded_packet_suppressed),
         LLU(elapsed_ms),
         LLU(rdev->discarded_packet_total),
         (unsigned int) kMaxAllowedPacketLength,
         LLU(rdev->oversized_packet_total));
    rdev->discarded_packet_suppressed = 0;
    rdev->discard_last_report_ms      = now_ms;
}

static void rawdeviceReportPendingDiscards(raw_device_t *rdev)
{
    if (rdev->discarded_packet_suppressed == 0)
    {
        return;
    }

    LOGW("RawDevice: discarded %llu oversized packet(s) before writer exit "
         "(total=%llu, exceeding kMaxAllowedPacketLength=%u: %llu)",
         LLU(rdev->discarded_packet_suppressed),
         LLU(rdev->discarded_packet_total),
         (unsigned int) kMaxAllowedPacketLength,
         LLU(rdev->oversized_packet_total));
    rdev->discarded_packet_suppressed = 0;
}

static WTHREAD_ROUTINE(routineWriteToRaw) // NOLINT
{
    raw_device_t     *rdev = userdata;
    sbuf_t           *buf;
    struct wchan_s   *writer_channel = deviceWriterChannelGetConsumerChannel(&rdev->writer_channel);
    WINDIVERT_ADDRESS addr           = {
                  .Layer       = WINDIVERT_LAYER_NETWORK,
                  .Outbound    = 1,
                  .IPChecksum  = 1,
                  .TCPChecksum = 1,
                  .UDPChecksum = 1,
    };

    while (atomicLoadExplicit(&(rdev->running), memory_order_relaxed))
    {
        if (! chanRecv(writer_channel, (void **) &buf))
        {
            LOGD("RawDevice: routine write will exit due to channel closed");
            break;
        }

        uint32_t packet_len = sbufGetLength(buf);
        if (UNLIKELY(packet_len > kMaxAllowedPacketLength))
        {
            rawdeviceRecordOversizedDiscard(rdev);
            bufferpoolReuseBuffer(rdev->writer_buffer_pool, buf);
            continue;
        }

        if (! windivertSend(rdev->handle, sbufGetRawPtr(buf), packet_len, NULL, &addr))
        {
            LOGW("RawDevice: WinDivertSend failed: error %lu", GetLastError());
            bufferpoolReuseBuffer(rdev->writer_buffer_pool, buf);
            continue;
        }
        bufferpoolReuseBuffer(rdev->writer_buffer_pool, buf);
    }

    rawdeviceReportPendingDiscards(rdev);
    return 0;
}

bool rawdeviceWrite(raw_device_t *rdev, sbuf_t *buf)
{
    assert(sbufGetLength(buf) > sizeof(struct ip_hdr));

    switch (deviceWriterChannelTrySend(&rdev->writer_channel, buf))
    {
    case kDeviceWriterSendOk:
        return true;
    case kDeviceWriterSendDown:
        LOGE("RawDevice: write failed, device is down");
        return false;
    case kDeviceWriterSendClosed:
        LOGE("RawDevice: write failed, channel was closed");
        return false;
    case kDeviceWriterSendFull:
        LOGE("RawDevice: write failed, ring is full");
        return false;
    }

    return false;
}

bool rawdeviceBringUp(raw_device_t *rdev)
{
    if (atomicLoadRelaxed(&rdev->up))
    {
        LOGE("RawDevice: device is already up");
        return false;
    }
    if (rdev->writer_joinable || deviceWriterChannelHasCurrent(&rdev->writer_channel))
    {
        LOGE("RawDevice: previous writer ownership has not been released");
        return false;
    }

    bufferpoolUpdateAllocationPaddings(rdev->writer_buffer_pool,
                                       bufferpoolGetLargeBufferPadding(getWorkerBufferPool(getWID())),
                                       bufferpoolGetSmallBufferPadding(getWorkerBufferPool(getWID())));

    if (! deviceWriterChannelOpen(&rdev->writer_channel, kRawWriteChannelQueueMax))
    {
        LOGE("RawDevice: failed to open writer channel");
        return false;
    }
    // These atomics carry only stop/status values; queue publication and thread
    // creation provide the resource-publication edges.
    atomicStoreRelaxed(&rdev->running, true);

    // wthread_error_t read_error = threadCreate(&rdev->read_thread, rdev->routine_reader, rdev);

    wthread_error_t error = threadCreate(&rdev->write_thread, rdev->routine_writer, rdev);
    if (UNLIKELY(error != kWThreadErrorNone))
    {
        LOGE("RawDevice: failed to create writer thread: error %u", error);
        atomicStoreRelaxed(&rdev->running, false);
        deviceWriterChannelClose(&rdev->writer_channel);
        discard deviceWriterChannelRetireCurrent(&rdev->writer_channel);
        atomicStoreRelaxed(&rdev->up, false);
        return false;
    }

    rdev->writer_joinable = true;
    atomicStoreRelaxed(&rdev->up, true);
    LOGI("RawDevice: device %s is now up", rdev->name);
    return true;
}

bool rawdeviceBringDown(raw_device_t *rdev)
{
    const bool was_up = atomicExchangeExplicit(&rdev->up, false, memory_order_relaxed);
    if (! was_up && ! rdev->writer_joinable && ! deviceWriterChannelHasCurrent(&rdev->writer_channel))
    {
        LOGE("RawDevice: device is already down");
        return true;
    }

    atomicStoreRelaxed(&rdev->running, false);
    deviceWriterChannelClose(&rdev->writer_channel);

    if (rdev->writer_joinable)
    {
        if (UNLIKELY(! safeThreadJoin(rdev->write_thread)))
        {
            LOGE("RawDevice: failed to join writer thread; retaining writer resources");
            return false;
        }
        rdev->writer_joinable = false;
        bufferpoolResetThreadOwnership(rdev->writer_buffer_pool);
    }
    if (! deviceWriterChannelRetireCurrent(&rdev->writer_channel))
    {
        return false;
    }

    LOGI("RawDevice: device %s is now down", rdev->name);

    return true;
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

    raw_device_t *rdev = memoryAllocate(sizeof(raw_device_t));

    buffer_pool_t *writer_bpool = bufferpoolCreate(GSTATE.masterpool_buffer_pools_large,
                                                   GSTATE.masterpool_buffer_pools_small,
                                                   RAM_PROFILE,
                                                   bufferpoolGetLargeBufferSize(getWorkerBufferPool(getWID())),
                                                   bufferpoolGetSmallBufferSize(getWorkerBufferPool(getWID()))

    );

    *rdev = (raw_device_t) {.name               = stringDuplicate(name),
                            .running            = false,
                            .up                 = false,
                            .routine_writer     = routineWriteToRaw,
                            .handle             = handle,
                            .mark               = mark,
                            .userdata           = userdata,
                            .writer_buffer_pool = writer_bpool,
                            .writer_joinable    = false};
    deviceWriterChannelInit(&rdev->writer_channel);

    return rdev;
}

void rawdeviceDestroy(raw_device_t *rdev)
{

    if (atomicLoadRelaxed(&rdev->up) || rdev->writer_joinable || deviceWriterChannelHasCurrent(&rdev->writer_channel))
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

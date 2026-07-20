#include "raw.h"

#include "buffer_pool.h"
#include "global_state.h"
#include "managers/windivert_manager.h"
#include "master_pool.h"
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

static WTHREAD_ROUTINE(routineWriteToRaw) // NOLINT
{
    raw_device_t     *rdev = userdata;
    sbuf_t           *buf;
    WINDIVERT_ADDRESS addr = {
        .Layer       = WINDIVERT_LAYER_NETWORK,
        .Outbound    = 1,
        .IPChecksum  = 1,
        .TCPChecksum = 1,
        .UDPChecksum = 1,
    };

    while (atomicLoadExplicit(&(rdev->running), memory_order_relaxed))
    {
        if (! chanRecv(rdev->writer_buffer_channel, (void **) &buf))
        {
            LOGD("RawDevice: routine write will exit due to channel closed");
            return 0;
        }

        if (UNLIKELY(kMaxAllowedPacketLength < sbufGetLength(buf)))
        {
            LOGE("RawDevice: WriteThread: Packet size %d exceeds kMaxAllowedPacketLength %d", sbufGetLength(buf),
                 kMaxAllowedPacketLength);
           
            bufferpoolReuseBuffer(rdev->writer_buffer_pool, buf);
            terminateProgram(1);
        }

        if (! windivertSend(rdev->handle, sbufGetRawPtr(buf), sbufGetLength(buf), NULL, &addr))
        {
            LOGW("RawDevice: WinDivertSend failed: error %lu", GetLastError());
            bufferpoolReuseBuffer(rdev->writer_buffer_pool, buf);
            continue;
        }
        bufferpoolReuseBuffer(rdev->writer_buffer_pool, buf);
    }
    return 0;
}

bool rawdeviceWrite(raw_device_t *rdev, sbuf_t *buf)
{
    assert(sbufGetLength(buf) > sizeof(struct ip_hdr));

    bool closed = false;
    if (! chanTrySend(rdev->writer_buffer_channel, &buf, &closed))
    {
        if (closed)
        {
            LOGE("RawDevice: write failed, channel was closed");
        }
        else
        {
            LOGE("RawDevice: write failed, ring is full");
        }
        return false;
    }
    return true;
}

bool rawdeviceBringUp(raw_device_t *rdev)
{
    assert(! rdev->up);

    bufferpoolUpdateAllocationPaddings(rdev->writer_buffer_pool,
                                       bufferpoolGetLargeBufferPadding(getWorkerBufferPool(getWID())),
                                       bufferpoolGetSmallBufferPadding(getWorkerBufferPool(getWID())));

    rdev->up                    = true;
    rdev->running               = true;
    rdev->writer_buffer_channel = chanOpen(sizeof(void *), kRawWriteChannelQueueMax);

    // rdev->read_thread = threadCreate(rdev->routine_reader, rdev);
    LOGI("RawDevice: device %s is now up", rdev->name);

    rdev->write_thread = threadCreate(rdev->routine_writer, rdev);
    return true;
}

bool rawdeviceBringDown(raw_device_t *rdev)
{
    assert(rdev->up);

    rdev->running = false;
    rdev->up      = false;

    atomicThreadFence(memory_order_release);

    chanClose(rdev->writer_buffer_channel);

    safeThreadJoin(rdev->write_thread);

    sbuf_t *buf;
    while (chanRecv(rdev->writer_buffer_channel, (void **) &buf))
    {
        bufferpoolReuseBuffer(rdev->writer_buffer_pool, buf);
    }

    chanFree(rdev->writer_buffer_channel);
    rdev->writer_buffer_channel = NULL;

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

    buffer_pool_t *writer_bpool =
        bufferpoolCreate(GSTATE.masterpool_buffer_pools_large, GSTATE.masterpool_buffer_pools_small, RAM_PROFILE,
                         bufferpoolGetLargeBufferSize(getWorkerBufferPool(getWID())),
                         bufferpoolGetSmallBufferSize(getWorkerBufferPool(getWID()))

        );

    *rdev = (raw_device_t){.name                  = stringDuplicate(name),
                           .running               = false,
                           .up                    = false,
                           .routine_writer        = routineWriteToRaw,
                           .handle                = handle,
                           .mark                  = mark,
                           .userdata              = userdata,
                           .writer_buffer_channel = NULL,
                           .writer_buffer_pool    = writer_bpool};

    return rdev;
}

void rawdeviceDestroy(raw_device_t *rdev)
{

    if (rdev->up)
    {
        rawdeviceBringDown(rdev);
    }
    memoryFree(rdev->name);
    bufferpoolDestroy(rdev->writer_buffer_pool);
    windivertShutdown(rdev->handle, WINDIVERT_SHUTDOWN_BOTH);
    windivertClose(rdev->handle);
    memoryFree(rdev);
}

#include "generic_pool.h"
#include "global_state.h"
#include "loggers/internal_logger.h"
#include "raw.h"
#include "wchan.h"
#include "worker.h"
#include <arpa/inet.h>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/ipv6.h>
#include <netinet/ip.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

enum
{
    kReadPacketSize                      = 1500,
    kMasterMessagePoosbufGetLeftCapacity = 64,
    kRawWriteChannelQueueMax             = 256
};

struct msg_event
{
    raw_device_t *rdev;
    sbuf_t       *buf;
};

static pool_item_t *allocRawMsgPoolHandle(master_pool_t *pool, void *userdata)
{
    discard userdata;
    discard pool;
    return memoryAllocate(sizeof(struct msg_event));
}

static void destroyRawMsgPoolHandle(master_pool_t *pool, master_pool_item_t *item, void *userdata)
{
    discard pool;
    discard userdata;
    memoryFree(item);
}

static void localThreadEventReceived(wevent_t *ev)
{
    struct msg_event *msg = weventGetUserdata(ev);
    wid_t             tid = (wid_t) (wloopGetWid(weventGetLoop(ev)));

    msg->rdev->read_event_callback(msg->rdev, msg->rdev->userdata, msg->buf, tid);

    masterpoolReuseItems(msg->rdev->reader_message_pool, (void **) &msg, 1, msg->rdev);
}

static void distributePacketPayload(raw_device_t *rdev, wid_t target_wid, sbuf_t *buf)
{
    struct msg_event *msg;
    masterpoolGetItems(rdev->reader_message_pool, (const void **) &(msg), 1, rdev);

    *msg = (struct msg_event) {.rdev = rdev, .buf = buf};

    wevent_t ev;
    memorySet(&ev, 0, sizeof(ev));
    ev.loop = getWorkerLoop(target_wid);
    ev.cb   = localThreadEventReceived;
    weventSetUserData(&ev, msg);
    wloopPostEvent(getWorkerLoop(target_wid), &ev);
}

static WTHREAD_ROUTINE(routineReadFromRaw) // NOLINT
{
    raw_device_t   *rdev = userdata;
    sbuf_t         *buf;
    ssize_t         nread;
    struct sockaddr saddr;
    int             saddr_len = sizeof(saddr);

    while (atomicLoadExplicit(&(rdev->running), memory_order_relaxed))
    {
        buf = bufferpoolGetSmallBuffer(rdev->reader_buffer_pool);

        buf = sbufReserveSpace(buf, kReadPacketSize);

        nread = recvfrom(rdev->socket, sbufGetMutablePtr(buf), kReadPacketSize, 0, &saddr, (socklen_t *) &saddr_len);

        if (nread == 0)
        {
            bufferpoolReuseBuffer(rdev->reader_buffer_pool, buf);
            LOGW("RawDevice: Exit read routine due to End Of File");
            return 0;
        }

        if (nread < 0)
        {
            bufferpoolReuseBuffer(rdev->reader_buffer_pool, buf);

            LOGE("RawDevice: reading a packet from RAW device failed, code: %d", (int) nread);
            if (errno == EINVAL || errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
            {
                continue;
            }
            LOGE("RawDevice: Exit read routine due to critical error");
            return 0;
        }
        if (rdev->read_event_callback == NULL)
        {
            bufferpoolReuseBuffer(rdev->reader_buffer_pool, buf);
            continue;
        }

        sbufSetLength(buf, nread);

        distributePacketPayload(rdev, getNextDistributionWID(), buf);
    }

    return 0;
}

static WTHREAD_ROUTINE(routineWriteToRaw) // NOLINT
{
    raw_device_t *rdev = userdata;
    sbuf_t       *buf;
    ssize_t       nwrite;

    while (atomicLoadExplicit(&(rdev->running), memory_order_relaxed))
    {
        if (-1 == chanRecv(rdev->writer_buffer_channel, (void **) &buf))
        {
            LOGD("RawDevice: routine write will exit due to channel closed");
            return 0;
        }

        assert(sbufGetLength(buf) > sizeof(struct iphdr));

        struct iphdr *ip_header = (struct iphdr *) sbufGetRawPtr(buf);

        volatile struct sockaddr_in to_addr = {.sin_family = AF_INET, .sin_addr.s_addr = ip_header->daddr};

        nwrite =
            sendto(rdev->socket, ip_header, sbufGetLength(buf), 0, (struct sockaddr *) (&to_addr), sizeof(to_addr));

        bufferpoolReuseBuffer(rdev->writer_buffer_pool, buf);

        if (nwrite == 0)
        {
            LOGW("RawDevice: Exit write routine due to End Of File");
            return 0;
        }

        if (nwrite < 0)
        {
            LOGW("RawDevice: writing a packet to RAW  device failed, code: %d ", strerror(errno));
            // if (errno == EINVAL || errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
            // {
            //     continue;
            // }
            // LOGE("RawDevice: Exit write routine due to critical error");
            continue;

            // return 0;
        }
    }
    return 0;
}

bool writeToRawDevce(raw_device_t *rdev, sbuf_t *buf)
{
    assert(sbufGetLength(buf) > sizeof(struct iphdr));

    if (-1 == chanSend(rdev->writer_buffer_channel, buf))
    {

        LOGE("RawDevice: write failed, ring is full");

        return false;
    }
    return true;
}

bool bringRawDeviceUP(raw_device_t *rdev)
{
    assert(! rdev->up);

    bufferpoolUpdateAllocationPaddings(rdev->reader_buffer_pool,
                                       bufferpoolGetLargeBufferPadding(getWorkerBufferPool(getWID())),
                                       bufferpoolGetSmallBufferPadding(getWorkerBufferPool(getWID())));

    bufferpoolUpdateAllocationPaddings(rdev->writer_buffer_pool,
                                       bufferpoolGetLargeBufferPadding(getWorkerBufferPool(getWID())),
                                       bufferpoolGetSmallBufferPadding(getWorkerBufferPool(getWID())));

    rdev->up      = true;
    rdev->running = true;

    LOGD("RawDevice: device %s is now up", rdev->name);

    rdev->read_thread = threadCreate(rdev->routine_reader, rdev);

    rdev->write_thread = threadCreate(rdev->routine_writer, rdev);
    return true;
}

bool bringRawDeviceDown(raw_device_t *rdev)
{
    assert(rdev->up);

    rdev->running = false;
    rdev->up      = false;

    chanClose(rdev->writer_buffer_channel);

    LOGD("RawDevice: device %s is now down", rdev->name);

    threadJoin(rdev->read_thread);

    threadJoin(rdev->write_thread);

    sbuf_t *buf;
    while (0 == chanRecv(rdev->writer_buffer_channel, (void**)&buf))
    {
        bufferpoolReuseBuffer(rdev->reader_buffer_pool, buf);
    }

    return true;
}

raw_device_t *createRawDevice(const char *name, uint32_t mark, void *userdata, RawReadEventHandle cb)
{

    int rsocket = socket(PF_INET, SOCK_RAW, IPPROTO_RAW);
    if (rsocket < 0)
    {
        LOGE("RawDevice: unable to open a raw socket");
        return NULL;
    }

    if (mark != 0)
    {
        if (setsockopt(rsocket, SOL_SOCKET, SO_MARK, &mark, sizeof(mark)) != 0)
        {
            LOGE("RawDevice:  unable to set raw socket mark to %u", mark);
            return NULL;
        }
    }

    raw_device_t *rdev = memoryAllocate(sizeof(raw_device_t));

    buffer_pool_t *reader_bpool        = NULL;
    master_pool_t *reader_message_pool = NULL;
    // if the user really wanted to read from raw socket

    reader_bpool        = bufferpoolCreate(GSTATE.masterpool_buffer_pools_large, GSTATE.masterpool_buffer_pools_small,
                                           RAM_PROFILE, bufferpoolGetLargeBufferSize(getWorkerBufferPool(getWID())),
                                           bufferpoolGetSmallBufferSize(getWorkerBufferPool(getWID()))

           );
    reader_message_pool = masterpoolCreateWithCapacity(kMasterMessagePoosbufGetLeftCapacity);

    masterpoolInstallCallBacks(reader_message_pool, allocRawMsgPoolHandle, destroyRawMsgPoolHandle);

    buffer_pool_t *writer_bpool =
        bufferpoolCreate(GSTATE.masterpool_buffer_pools_large, GSTATE.masterpool_buffer_pools_small, RAM_PROFILE,
                         bufferpoolGetLargeBufferSize(getWorkerBufferPool(getWID())),
                         bufferpoolGetSmallBufferSize(getWorkerBufferPool(getWID()))

        );

    *rdev = (raw_device_t) {.name                  = stringDuplicate(name),
                            .running               = false,
                            .up                    = false,
                            .routine_reader        = routineReadFromRaw,
                            .routine_writer        = routineWriteToRaw,
                            .socket                = rsocket,
                            .mark                  = mark,
                            .read_event_callback   = cb,
                            .userdata              = userdata,
                            .writer_buffer_channel = chanInit(kRawWriteChannelQueueMax),
                            .reader_message_pool   = reader_message_pool,
                            .reader_buffer_pool    = reader_bpool,
                            .writer_buffer_pool    = writer_bpool};

    return rdev;
}

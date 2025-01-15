#include "generic_pool.h"
#include "wchan.h"
#include "loggers/internal_logger.h"
#include "raw.h"
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
    kReadPacketSize          = 1500,
    kMasterMessagePoosbufGetLeftCapacity    = 64,
    kRawWriteChannelQueueMax = 256
};

struct msg_event
{
    raw_device_t   *rdev;
    sbuf_t *buf;
};

static pool_item_t *allocRawMsgPoolHandle(struct master_pool_s *pool, void *userdata)
{
    (void) userdata;
    (void) pool;
    return memoryAllocate(sizeof(struct msg_event));
}

static void destroyRawMsgPoolHandle(struct master_pool_s *pool, master_pool_item_t *item, void *userdata)
{
    (void) pool;
    (void) userdata;
    memoryFree(item);
}

static void localThreadEventReceived(wevent_t *ev)
{
    struct msg_event *msg = weventGetUserdata(ev);
    tid_t             tid = (tid_t) (wloopTID(weventGetLoop(ev)));

    msg->rdev->read_event_callback(msg->rdev, msg->rdev->userdata, msg->buf, tid);

    reuseMasterPoolItems(msg->rdev->reader_message_pool, (void **) &msg, 1, msg->rdev);
}

static void distributePacketPayload(raw_device_t *rdev, tid_t target_tid, sbuf_t *buf)
{
    struct msg_event *msg;
    popMasterPoolItems(rdev->reader_message_pool, (const void **) &(msg), 1, rdev);

    *msg = (struct msg_event) {.rdev = rdev, .buf = buf};

    wevent_t ev;
    memorySet(&ev, 0, sizeof(ev));
    ev.loop = getWorkerLoop(target_tid);
    ev.cb   = localThreadEventReceived;
    weventSetUserData(&ev, msg);
    wloopPostEvent(getWorkerLoop(target_tid), &ev);
}

static HTHREAD_ROUTINE(routineReadFromRaw) // NOLINT
{
    raw_device_t   *rdev           = userdata;
    tid_t           distribute_tid = 0;
    sbuf_t *buf;
    ssize_t         nread;
    struct sockaddr saddr;
    int             saddr_len = sizeof(saddr);

    while (atomicLoadExplicit(&(rdev->running), memory_order_relaxed))
    {
        buf = bufferpoolPopSmall(rdev->reader_buffer_pool);

        buf = sbufReserveSpace(buf, kReadPacketSize);

        nread = recvfrom(rdev->socket, sbufGetMutablePtr(buf), kReadPacketSize, 0, &saddr, (socklen_t *) &saddr_len);

        if (nread == 0)
        {
            bufferpoolResuesbuf(rdev->reader_buffer_pool, buf);
            LOGW("RawDevice: Exit read routine due to End Of File");
            return 0;
        }

        if (nread < 0)
        {
            bufferpoolResuesbuf(rdev->reader_buffer_pool, buf);

            LOGE("RawDevice: reading a packet from RAW device failed, code: %d", (int) nread);
            if (errno == EINVAL || errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
            {
                continue;
            }
            LOGE("RawDevice: Exit read routine due to critical error");
            return 0;
        }

        sbufSetLength(buf, nread);

        distributePacketPayload(rdev, distribute_tid++, buf);

        if (distribute_tid >= WORKERS_COUNT)
        {
            distribute_tid = 0;
        }
    }

    return 0;
}

static HTHREAD_ROUTINE(routineWriteToRaw) // NOLINT
{
    raw_device_t   *rdev = userdata;
    sbuf_t *buf;
    ssize_t         nwrite;

    while (atomicLoadExplicit(&(rdev->running), memory_order_relaxed))
    {
        if (! chanRecv(rdev->writer_buffer_channel, &buf))
        {
            LOGD("RawDevice: routine write will exit due to channel closed");
            return 0;
        }

        assert(sbufGetBufLength(buf) > sizeof(struct iphdr));

        struct iphdr *ip_header = (struct iphdr *) sbufGetRawPtr(buf);

        struct sockaddr_in to_addr = {.sin_family = AF_INET, .sin_addr.s_addr = ip_header->daddr};

        nwrite = sendto(rdev->socket, ip_header, sbufGetBufLength(buf), 0, (struct sockaddr *) (&to_addr), sizeof(to_addr));

        bufferpoolResuesbuf(rdev->writer_buffer_pool, buf);

        if (nwrite == 0)
        {
            LOGW("RawDevice: Exit write routine due to End Of File");
            return 0;
        }

        if (nwrite < 0)
        {
            LOGW("RawDevice: writing a packet to RAW  device failed, code: %d", (int) nwrite);
            if (errno == EINVAL || errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
            {
                continue;
            }
            LOGE("RawDevice: Exit write routine due to critical error");
            return 0;
        }
    }
    return 0;
}

bool writeToRawDevce(raw_device_t *rdev, sbuf_t *buf)
{
    assert(sbufGetBufLength(buf) > sizeof(struct iphdr));

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

bool bringRawDeviceUP(raw_device_t *rdev)
{
    assert(! rdev->up);

    rdev->up      = true;
    rdev->running = true;

    LOGD("RawDevice: device %s is now up", rdev->name);

    if (rdev->read_event_callback != NULL)
    {
        rdev->read_thread = threadCreate(rdev->routine_reader, rdev);
    }
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

    if (rdev->read_event_callback != NULL)
    {
        threadJoin(rdev->read_thread);
    }
    threadJoin(rdev->write_thread);

    sbuf_t *buf;
    while (chanRecv(rdev->writer_buffer_channel, &buf))
    {
        bufferpoolResuesbuf(rdev->reader_buffer_pool, buf);
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

    buffer_pool_t  *reader_bpool        = NULL;
    master_pool_t  *reader_message_pool = NULL;
    if (cb != NULL)
    {
        // if the user really wanted to read from raw socket
       
        reader_bpool   = bufferpoolCreate(GSTATE.masterpool_buffer_pools_large, GSTATE.masterpool_buffer_pools_small,
                                           GSTATE.ram_profile);
        reader_message_pool = newMasterPoolWithCap(kMasterMessagePoosbufGetLeftCapacity);

        installMasterPoolAllocCallBacks(reader_message_pool, allocRawMsgPoolHandle, destroyRawMsgPoolHandle);
    }

    buffer_pool_t  *writer_bpool   = bufferpoolCreate(
        GSTATE.masterpool_buffer_pools_large, GSTATE.masterpool_buffer_pools_small,  GSTATE.ram_profile);

    *rdev = (raw_device_t) {.name                     = stringDuplicate(name),
                            .running                  = false,
                            .up                       = false,
                            .routine_reader           = routineReadFromRaw,
                            .routine_writer           = routineWriteToRaw,
                            .socket                   = rsocket,
                            .mark                     = mark,
                            .read_event_callback      = cb,
                            .userdata                 = userdata,
                            .writer_buffer_channel    = chanOpen(sizeof(void *), kRawWriteChannelQueueMax),
                            .reader_message_pool      = reader_message_pool,
                            .reader_buffer_pool       = reader_bpool,
                            .writer_buffer_pool       = writer_bpool};

    return rdev;
}

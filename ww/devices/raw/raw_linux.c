#include "generic_pool.h"
#include "global_state.h"
#include "loggers/internal_logger.h"
#include "raw.h"
#include "wchan.h"
#include "worker.h"
#include "wtime.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/ipv6.h>
#include <netinet/ip.h>
#include <poll.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

enum
{
    kRawWriteChannelQueueMax = 128 * 1024,
    kBatchSize               = 512,
    kRawSocketSendBuffer     = 16 * 1024 * 1024
};

typedef enum rawdevice_discard_reason_e
{
    kRawDeviceDiscardOversized,
    kRawDeviceDiscardMessageTooLarge
} rawdevice_discard_reason_t;

static void rawdeviceLogSocketBufferSize(int socket_fd, int option, const char *name)
{
    int       actual = 0;
    socklen_t len    = sizeof(actual);

    if (getsockopt(socket_fd, SOL_SOCKET, option, &actual, &len) != 0)
    {
        LOGW("RawDevice: failed to read actual %s: %s", name, strerror(errno));
        return;
    }

    LOGD("RawDevice: actual %s is %d bytes", name, actual);
}

static void rawdeviceRecordDiscard(raw_device_t *rdev, rawdevice_discard_reason_t reason)
{
    unsigned long long now_ms = getTimeOfDayMS();

    rdev->discarded_packet_total++;
    rdev->discarded_packet_suppressed++;
    if (reason == kRawDeviceDiscardOversized)
    {
        rdev->oversized_packet_total++;
    }
    else
    {
        rdev->message_too_large_packet_total++;
    }

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

    LOGW("RawDevice: discarded %llu packet(s) over %llums "
         "(total=%llu, exceeding kMaxAllowedPacketLength=%u: %llu, EMSGSIZE=%llu)",
         LLU(rdev->discarded_packet_suppressed),
         LLU(elapsed_ms),
         LLU(rdev->discarded_packet_total),
         (unsigned int) kMaxAllowedPacketLength,
         LLU(rdev->oversized_packet_total),
         LLU(rdev->message_too_large_packet_total));
    rdev->discarded_packet_suppressed = 0;
    rdev->discard_last_report_ms      = now_ms;
}

static void rawdeviceReportPendingDiscards(raw_device_t *rdev)
{
    if (rdev->discarded_packet_suppressed == 0)
    {
        return;
    }

    LOGW("RawDevice: discarded %llu packet(s) before writer exit "
         "(total=%llu, exceeding kMaxAllowedPacketLength=%u: %llu, EMSGSIZE=%llu)",
         LLU(rdev->discarded_packet_suppressed),
         LLU(rdev->discarded_packet_total),
         (unsigned int) kMaxAllowedPacketLength,
         LLU(rdev->oversized_packet_total),
         LLU(rdev->message_too_large_packet_total));
    rdev->discarded_packet_suppressed = 0;
}

static bool rawdevicePrepareSendMessage(raw_device_t       *rdev,
                                        sbuf_t             *buf,
                                        struct mmsghdr     *msg,
                                        struct iovec       *iov,
                                        struct sockaddr_in *addr)
{
    uint32_t packet_len = sbufGetLength(buf);
    if (UNLIKELY(packet_len > kMaxAllowedPacketLength))
    {
        rawdeviceRecordDiscard(rdev, kRawDeviceDiscardOversized);
        bufferpoolReuseBuffer(rdev->writer_buffer_pool, buf);
        return false;
    }

    struct iphdr *ip_header = (struct iphdr *) sbufGetRawPtr(buf);

    memoryZero(addr, sizeof(*addr));
    addr->sin_family      = AF_INET;
    addr->sin_addr.s_addr = ip_header->daddr;

    iov->iov_base = (void *) ip_header;
    iov->iov_len  = packet_len;

    memoryZero(msg, sizeof(*msg));
    msg->msg_hdr.msg_name    = addr;
    msg->msg_hdr.msg_namelen = sizeof(*addr);
    msg->msg_hdr.msg_iov     = iov;
    msg->msg_hdr.msg_iovlen  = 1;
    return true;
}

static void rawdeviceReuseBatchRange(raw_device_t *rdev, sbuf_t **bufs, int begin, int end)
{
    for (int i = begin; i < end; ++i)
    {
        bufferpoolReuseBuffer(rdev->writer_buffer_pool, bufs[i]);
    }
}

static WTHREAD_ROUTINE(routineWriteToRaw) // NOLINT
{
    raw_device_t *rdev = userdata;
    sbuf_t       *buf;

    struct mmsghdr     msgs[kBatchSize];
    struct iovec       iovs[kBatchSize];
    struct sockaddr_in addrs[kBatchSize];
    sbuf_t            *bufs[kBatchSize];

    while (atomicLoadExplicit(&(rdev->running), memory_order_relaxed))
    {
        if (! chanRecv(rdev->writer_buffer_channel, (void **) &buf))
        {
            LOGD("RawDevice: routine write will exit due to channel closed");
            break;
        }

        int cnt = 0;
        if (rawdevicePrepareSendMessage(rdev, buf, &msgs[cnt], &iovs[cnt], &addrs[cnt]))
        {
            bufs[cnt] = buf;
            cnt++;
        }

        for (int i = 1; i < kBatchSize; ++i)
        {
            sbuf_t *b2     = NULL;
            bool    closed = false;
            if (! chanTryRecv(rdev->writer_buffer_channel, (void **) &b2, &closed))
            {
                if (closed)
                {
                    break;
                }
                break;
            }

            if (rawdevicePrepareSendMessage(rdev, b2, &msgs[cnt], &iovs[cnt], &addrs[cnt]))
            {
                bufs[cnt] = b2;
                cnt++;
            }
        }

        if (cnt == 0)
        {
            continue;
        }

        int sent = 0;
        while (sent < cnt)
        {
            if (! atomicLoadExplicit(&(rdev->running), memory_order_relaxed))
            {
                rawdeviceReuseBatchRange(rdev, bufs, sent, cnt);
                break;
            }

            int res = sendmmsg(rdev->socket, &msgs[sent], cnt - sent, 0);
            if (res > 0)
            {
                // res messages were consumed
                rawdeviceReuseBatchRange(rdev, bufs, sent, sent + res);
                sent += res;
                continue;
            }

            int err = errno;
            if (res == -1 && (err == EINTR))
            {
                continue;
            }
            if (res == -1 && (err == EAGAIN || err == EWOULDBLOCK))
            {

                struct pollfd pfd = {.fd = rdev->socket, .events = POLLOUT};
                int           pr  = poll(&pfd, 1, 50 /*ms timeout*/);
                if (pr <= 0)
                {
                    // either timeout, error, or still not writable; continue loop to retry
                    continue;
                }
                continue; // socket writable — try sendmmsg again
            }

            if (res == -1 && err == EMSGSIZE)
            {
                rawdeviceRecordDiscard(rdev, kRawDeviceDiscardMessageTooLarge);
                bufferpoolReuseBuffer(rdev->writer_buffer_pool, bufs[sent]);
                sent++;
                continue;
            }

            LOGW("RawDevice: sendmmsg() failed with error: %s", strerror(err));
            rawdeviceReuseBatchRange(rdev, bufs, sent, cnt);
            break;
        }
    }

    rawdeviceReportPendingDiscards(rdev);
    return 0;
}

bool rawdeviceWrite(raw_device_t *rdev, sbuf_t *buf)
{
    assert(sbufGetLength(buf) > sizeof(struct iphdr));

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

    LOGD("RawDevice: device %s is now up", rdev->name);

    // rdev->read_thread = threadCreate(rdev->routine_reader, rdev);

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

    LOGD("RawDevice: device %s is now down", rdev->name);

    return true;
}

raw_device_t *rawdeviceCreate(const char *name, uint32_t mark, void *userdata)
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
            close(rsocket);
            return NULL;
        }
    }
    int one = 1;
    if (setsockopt(rsocket, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0)
    {
        perror("setsockopt IP_HDRINCL");
        terminateProgram(1);
    }
    int flags = fcntl(rsocket, F_GETFL, 0);
    if (flags < 0)
    {
        LOGE("RawDevice: unable to get raw socket flags: %s", strerror(errno));
        close(rsocket);
        return NULL;
    }
    if (fcntl(rsocket, F_SETFL, flags | O_NONBLOCK) < 0)
    {
        LOGE("RawDevice: unable to set raw socket nonblocking mode: %s", strerror(errno));
        close(rsocket);
        return NULL;
    }

    int sndbuf = kRawSocketSendBuffer;
    if (setsockopt(rsocket, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf)) < 0)
    {
        LOGW("RawDevice: failed to set SO_SNDBUF: %s", strerror(errno));
    }
    rawdeviceLogSocketBufferSize(rsocket, SO_SNDBUF, "SO_SNDBUF");

    raw_device_t *rdev = memoryAllocate(sizeof(raw_device_t));

    buffer_pool_t *writer_bpool = bufferpoolCreate(GSTATE.masterpool_buffer_pools_large,
                                                   GSTATE.masterpool_buffer_pools_small,
                                                   RAM_PROFILE,
                                                   bufferpoolGetLargeBufferSize(getWorkerBufferPool(getWID())),
                                                   bufferpoolGetSmallBufferSize(getWorkerBufferPool(getWID()))

    );

    *rdev = (raw_device_t) {.name                  = stringDuplicate(name),
                            .running               = false,
                            .up                    = false,
                            .routine_writer        = routineWriteToRaw,
                            .socket                = rsocket,
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
    close(rdev->socket);
    memoryFree(rdev);
}

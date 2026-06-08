#include "generic_pool.h"
#include "global_state.h"
#include "loggers/internal_logger.h"
#include "raw.h"
#include "wchan.h"
#include "worker.h"
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
    kMaxWriteablePacketSize  = 1500,
    kRawWriteChannelQueueMax = 128 * 1024,
    kBatchSize               = 512,
    kRawSocketSendBuffer     = 16 * 1024 * 1024
};

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
            return 0;
        }

        int cnt  = 0;
        int len0 = sbufGetLength(buf);
        if (UNLIKELY(kMaxAllowedPacketLength < len0))
        {
            LOGE("RawDevice: WriteThread: Packet size %d exceeds kMaxAllowedPacketLength %d",
                 len0,
                 kMaxAllowedPacketLength);
            LOGF("RawDevice: This is related to the MTU size, (core.json) please set a correct value for 'mtu' in the "
                 "'misc' section");
            bufferpoolReuseBuffer(rdev->writer_buffer_pool, buf);
            terminateProgram(1);
        }

        struct iphdr *ip_header0 = (struct iphdr *) sbufGetRawPtr(buf);

        memorySet(&addrs[0], 0, sizeof(addrs[0]));
        addrs[0].sin_family      = AF_INET;
        addrs[0].sin_addr.s_addr = ip_header0->daddr;

        iovs[0].iov_base = (void *) ip_header0;
        iovs[0].iov_len  = len0;

        memorySet(&msgs[0], 0, sizeof(msgs[0]));
        msgs[0].msg_hdr.msg_name    = &addrs[0];
        msgs[0].msg_hdr.msg_namelen = sizeof(addrs[0]);
        msgs[0].msg_hdr.msg_iov     = &iovs[0];
        msgs[0].msg_hdr.msg_iovlen  = 1;

        bufs[0] = buf;
        cnt     = 1;

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

            if (UNLIKELY(kMaxWriteablePacketSize < sbufGetLength(b2)))
            {
                LOGE("RawDevice: WriteThread: Packet size %d exceeds kMaxWriteablePacketSize %d",
                     sbufGetLength(b2),
                     kMaxWriteablePacketSize);
                bufferpoolReuseBuffer(rdev->writer_buffer_pool, b2);
                terminateProgram(1);
            }

            struct iphdr *ip_header = (struct iphdr *) sbufGetRawPtr(b2);
            memorySet(&addrs[i], 0, sizeof(addrs[i]));
            addrs[i].sin_family      = AF_INET;
            addrs[i].sin_addr.s_addr = ip_header->daddr;
            iovs[i].iov_base         = (void *) ip_header;
            iovs[i].iov_len          = sbufGetLength(b2);
            memorySet(&msgs[i], 0, sizeof(msgs[i]));
            msgs[i].msg_hdr.msg_name    = &addrs[i];
            msgs[i].msg_hdr.msg_namelen = sizeof(addrs[i]);
            msgs[i].msg_hdr.msg_iov     = &iovs[i];
            msgs[i].msg_hdr.msg_iovlen  = 1;

            bufs[i] = b2;
            cnt++;
        }

        int sent = 0;
        while (sent < cnt)
        {
            int res = sendmmsg(rdev->socket, &msgs[sent], cnt - sent, 0);
            if (res > 0)
            {
                // res messages were consumed
                for (int k = 0; k < res; ++k)
                {
                    bufferpoolReuseBuffer(rdev->writer_buffer_pool, bufs[sent + k]);
                }
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

            // Fatal
            LOGW("RawDevice: sendmmsg() failed with error: %s", strerror(err));
            if (err == EMSGSIZE)
            {
                LOGF("RawDevice: This is related to the MTU size, (core.json) please set a correct value for 'mtu' in "
                     "the 'misc' section");
                terminateProgram(1);
            }

            // On other errors: reuse/free remaining buffers and break out
            for (int k = sent; k < cnt; ++k)
            {
                bufferpoolReuseBuffer(rdev->writer_buffer_pool, bufs[k]);
            }
            break;
        }
    }
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

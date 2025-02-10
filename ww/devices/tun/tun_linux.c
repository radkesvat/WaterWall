#include "generic_pool.h"
#include "global_state.h"
#include "loggers/internal_logger.h"
#include "tun.h"
#include "wchan.h"
#include "wproc.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <linux/ipv6.h>
#include <netinet/ip.h>
#include <sys/ioctl.h>

struct msg_event
{
    tun_device_t *tdev;
    sbuf_t       *buf;
};

// Function to print IP packet information
static void printIPPacketInfo(const char *devname, const unsigned char *buffer)
{
    char  src_ip[INET6_ADDRSTRLEN];
    char  dst_ip[INET6_ADDRSTRLEN];
    char  logbuf[256];
    int   rem = sizeof(logbuf);
    char *ptr = logbuf;
    int   ret;

    uint8_t version = buffer[0] >> 4;

    if (version == 4)
    {
        struct iphdr *ip_header = (struct iphdr *) buffer;
        inet_ntop(AF_INET, &ip_header->saddr, src_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &ip_header->daddr, dst_ip, INET_ADDRSTRLEN);
        ret = snprintf(ptr, rem, "TunDevice: %s => From %s to %s, Data: ", devname, src_ip, dst_ip);
    }
    else if (version == 6)
    {
        struct ipv6hdr *ip6_header = (struct ipv6hdr *) buffer;
        inet_ntop(AF_INET6, &ip6_header->saddr, src_ip, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, &ip6_header->daddr, dst_ip, INET6_ADDRSTRLEN);
        ret = snprintf(ptr, rem, "TunDevice: %s => From %s to %s, Data: ", devname, src_ip, dst_ip);
    }
    else
    {
        ret = snprintf(ptr, rem, "TunDevice: %s => Unknown IP version, Data: ", devname);
    }

    ptr += ret;
    rem -= ret;

    for (int i = 0; i < 16; i++)
    {
        ret = snprintf(ptr, rem, "%02x ", buffer[i]);
        ptr += ret;
        rem -= ret;
    }
    *ptr = '\0';

    LOGD(logbuf);
}

// Allocate memory for message pool handle
static pool_item_t *allocTunMsgPoolHandle(master_pool_t *pool, void *userdata)
{
    (void) userdata;
    (void) pool;
    return memoryAllocate(sizeof(struct msg_event));
}

// Free memory for message pool handle
static void destroyTunMsgPoolHandle(master_pool_t *pool, master_pool_item_t *item, void *userdata)
{
    (void) pool;
    (void) userdata;
    memoryFree(item);
}

// Handle local thread event
static void localThreadEventReceived(wevent_t *ev)
{
    struct msg_event *msg = weventGetUserdata(ev);
    wid_t             tid = (wid_t) (wloopTID(weventGetLoop(ev)));

    msg->tdev->read_event_callback(msg->tdev, msg->tdev->userdata, msg->buf, tid);
    masterpoolReuseItems(msg->tdev->reader_message_pool, (void **) &msg, 1, msg->tdev);
}

// Distribute packet payload to the target thread
static void distributePacketPayload(tun_device_t *tdev, wid_t target_tid, sbuf_t *buf)
{
    struct msg_event *msg;
    masterpoolGetItems(tdev->reader_message_pool, (const void **) &(msg), 1, tdev);

    *msg = (struct msg_event){.tdev = tdev, .buf = buf};

    wevent_t ev;
    memorySet(&ev, 0, sizeof(ev));
    ev.loop = getWorkerLoop(target_tid);
    ev.cb   = localThreadEventReceived;
    weventSetUserData(&ev, msg);
    wloopPostEvent(getWorkerLoop(target_tid), &ev);
}

// Routine to read from TUN device
static WTHREAD_ROUTINE(routineReadFromTun)
{
    tun_device_t *tdev           = userdata;
    wid_t         distribute_tid = 0;
    sbuf_t       *buf;
    ssize_t       nread;

    while (atomicLoadExplicit(&(tdev->running), memory_order_relaxed))
    {
        buf = bufferpoolGetSmallBuffer(tdev->reader_buffer_pool);
        assert(sbufGetRightCapacity(buf) >= kReadPacketSize);

        nread = read(tdev->handle, sbufGetMutablePtr(buf), kReadPacketSize);

        if (nread == 0)
        {
            bufferpoolReuseBuffer(tdev->reader_buffer_pool, buf);
            LOGW("TunDevice: Exit read routine due to End Of File");
            return 0;
        }

        if (nread < 0)
        {
            bufferpoolReuseBuffer(tdev->reader_buffer_pool, buf);
            LOGE("TunDevice: reading a packet from TUN device failed, code: %d", (int) nread);
            if (errno == EINVAL || errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
            {
                continue;
            }
            LOGE("TunDevice: Exit read routine due to critical error");
            return 0;
        }

        sbufSetLength(buf, nread);

        if (TUN_LOG_EVERYTHING)
        {
            LOGD("TunDevice: read %zd bytes from device %s", nread, tdev->name);
        }

        distributePacketPayload(tdev, distribute_tid++, buf);

        if (distribute_tid >= getWorkersCount())
        {
            distribute_tid = 0;
        }
    }

    return 0;
}

// Routine to write to TUN device
static WTHREAD_ROUTINE(routineWriteToTun)
{
    tun_device_t *tdev = userdata;
    sbuf_t       *buf;
    ssize_t       nwrite;

    while (atomicLoadExplicit(&(tdev->running), memory_order_relaxed))
    {
        if (! chanRecv(tdev->writer_buffer_channel, (void *) &buf))
        {
            LOGD("TunDevice: routine write will exit due to channel closed");
            return 0;
        }

        assert(sbufGetBufLength(buf) > sizeof(struct iphdr));

        nwrite = write(tdev->handle, sbufGetRawPtr(buf), sbufGetBufLength(buf));
        bufferpoolReuseBuffer(tdev->writer_buffer_pool, buf);

        if (nwrite == 0)
        {
            LOGW("TunDevice: Exit write routine due to End Of File");
            return 0;
        }

        if (nwrite < 0)
        {
            LOGW("TunDevice: writing a packet to TUN device failed, code: %d", (int) nwrite);
            if (errno == EINVAL || errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
            {
                continue;
            }
            LOGE("TunDevice: Exit write routine due to critical error");
            return 0;
        }
    }
    return 0;
}

// Write to TUN device
bool tundeviceWrite(tun_device_t *tdev, sbuf_t *buf)
{
    assert(sbufGetBufLength(buf) > sizeof(struct iphdr));
    if (atomicLoadRelaxed(&(tdev->running)) == false)
    {
        LOGE("Write failed, device is not running");
        return false;
    }

    bool closed = false;
    if (! chanTrySend(tdev->writer_buffer_channel, (void *) &buf, &closed))
    {
        if (closed)
        {
            LOGE("TunDevice: write failed, channel was closed");
        }
        else
        {
            LOGE("TunDevice: write failed, ring is full");
        }
        return false;
    }
    return true;
}

// Unassign IP address from TUN device
bool tundeviceUnAssignIP(tun_device_t *tdev, const char *ip_presentation, unsigned int subnet)
{
    char command[128];

    snprintf(command, sizeof(command), "ip addr del %s/%d  dev %s", ip_presentation, subnet, tdev->name);
    if (execCmd(command).exit_code != 0)
    {
        LOGE("TunDevice: error unassigning ip address");
        return false;
    }
    LOGD("TunDevice: ip address removed from %s", tdev->name);
    return true;
}

// Assign IP address to TUN device
bool tundeviceAssignIP(tun_device_t *tdev, const char *ip_presentation, unsigned int subnet)
{
    char command[128];

    snprintf(command, sizeof(command), "ip addr add %s/%d dev %s", ip_presentation, subnet, tdev->name);
    if (execCmd(command).exit_code != 0)
    {
        LOGE("TunDevice: error setting ip address");
        return false;
    }
    LOGD("TunDevice: ip address %s/%d assigned to dev %s", ip_presentation, subnet, tdev->name);
    return true;
}

// Bring TUN device up
bool tundeviceBringUp(tun_device_t *tdev)
{
    if (tdev->up)
    {
        LOGE("TunDevice: device is already up");
        return false;
    }

    tdev->up = true;
    atomicStoreRelaxed(&(tdev->running), true);

    tdev->writer_buffer_channel = chanOpen(sizeof(void *), kTunWriteChannelQueueMax);

    char command[128];
    snprintf(command, sizeof(command), "ip link set dev %s up", tdev->name);
    if (execCmd(command).exit_code != 0)
    {
        LOGE("TunDevice: error bringing device %s up", tdev->name);
        return false;
    }
    LOGD("TunDevice: device %s is now up", tdev->name);

    if (tdev->read_event_callback != NULL)
    {
        tdev->read_thread = threadCreate(tdev->routine_reader, tdev);
    }
    tdev->write_thread = threadCreate(tdev->routine_writer, tdev);
    return true;
}

// Bring TUN device down
bool tundeviceBringDown(tun_device_t *tdev)
{
    if (! tdev->up)
    {
        LOGE("TunDevice: device is already down");
        return false;
    }

    atomicStoreRelaxed(&(tdev->running), false);
    tdev->up = false;

    chanClose(tdev->writer_buffer_channel);
    sbuf_t *buf;

    while (chanRecv(tdev->writer_buffer_channel, (void *) &buf))
    {
        bufferpoolReuseBuffer(tdev->reader_buffer_pool, buf);
    }
    tdev->writer_buffer_channel = NULL;

    char command[128];
    snprintf(command, sizeof(command), "ip link set dev %s down", tdev->name);
    if (execCmd(command).exit_code != 0)
    {
        LOGE("TunDevice: error bringing %s down", tdev->name);
        return false;
    }
    LOGD("TunDevice: device %s is now down", tdev->name);

    if (tdev->read_event_callback != NULL)
    {
        threadJoin(tdev->read_thread);
    }
    threadJoin(tdev->write_thread);

    return true;
}

// Create TUN device
tun_device_t *tundeviceCreate(const char *name, bool offload, void *userdata, TunReadEventHandle cb)
{
    (void) offload; // todo (send/receive offloading)

    struct ifreq ifr;

    int fd = open("/dev/net/tun", O_RDWR);
    if (fd < 0)
    {
        LOGE("TunDevice: opening /dev/net/tun failed");
        return NULL;
    }

    memorySet(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI; // TUN device, no packet information
    if (*name)
    {
        stringCopyN(ifr.ifr_name, name, IFNAMSIZ);
        ifr.ifr_name[IFNAMSIZ - 1] = '\0';
    }

    int err = ioctl(fd, TUNSETIFF, (void *) &ifr);
    if (err < 0)
    {
        LOGE("TunDevice: ioctl(TUNSETIFF) failed");
        close(fd);
        return NULL;
    }

    buffer_pool_t *reader_bpool =
        bufferpoolCreate(GSTATE.masterpool_buffer_pools_large, GSTATE.masterpool_buffer_pools_small,
                         (0) + GSTATE.ram_profile, bufferpoolGetLargeBufferSize(getWorkerBufferPool(getWID())),
                         bufferpoolGetSmallBufferSize(getWorkerBufferPool(getWID()))

        );

    buffer_pool_t *writer_bpool =
        bufferpoolCreate(GSTATE.masterpool_buffer_pools_large, GSTATE.masterpool_buffer_pools_small,
                         (0) + GSTATE.ram_profile, bufferpoolGetLargeBufferSize(getWorkerBufferPool(getWID())),
                         bufferpoolGetSmallBufferSize(getWorkerBufferPool(getWID()))

        );
    
    bufferpoolUpdateAllocationPaddings(reader_bpool, bufferpoolGetLargeBufferPadding(getWorkerBufferPool(getWID())), 
    bufferpoolGetSmallBufferPadding(getWorkerBufferPool(getWID())));

    bufferpoolUpdateAllocationPaddings(writer_bpool, bufferpoolGetLargeBufferPadding(getWorkerBufferPool(getWID())), 
    bufferpoolGetSmallBufferPadding(getWorkerBufferPool(getWID())));

    tun_device_t *tdev = memoryAllocate(sizeof(tun_device_t));

    *tdev = (tun_device_t){.name                  = stringDuplicate(ifr.ifr_name),
                           .running               = false,
                           .up                    = false,
                           .routine_reader        = routineReadFromTun,
                           .routine_writer        = routineWriteToTun,
                           .handle                = fd,
                           .read_event_callback   = cb,
                           .userdata              = userdata,
                           .writer_buffer_channel = NULL,
                           .reader_message_pool   = masterpoolCreateWithCapacity(kMasterMessagePoosbufGetLeftCapacity),
                           .reader_buffer_pool    = reader_bpool,
                           .writer_buffer_pool    = writer_bpool};

    masterpoolInstallCallBacks(tdev->reader_message_pool, allocTunMsgPoolHandle, destroyTunMsgPoolHandle);

    return tdev;
}
// Destroy TUN device
void tundeviceDestroy(tun_device_t *tdev)
{
    if (tdev->up)
    {
        tundeviceBringDown(tdev);
    }
    memoryFree(tdev->name);
    bufferpoolDestroy(tdev->reader_buffer_pool);
    bufferpoolDestroy(tdev->writer_buffer_pool);
    masterpoolDestroy(tdev->reader_message_pool);
    close(tdev->handle);
    memoryFree(tdev);
}

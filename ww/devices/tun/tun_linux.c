#include "generic_pool.h"
#include "hchan.h"
#include "loggers/network_logger.h"
#include "tun.h"
#include "utils/procutils.h"
#include "ww.h"
#include <arpa/inet.h>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <netinet/ip.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

enum
{
    kReadPacketSize          = 1500,
    kMasterMessagePoolCap    = 64,
    kTunWriteChannelQueueMax = 128
};

struct msg_event
{
    tun_device_t   *tdev;
    shift_buffer_t *buf;
};

static void printIPPacketInfo(const char *devname, const unsigned char *buffer)
{
    struct iphdr *ip_header = (struct iphdr *) buffer;
    char          src_ip[INET_ADDRSTRLEN];
    char          dst_ip[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, &ip_header->saddr, src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &ip_header->daddr, dst_ip, INET_ADDRSTRLEN);

    char  logbuf[128];
    int   rem = sizeof(logbuf);
    char *ptr = logbuf;
    int   ret = snprintf(ptr, rem, "TunDevice: %s => From %s to %s, Data:", devname, src_ip, dst_ip);
    ptr += ret;
    rem -= ret;
    for (int i = sizeof(struct iphdr); i < 10; i++)
    {
        ret = snprintf(ptr, rem, "%02x ", buffer[i]);
        ptr += ret;
        rem -= ret;
    }
    LOGD(logbuf);
}

static pool_item_t *allocTunMsgPoolHandle(struct master_pool_s *pool, void *userdata)
{
    (void) userdata;
    (void) pool;
    return globalMalloc(sizeof(struct msg_event));
}

static void destroyTunMsgPoolHandle(struct master_pool_s *pool, master_pool_item_t *item, void *userdata)
{
    (void) pool;
    (void) userdata;
    globalFree(item);
}

static void localThreadEventReceived(hevent_t *ev)
{
    struct msg_event *msg = hevent_userdata(ev);
    tid_t             tid = (tid_t) (hloop_tid(hevent_loop(ev)));

    msg->tdev->read_event_callback(msg->tdev, msg->tdev->userdata, msg->buf, tid);

    reuseMasterPoolItems(msg->tdev->reader_message_pool, (void **) &msg, 1);
}

static void distributePacketPayload(tun_device_t *tdev, tid_t target_tid, shift_buffer_t *buf)
{
    struct msg_event *msg;
    popMasterPoolItems(tdev->reader_message_pool, (const void **) &(msg), 1);

    *msg = (struct msg_event) {.tdev = tdev, .buf = buf};

    hevent_t ev;
    memset(&ev, 0, sizeof(ev));
    ev.loop = getWorkerLoop(target_tid);
    ev.cb   = localThreadEventReceived;
    hevent_set_userdata(&ev, msg);
    hloop_post_event(getWorkerLoop(target_tid), &ev);
}

static HTHREAD_ROUTINE(routineReadFromTun) // NOLINT
{
    tun_device_t   *tdev           = userdata;
    tid_t           distribute_tid = 0;
    shift_buffer_t *buf;
    ssize_t         nread;

    while (atomic_load_explicit(&(tdev->running), memory_order_relaxed))
    {
        buf = popSmallBuffer(tdev->reader_buffer_pool);

        reserveBufSpace(buf, kReadPacketSize);

        nread = read(tdev->handle, rawBufMut(buf), kReadPacketSize);

        if (nread < 0)
        {
            LOGE("TunDevice: reading from TUN device failed");
            reuseBuffer(tdev->reader_buffer_pool, buf);
            return 0;
        }

        setLen(buf, nread);

        if (TUN_LOG_EVERYTHING)
        {
            LOGD("TunDevice: read %zd bytes from device %s", nread, tdev->name);
        }

        distributePacketPayload(tdev, distribute_tid++, buf);

        if (distribute_tid >= WORKERS_COUNT)
        {
            distribute_tid = 0;
        }
    }

    return 0;
}

static HTHREAD_ROUTINE(routineWriteToTun) // NOLINT
{
    tun_device_t   *tdev = userdata;
    shift_buffer_t *buf;
    ssize_t         nwrite;

    while (atomic_load_explicit(&(tdev->running), memory_order_relaxed))
    {
        if (! hchanRecv(tdev->writer_buffer_channel, &buf))
        {
            LOGD("TunDevice: routine write will exit due to channel closed");
            return 0;
        }

        if (! atomic_load_explicit(&(tdev->running), memory_order_relaxed))
        {
            reuseBufferThreadSafe(buf);
            return 0;
        }

        nwrite = write(tdev->handle, rawBuf(buf), bufLen(buf));

        reuseBufferThreadSafe(buf);

        if (nwrite < 0)
        {
            LOGE("TunDevice: writing to TUN device failed");
            return 0;
        }
    }
    return 0;
}

bool unAssignIpToTunDevice(tun_device_t *tdev, const char *ip_presentation, int subnet)
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

bool assignIpToTunDevice(tun_device_t *tdev, const char *ip_presentation, int subnet)
{
    char command[128];

    snprintf(command, sizeof(command), "ip addr add %s/%d dev %s", ip_presentation, subnet, tdev->name);
    if (execCmd(command).exit_code != 0)
    {
        LOGF("TunDevice: error setting ip address");
        return false;
    }
    LOGD("TunDevice: ip address %s/%d assigned to dev %s", ip_presentation, subnet, tdev->name);
    return true;
}

bool bringTunDeviceUP(tun_device_t *tdev)
{
    assert(! tdev->up);

    tdev->up      = true;
    tdev->running = true;

    char command[128];
    snprintf(command, sizeof(command), "ip link set dev %s up", tdev->name);
    if (execCmd(command).exit_code != 0)
    {
        LOGF("TunDevice: error bringing device %s up", tdev->name);
        return false;
    }
    LOGD("TunDevice: device %s is now up", tdev->name);

    tdev->read_thread  = hthread_create(tdev->routine_reader, tdev);
    tdev->write_thread = hthread_create(tdev->routine_writer, tdev);
    return true;
}

bool bringTunDeviceDown(tun_device_t *tdev)
{
    assert(tdev->up);

    tdev->running = false;
    tdev->up      = false;

    hchanClose(tdev->writer_buffer_channel);

    char command[128];

    snprintf(command, sizeof(command), "ip link set dev %s down", tdev->name);
    if (execCmd(command).exit_code != 0)
    {
        LOGF("TunDevice: error bringing %s down", tdev->name);
        return false;
    }
    LOGD("TunDevice: device %s is now down", tdev->name);

    hthread_join(tdev->read_thread);
    hthread_join(tdev->write_thread);

    shift_buffer_t *buf;
    while (hchanRecv(tdev->writer_buffer_channel, &buf))
    {
        reuseBufferThreadSafe(buf);
    }

    return true;
}

tun_device_t *createTunDevice(const char *name, bool offload, void *userdata, TunReadEventHandle cb)
{
    (void) offload; // todo (send/receive offloading)

    struct ifreq ifr;

    int fd = open("/dev/net/tun", O_RDWR);
    if (fd < 0)
    {
        LOGF("TunDevice: opening /dev/net/tun failed");
        return NULL;
    }

    memset(&ifr, 0, sizeof(ifr));

    ifr.ifr_flags = IFF_TUN | IFF_NO_PI; // TUN device, no packet information
    if (*name)
    {
        strncpy(ifr.ifr_name, name, IFNAMSIZ);
    }

    int err = ioctl(fd, TUNSETIFF, (void *) &ifr);
    if (err < 0)
    {
        LOGF("TunDevice: ioctl(TUNSETIFF) failed");
        close(fd);
        return NULL;
    }

    generic_pool_t *sb_pool = newGenericPoolWithCap(GSTATE.masterpool_shift_buffer_pools, (64) + GSTATE.ram_profile,
                                                    allocShiftBufferPoolHandle, destroyShiftBufferPoolHandle);
    buffer_pool_t  *bpool   = createBufferPool(GSTATE.masterpool_buffer_pools_large, GSTATE.masterpool_buffer_pools_small, sb_pool);

    tun_device_t *tdev = globalMalloc(sizeof(tun_device_t));

    *tdev = (tun_device_t) {.name                     = strdup(ifr.ifr_name),
                            .running                  = false,
                            .up                       = false,
                            .handle                   = fd,
                            .reader_shift_buffer_pool = sb_pool,
                            .read_event_callback      = cb,
                            .userdata                 = userdata,
                            .writer_buffer_channel    = hchanOpen(sizeof(void *), kTunWriteChannelQueueMax),
                            .reader_message_pool      = newMasterPoolWithCap(kMasterMessagePoolCap),
                            .reader_buffer_pool       = bpool};

    installMasterPoolAllocCallbacks(tdev->reader_message_pool, tdev, allocTunMsgPoolHandle, destroyTunMsgPoolHandle);

    return tdev;
}

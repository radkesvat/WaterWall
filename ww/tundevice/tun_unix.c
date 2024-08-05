#include "generic_pool.h"
#include "hchan.h"
#include "loggers/network_logger.h"
#include "tun.h"
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
    kReadPacketSize       = 1500,
    kMasterMessagePoolCap = 64
};

struct msg_event
{
    tun_device_t   *tdev;
    shift_buffer_t *buf;
};

static void printPacketInfo(const unsigned char *buffer, int length)
{
    struct iphdr *ip_header = (struct iphdr *) buffer;
    char          src_ip[INET_ADDRSTRLEN];
    char          dst_ip[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, &ip_header->saddr, src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &ip_header->daddr, dst_ip, INET_ADDRSTRLEN);

    printf("From %s to %s, Data: ", src_ip, dst_ip);
    for (int i = sizeof(struct iphdr); i < length; i++)
    {
        printf("%02x ", buffer[i]);
    }
    printf("\n");
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

    *msg = (struct msg_event){.tdev = tdev, .buf = buf};

    hevent_t ev;
    memset(&ev, 0, sizeof(ev));
    ev.loop = getWorkerLoop(target_tid);
    ev.cb   = localThreadEventReceived;
    hevent_set_userdata(&ev, msg);
    hloop_post_event(getWorkerLoop(target_tid), &ev);
}

static HTHREAD_ROUTINE(routineWriteToTun) // NOLINT
{
    tun_device_t *tdev = userdata;

    tid_t distribute_tid = 0;

    while (atomic_load_explicit(&(tdev->notstop), memory_order_relaxed))
    {
        shift_buffer_t *buf = popSmallBuffer(tdev->reader_buffer_pool);

        reserveBufSpace(buf, kReadPacketSize);

        ssize_t nread = read(tdev->handle, rawBufMut(buf), kReadPacketSize);

        if (nread < 0)
        {
            LOGF("Reading from TUN device");
            exit(1);
        }

        if (TUN_LOG_EVERYTHING)
        {
            LOGD("Read %zd bytes from device %s\n", nread, tdev->name);
        }

        distributePacketPayload(tdev, distribute_tid++, buf);

        if (distribute_tid >= WORKERS_COUNT)
        {
            distribute_tid = 0;
        }
    }

    return 0;
}

static HTHREAD_ROUTINE(routineReadFromTun) // NOLINT
{
    tun_device_t *tdev = userdata;
    while (atomic_load_explicit(&(tdev->notstop), memory_order_relaxed))
    {
    }
    return 0;
}

void bringTunDeviceUP(tun_device_t *tdev)
{
    assert(! tdev->up);

    tdev->up      = true;
    tdev->notstop = true;
    hthread_create(tdev->routine_reader, tdev);
    hthread_create(tdev->routine_writer, tdev);
}

tun_device_t *createTunDevice(const char *name, bool offload, void *userdata, TunReadEventHandle cb)
{
    (void) offload; // todo (send/receive offloading)

    struct ifreq ifr;

    int fd = open("/tdev/net/tun", O_RDWR);
    if (fd < 0)
    {
        perror("Opening /tdev/net/tun");
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
        perror("ioctl(TUNSETIFF)");
        close(fd);
        return NULL;
    }

    generic_pool_t *sb_pool = newGenericPoolWithCap(GSTATE.masterpool_shift_buffer_pools, (64) + GSTATE.ram_profile,
                                                    allocShiftBufferPoolHandle, destroyShiftBufferPoolHandle);

    tun_device_t *tdev = globalMalloc(sizeof(tun_device_t));

    *tdev = (tun_device_t) {.name                     = strdup(ifr.ifr_name),
                            .handle                   = fd,
                            .reader_shift_buffer_pool = sb_pool,
                            .read_event_callback      = cb,
                            .userdata                 = userdata,
                            .reader_message_pool      = newMasterPoolWithCap(kMasterMessagePoolCap),
                            .reader_buffer_pool = createBufferPool(NULL, GSTATE.masterpool_buffer_pools_small, sb_pool)

    };

    installMasterPoolAllocCallbacks(tdev->reader_message_pool, tdev, allocTunMsgPoolHandle, destroyTunMsgPoolHandle);

    return tdev;
}

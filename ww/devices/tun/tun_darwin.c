#include "generic_pool.h"
#include "global_state.h"
#include "loggers/internal_logger.h"
#include "tun.h"
#include "wchan.h"
#include "wproc.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <net/if_utun.h>
#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet6/in6_var.h>
#include <netinet6/nd6.h>
#include <poll.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/kern_control.h>
#include <sys/socket.h>
#include <sys/sys_domain.h>
#include <sys/uio.h>
#include <unistd.h>

enum
{
    kTunWriteChannelQueueMax    = 1024,
    kMaxReadDistributeQueueSize = 128
};

struct msg_event
{
    tun_device_t *tdev;
    sbuf_t       *bufs[kMaxReadDistributeQueueSize];
    uint8_t       count;
};

static uint16_t tunDeviceMtu(const tun_device_t *tdev)
{
    return tdev->mtu > 0 ? tdev->mtu : GLOBAL_MTU_SIZE;
}

static uint32_t ipv4PrefixToMask(unsigned int prefix)
{
    assert(prefix <= 32);

    if (prefix == 0)
    {
        return 0;
    }

    return htonl(UINT32_MAX << (32U - prefix));
}

static void ipv6PrefixToMask(uint8_t bytes[16], unsigned int prefix)
{
    assert(prefix <= 128);

    memorySet(bytes, 0, 16);
    unsigned int full_bytes = prefix / 8U;
    unsigned int rem_bits   = prefix % 8U;

    for (unsigned int i = 0; i < full_bytes; ++i)
    {
        bytes[i] = 0xFF;
    }

    if (rem_bits != 0 && full_bytes < 16)
    {
        bytes[full_bytes] = (uint8_t) (0xFFU << (8U - rem_bits));
    }
}

static bool tunSetNonBlocking(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0)
    {
        LOGW("TunDevice: failed to get fd flags for O_NONBLOCK: %s", strerror(errno));
        return false;
    }

    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0)
    {
        LOGW("TunDevice: failed to set O_NONBLOCK: %s", strerror(errno));
        return false;
    }

    return true;
}

static bool tunSetMtuByName(const char *name, uint16_t mtu)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
    {
        LOGE("TunDevice: failed to create socket for MTU setting: %s", strerror(errno));
        return false;
    }

    struct ifreq ifr;
    memorySet(&ifr, 0, sizeof(ifr));
    stringCopyN(ifr.ifr_name, name, IFNAMSIZ);
    ifr.ifr_name[IFNAMSIZ - 1] = '\0';
    ifr.ifr_mtu                = mtu;

    bool ok = true;
    if (ioctl(fd, SIOCSIFMTU, &ifr) < 0)
    {
        LOGE("TunDevice: failed to set MTU to %u for %s: %s", mtu, ifr.ifr_name, strerror(errno));
        ok = false;
    }

    close(fd);
    return ok;
}

static bool tunSetStateByName(const char *name, bool up)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
    {
        LOGE("TunDevice: failed to create socket for interface state setting: %s", strerror(errno));
        return false;
    }

    struct ifreq ifr;
    memorySet(&ifr, 0, sizeof(ifr));
    stringCopyN(ifr.ifr_name, name, IFNAMSIZ);
    ifr.ifr_name[IFNAMSIZ - 1] = '\0';

    bool ok = true;
    if (ioctl(fd, SIOCGIFFLAGS, &ifr) < 0)
    {
        LOGE("TunDevice: failed to get interface flags for %s: %s", name, strerror(errno));
        ok = false;
        goto done;
    }

    if (up)
    {
        ifr.ifr_flags |= IFF_UP;
    }
    else
    {
        ifr.ifr_flags &= (short) ~IFF_UP;
    }

    if (ioctl(fd, SIOCSIFFLAGS, &ifr) < 0)
    {
        LOGE("TunDevice: failed to set interface flags for %s: %s", name, strerror(errno));
        ok = false;
    }

done:
    close(fd);
    return ok;
}

static bool routeCommandArgIsSafe(const char *arg)
{
    if (arg == NULL || arg[0] == '\0')
    {
        return false;
    }

    for (const char *p = arg; *p != '\0'; ++p)
    {
        if (! (isalnum((unsigned char) *p) || *p == '_' || *p == '-' || *p == '.' || *p == ':' || *p == '/'))
        {
            return false;
        }
    }

    return true;
}

static bool routeTableIsMain(const char *route_table)
{
    return route_table == NULL || stringCompare(route_table, "main") == 0 || stringCompare(route_table, "auto") == 0;
}

static pool_item_t *allocTunMsgPoolHandle(master_pool_t *pool, void *userdata)
{
    discard userdata;
    discard pool;
    return memoryAllocate(sizeof(struct msg_event));
}

static void destroyTunMsgPoolHandle(master_pool_t *pool, master_pool_item_t *item, void *userdata)
{
    discard pool;
    discard userdata;
    memoryFree(item);
}

static void localThreadEventReceived(wevent_t *ev)
{
    struct msg_event *msg = weventGetUserdata(ev);
    wid_t             wid = (wid_t) (wloopGetWid(weventGetLoop(ev)));

    for (unsigned int i = 0; i < msg->count; i++)
    {
        msg->tdev->read_event_callback(msg->tdev, msg->tdev->userdata, msg->bufs[i], wid);
    }

    masterpoolReuseItems(msg->tdev->reader_message_pool, (void **) &msg, 1, msg->tdev);
}

static void distributePacketPayloads(tun_device_t *tdev, wid_t target_wid, sbuf_t **buf, unsigned int queued_count)
{
    struct msg_event *msg;
    masterpoolGetItems(tdev->reader_message_pool, (const void **) &(msg), 1, tdev);

    msg->tdev  = tdev;
    msg->count = queued_count;
    for (unsigned int i = 0; i < queued_count; i++)
    {
        msg->bufs[i] = buf[i];
    }

    wevent_t ev;
    memorySet(&ev, 0, sizeof(ev));
    ev.loop = getWorkerLoop(target_wid);
    ev.cb   = localThreadEventReceived;
    weventSetUserData(&ev, msg);
    if (UNLIKELY(false == wloopPostEvent(getWorkerLoop(target_wid), &ev)))
    {
        for (unsigned int i = 0; i < queued_count; i++)
        {
            bufferpoolReuseBuffer(tdev->reader_buffer_pool, msg->bufs[i]);
        }
        masterpoolReuseItems(tdev->reader_message_pool, (void **) &msg, 1, tdev);
    }
}

static int tunDrainPackets(tun_device_t *tdev)
{
    uint8_t  queued_count = 0;
    sbuf_t  *bufs[kMaxReadDistributeQueueSize];
    uint32_t read_size = (uint32_t) tunDeviceMtu(tdev) + sizeof(uint32_t);

    for (uint32_t i = 0; i < RAM_PROFILE && queued_count < kMaxReadDistributeQueueSize; ++i)
    {
        bufs[queued_count] = bufferpoolGetSmallBuffer(tdev->reader_buffer_pool);
        bufs[queued_count] = sbufReserveSpace(bufs[queued_count], read_size);

        int nread;
        for (;;)
        {
            nread = (int) read(tdev->handle, sbufGetMutablePtr(bufs[queued_count]), read_size);
            if (nread < 0 && errno == EINTR)
            {
                continue;
            }
            break;
        }

        if (nread == 0)
        {
            bufferpoolReuseBuffer(tdev->reader_buffer_pool, bufs[queued_count]);
            if (queued_count > 0)
            {
                distributePacketPayloads(tdev, getNextDistributionWID(), bufs, queued_count);
            }
            return 0;
        }

        if (nread < 0)
        {
            int saved_errno = errno;
            bufferpoolReuseBuffer(tdev->reader_buffer_pool, bufs[queued_count]);
            if (queued_count > 0)
            {
                distributePacketPayloads(tdev, getNextDistributionWID(), bufs, queued_count);
            }

            if (saved_errno == EAGAIN || saved_errno == EWOULDBLOCK)
            {
                return 1;
            }
            LOGW("TunDevice: failed to read a packet from TUN device, errno is %d (%s), retrying...", saved_errno,
                 strerror(saved_errno));
            return -1;
        }

        if (nread <= (int) sizeof(uint32_t))
        {
            LOGW("TunDevice: dropping short utun frame of size %d", nread);
            bufferpoolReuseBuffer(tdev->reader_buffer_pool, bufs[queued_count]);
            continue;
        }

        sbufSetLength(bufs[queued_count], (uint32_t) nread);
        sbufShiftRight(bufs[queued_count], sizeof(uint32_t));

        if (UNLIKELY(sbufGetLength(bufs[queued_count]) > tunDeviceMtu(tdev)))
        {
            LOGE("TunDevice: ReadThread: read packet size %d exceeds device MTU %u",
                 sbufGetLength(bufs[queued_count]), tunDeviceMtu(tdev));
            LOGF("TunDevice: This is related to the MTU size, please set a correct value for TunDevice 'device-mtu'");
            bufferpoolReuseBuffer(tdev->reader_buffer_pool, bufs[queued_count]);
            terminateProgram(1);
        }

        queued_count++;
    }

    if (queued_count > 0)
    {
        distributePacketPayloads(tdev, getNextDistributionWID(), bufs, queued_count);
    }

    return 1;
}

static WTHREAD_ROUTINE(routineReadFromTun)
{
    tun_device_t *tdev = userdata;

    struct pollfd fds[2];
    fds[0].fd     = tdev->handle;
    fds[1].fd     = tdev->linux_pipe_fds[0];
    fds[0].events = POLLIN;
    fds[1].events = POLLIN;

    while (atomicLoadExplicit(&(tdev->running), memory_order_relaxed))
    {
        int ret = poll(fds, 2, -1);

        if (ret < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }
            LOGE("TunDevice: Exit read routine due to poll failed with error %d (%s)", errno, strerror(errno));
            break;
        }

        if (fds[1].revents & POLLIN)
        {
            char    drain_byte;
            ssize_t drain_res = read(tdev->linux_pipe_fds[0], &drain_byte, 1);
            discard drain_res;
            LOGW("TunDevice: Exit read routine due to pipe event");
            break;
        }

        if (fds[0].revents & (POLLERR | POLLHUP | POLLNVAL))
        {
            LOGE("TunDevice: Exit read routine due to device poll event: %s%s%s",
                 (fds[0].revents & POLLERR) ? "POLLERR " : "", (fds[0].revents & POLLHUP) ? "POLLHUP " : "",
                 (fds[0].revents & POLLNVAL) ? "POLLNVAL " : "");
            break;
        }

        if (fds[0].revents & POLLIN)
        {
            int drain_res = tunDrainPackets(tdev);
            if (drain_res == 0)
            {
                LOGE("TunDevice: Exit read routine due to End Of File");
                return 0;
            }
            continue;
        }

        LOGE("TunDevice: Exit read routine due to unexpected poll events - fd[0].revents=0x%x, fd[1].revents=0x%x",
             fds[0].revents, fds[1].revents);
        return 0;
    }

    return 0;
}

static WTHREAD_ROUTINE(routineWriteToTun)
{
    tun_device_t *tdev = userdata;
    sbuf_t       *buf;

    while (atomicLoadExplicit(&(tdev->running), memory_order_relaxed))
    {
        if (! chanRecv(tdev->writer_buffer_channel, (void *) &buf))
        {
            LOGD("TunDevice: routine write will exit due to channel closed");
            return 0;
        }

        if (UNLIKELY(tunDeviceMtu(tdev) < sbufGetLength(buf)))
        {
            LOGW("TunDevice: WriteThread: discarded a packet -> size %d exceeds device MTU %u", sbufGetLength(buf),
                 tunDeviceMtu(tdev));
            bufferpoolReuseBuffer(tdev->writer_buffer_pool, buf);
            continue;
        }

        if (UNLIKELY(sbufGetLength(buf) == 0))
        {
            bufferpoolReuseBuffer(tdev->writer_buffer_pool, buf);
            continue;
        }

        const uint8_t version = (uint8_t) (((const uint8_t *) sbufGetRawPtr(buf))[0] >> 4U);
        uint32_t      family;
        if (version == 4)
        {
            family = htonl(AF_INET);
        }
        else if (version == 6)
        {
            family = htonl(AF_INET6);
        }
        else
        {
            LOGW("TunDevice: WriteThread: discarded packet with unsupported IP version %u", version);
            bufferpoolReuseBuffer(tdev->writer_buffer_pool, buf);
            continue;
        }

        struct iovec iov[2];
        iov[0].iov_base = &family;
        iov[0].iov_len  = sizeof(family);
        iov[1].iov_base = (void *) sbufGetRawPtr(buf);
        iov[1].iov_len  = sbufGetLength(buf);

        ssize_t nwrite  = writev(tdev->handle, iov, 2);
        ssize_t expected = (ssize_t) (sizeof(family) + sbufGetLength(buf));
        bufferpoolReuseBuffer(tdev->writer_buffer_pool, buf);

        if (nwrite == 0)
        {
            LOGW("TunDevice: Exit write routine due to End Of File");
            return 0;
        }

        if (nwrite < 0)
        {
            LOGW("TunDevice: writing a packet to TUN device failed: %s", strerror(errno));
            if (errno == EINVAL || errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
            {
                continue;
            }

            if (errno == EMSGSIZE)
            {
                LOGF("TunDevice: This is related to the MTU size, please set a correct value for TunDevice "
                     "'device-mtu'");
                terminateProgram(1);
            }
            continue;
        }

        if (UNLIKELY(nwrite != expected))
        {
            LOGW("TunDevice: partial utun write, wrote %d of %d bytes", (int) nwrite, (int) expected);
        }
    }
    return 0;
}

bool tundeviceWrite(tun_device_t *tdev, sbuf_t *buf)
{
    assert(sbufGetLength(buf) > 0);

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

bool tundeviceAssignIP(tun_device_t *tdev, const char *ip_presentation, unsigned int subnet)
{
    if (subnet <= 32)
    {
        struct ifaliasreq ifra;
        memorySet(&ifra, 0, sizeof(ifra));
        stringCopyN(ifra.ifra_name, tdev->name, IFNAMSIZ);
        ifra.ifra_name[IFNAMSIZ - 1] = '\0';

        struct sockaddr_in *addr = (struct sockaddr_in *) &ifra.ifra_addr;
        addr->sin_len            = sizeof(*addr);
        addr->sin_family         = AF_INET;
        if (inet_pton(AF_INET, ip_presentation, &addr->sin_addr) == 1)
        {
            memoryCopy(&ifra.ifra_broadaddr, &ifra.ifra_addr, sizeof(ifra.ifra_addr));

            struct sockaddr_in *mask = (struct sockaddr_in *) &ifra.ifra_mask;
            mask->sin_len            = sizeof(*mask);
            mask->sin_family         = AF_INET;
            mask->sin_addr.s_addr    = ipv4PrefixToMask(subnet);

            int fd = socket(AF_INET, SOCK_DGRAM, 0);
            if (fd < 0)
            {
                LOGE("TunDevice: failed to create socket for IPv4 assignment: %s", strerror(errno));
                return false;
            }

            bool ok = true;
            if (ioctl(fd, SIOCAIFADDR, &ifra) < 0 && errno != EEXIST)
            {
                LOGE("TunDevice: error setting IPv4 address on %s: %s", tdev->name, strerror(errno));
                ok = false;
            }
            close(fd);

            if (ok)
            {
                LOGD("TunDevice: ip address %s/%d assigned to dev %s", ip_presentation, subnet, tdev->name);
            }
            return ok;
        }
    }

    if (subnet <= 128)
    {
        struct in6_aliasreq ifra;
        memorySet(&ifra, 0, sizeof(ifra));
        stringCopyN(ifra.ifra_name, tdev->name, IFNAMSIZ);
        ifra.ifra_name[IFNAMSIZ - 1] = '\0';
        ifra.ifra_lifetime.ia6t_vltime = ND6_INFINITE_LIFETIME;
        ifra.ifra_lifetime.ia6t_pltime = ND6_INFINITE_LIFETIME;

        ifra.ifra_addr.sin6_len    = sizeof(ifra.ifra_addr);
        ifra.ifra_addr.sin6_family = AF_INET6;
        if (inet_pton(AF_INET6, ip_presentation, &ifra.ifra_addr.sin6_addr) == 1)
        {
            ifra.ifra_prefixmask.sin6_len    = sizeof(ifra.ifra_prefixmask);
            ifra.ifra_prefixmask.sin6_family = AF_INET6;
            ipv6PrefixToMask((uint8_t *) &ifra.ifra_prefixmask.sin6_addr, subnet);

            int fd = socket(AF_INET6, SOCK_DGRAM, 0);
            if (fd < 0)
            {
                LOGE("TunDevice: failed to create socket for IPv6 assignment: %s", strerror(errno));
                return false;
            }

            bool ok = true;
            if (ioctl(fd, SIOCAIFADDR_IN6, &ifra) < 0 && errno != EEXIST)
            {
                LOGE("TunDevice: error setting IPv6 address on %s: %s", tdev->name, strerror(errno));
                ok = false;
            }
            close(fd);

            if (ok)
            {
                LOGD("TunDevice: ip address %s/%d assigned to dev %s", ip_presentation, subnet, tdev->name);
            }
            return ok;
        }
    }

    LOGE("TunDevice: Cannot set IP -> Invalid IP address or prefix: %s/%u", ip_presentation, subnet);
    return false;
}

bool tundeviceUnAssignIP(tun_device_t *tdev, const char *ip_presentation, unsigned int subnet)
{
    discard subnet;

    struct ifreq ifr;
    memorySet(&ifr, 0, sizeof(ifr));
    stringCopyN(ifr.ifr_name, tdev->name, IFNAMSIZ);
    ifr.ifr_name[IFNAMSIZ - 1] = '\0';

    struct sockaddr_in *addr = (struct sockaddr_in *) &ifr.ifr_addr;
    addr->sin_len            = sizeof(*addr);
    addr->sin_family         = AF_INET;
    if (inet_pton(AF_INET, ip_presentation, &addr->sin_addr) == 1)
    {
        int fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (fd < 0)
        {
            LOGE("TunDevice: failed to create socket for IPv4 removal: %s", strerror(errno));
            return false;
        }

        bool ok = true;
        if (ioctl(fd, SIOCDIFADDR, &ifr) < 0 && errno != EADDRNOTAVAIL)
        {
            LOGE("TunDevice: error unassigning IPv4 address from %s: %s", tdev->name, strerror(errno));
            ok = false;
        }
        close(fd);
        return ok;
    }

    struct in6_ifreq ifr6;
    memorySet(&ifr6, 0, sizeof(ifr6));
    stringCopyN(ifr6.ifr_name, tdev->name, IFNAMSIZ);
    ifr6.ifr_name[IFNAMSIZ - 1] = '\0';
    ifr6.ifr_addr.sin6_len      = sizeof(ifr6.ifr_addr);
    ifr6.ifr_addr.sin6_family   = AF_INET6;
    if (inet_pton(AF_INET6, ip_presentation, &ifr6.ifr_addr.sin6_addr) == 1)
    {
        int fd = socket(AF_INET6, SOCK_DGRAM, 0);
        if (fd < 0)
        {
            LOGE("TunDevice: failed to create socket for IPv6 removal: %s", strerror(errno));
            return false;
        }

        bool ok = true;
        if (ioctl(fd, SIOCDIFADDR_IN6, &ifr6) < 0 && errno != EADDRNOTAVAIL)
        {
            LOGE("TunDevice: error unassigning IPv6 address from %s: %s", tdev->name, strerror(errno));
            ok = false;
        }
        close(fd);
        return ok;
    }

    LOGE("TunDevice: Cannot unset IP -> Invalid IP address: %s", ip_presentation);
    return false;
}

bool tundeviceAddRoute(tun_device_t *tdev, const char *cidr, const char *route_table)
{
    if (! routeTableIsMain(route_table))
    {
        LOGE("TunDevice: route-table '%s' is not supported on macOS", route_table);
        return false;
    }

    if (! routeCommandArgIsSafe(tdev->name) || ! routeCommandArgIsSafe(cidr))
    {
        LOGE("TunDevice: invalid route argument");
        return false;
    }

    char        command[512];
    const char *family = stringChr(cidr, ':') != NULL ? "-inet6" : "-inet";
    stringNPrintf(command, sizeof(command), "route -n add %s %s -interface %s", family, cidr, tdev->name);

    if (execCmd(command).exit_code != 0)
    {
        LOGE("TunDevice: failed to add system route %s on %s", cidr, tdev->name);
        return false;
    }

    LOGI("TunDevice: added system route %s on %s", cidr, tdev->name);
    return true;
}

bool tundeviceRemoveRoute(tun_device_t *tdev, const char *cidr, const char *route_table)
{
    if (! routeTableIsMain(route_table))
    {
        LOGE("TunDevice: route-table '%s' is not supported on macOS", route_table);
        return false;
    }

    if (! routeCommandArgIsSafe(tdev->name) || ! routeCommandArgIsSafe(cidr))
    {
        LOGE("TunDevice: invalid route argument");
        return false;
    }

    char        command[512];
    const char *family = stringChr(cidr, ':') != NULL ? "-inet6" : "-inet";
    stringNPrintf(command, sizeof(command), "route -n delete %s %s -interface %s", family, cidr, tdev->name);

    if (execCmd(command).exit_code != 0)
    {
        LOGE("TunDevice: failed to remove system route %s on %s", cidr, tdev->name);
        return false;
    }

    LOGI("TunDevice: removed system route %s on %s", cidr, tdev->name);
    return true;
}

bool tundeviceBringUp(tun_device_t *tdev)
{
    if (tdev->up)
    {
        LOGE("TunDevice: device is already up");
        return false;
    }

    bufferpoolUpdateAllocationPaddings(tdev->reader_buffer_pool,
                                       bufferpoolGetLargeBufferPadding(getWorkerBufferPool(getWID())),
                                       bufferpoolGetSmallBufferPadding(getWorkerBufferPool(getWID())));

    bufferpoolUpdateAllocationPaddings(tdev->writer_buffer_pool,
                                       bufferpoolGetLargeBufferPadding(getWorkerBufferPool(getWID())),
                                       bufferpoolGetSmallBufferPadding(getWorkerBufferPool(getWID())));

    tdev->writer_buffer_channel = chanOpen(sizeof(void *), kTunWriteChannelQueueMax);

    if (! tunSetStateByName(tdev->name, true))
    {
        LOGE("TunDevice: error bringing device %s up", tdev->name);
        chanClose(tdev->writer_buffer_channel);
        chanFree(tdev->writer_buffer_channel);
        tdev->writer_buffer_channel = NULL;
        return false;
    }

    tdev->up = true;
    atomicStoreRelaxed(&(tdev->running), true);

    LOGI("TunDevice: device %s is now up", tdev->name);

    if (tdev->read_event_callback != NULL)
    {
        tdev->read_thread = threadCreate(tdev->routine_reader, tdev);
    }
    tdev->write_thread = threadCreate(tdev->routine_writer, tdev);
    return true;
}

bool tundeviceBringDown(tun_device_t *tdev)
{
    if (! tdev->up)
    {
        LOGE("TunDevice: device is already down");
        return true;
    }

    atomicStoreRelaxed(&(tdev->running), false);
    tdev->up = false;

    chanClose(tdev->writer_buffer_channel);
    sbuf_t *buf;
    while (chanRecv(tdev->writer_buffer_channel, (void *) &buf))
    {
        bufferpoolReuseBuffer(tdev->writer_buffer_pool, buf);
    }

    bool bring_down_ok = true;
    if (! tunSetStateByName(tdev->name, false))
    {
        LOGE("TunDevice: error bringing %s down", tdev->name);
        bring_down_ok = false;
    }
    else
    {
        LOGI("TunDevice: device %s is now down", tdev->name);
    }

    if (tdev->read_event_callback != NULL)
    {
        ssize_t write_res = write(tdev->linux_pipe_fds[1], "x", 1);
        discard write_res;

        safeThreadJoin(tdev->read_thread);
    }
    safeThreadJoin(tdev->write_thread);

    chanFree(tdev->writer_buffer_channel);
    tdev->writer_buffer_channel = NULL;

    return bring_down_ok;
}

static int tunDarwinOpen(const char *name, char actual_name[IFNAMSIZ])
{
    struct ctl_info     ci;
    struct sockaddr_ctl sc;
    int                 fd = -1;

    memorySet(&ci, 0, sizeof(ci));
    stringCopyN(ci.ctl_name, UTUN_CONTROL_NAME, sizeof(ci.ctl_name));

    fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
    if (fd < 0)
    {
        LOGE("TunDevice: opening utun control socket failed: %s", strerror(errno));
        return -1;
    }

    if (ioctl(fd, CTLIOCGINFO, &ci) < 0)
    {
        LOGE("TunDevice: CTLIOCGINFO failed: %s", strerror(errno));
        close(fd);
        return -1;
    }

    memorySet(&sc, 0, sizeof(sc));
    sc.sc_id     = ci.ctl_id;
    sc.sc_len    = sizeof(sc);
    sc.sc_family = AF_SYSTEM;
    sc.ss_sysaddr = AF_SYS_CONTROL;
    sc.sc_unit   = 0;

    unsigned int requested_unit = 0;
    if (name != NULL && sscanf(name, "utun%u", &requested_unit) == 1)
    {
        sc.sc_unit = requested_unit + 1;
    }

    if (connect(fd, (struct sockaddr *) &sc, sizeof(sc)) < 0)
    {
        LOGE("TunDevice: connecting utun control socket failed: %s", strerror(errno));
        close(fd);
        return -1;
    }

    socklen_t len = IFNAMSIZ;
    if (getsockopt(fd, SYSPROTO_CONTROL, UTUN_OPT_IFNAME, actual_name, &len) < 0)
    {
        LOGE("TunDevice: failed to get utun interface name: %s", strerror(errno));
        close(fd);
        return -1;
    }
    actual_name[IFNAMSIZ - 1] = '\0';

    tunSetNonBlocking(fd);
    return fd;
}

tun_device_t *tundeviceCreate(const char *name, bool offload, uint16_t mtu, void *userdata, TunReadEventHandle cb)
{
    discard offload;

    char actual_name[IFNAMSIZ];
    memorySet(actual_name, 0, sizeof(actual_name));

    int fd = tunDarwinOpen(name, actual_name);
    if (fd < 0)
    {
        return NULL;
    }

    if (! tunSetMtuByName(actual_name, mtu))
    {
        close(fd);
        return NULL;
    }

    uint32_t worker_large_buffer_size = bufferpoolGetLargeBufferSize(getWorkerBufferPool(getWID()));
    uint32_t worker_small_buffer_size = bufferpoolGetSmallBufferSize(getWorkerBufferPool(getWID()));
    worker_small_buffer_size          = max(worker_small_buffer_size, (uint32_t) mtu + sizeof(uint32_t));

    buffer_pool_t *reader_bpool =
        bufferpoolCreate(GSTATE.masterpool_buffer_pools_large, GSTATE.masterpool_buffer_pools_small, RAM_PROFILE,
                         worker_large_buffer_size, worker_small_buffer_size);

    buffer_pool_t *writer_bpool =
        bufferpoolCreate(GSTATE.masterpool_buffer_pools_large, GSTATE.masterpool_buffer_pools_small, RAM_PROFILE,
                         worker_large_buffer_size, worker_small_buffer_size);

    tun_device_t *tdev = memoryAllocate(sizeof(tun_device_t));
    *tdev = (tun_device_t){.name                  = stringDuplicate(actual_name),
                           .running               = false,
                           .up                    = false,
                           .routine_reader        = routineReadFromTun,
                           .routine_writer        = routineWriteToTun,
                           .handle                = fd,
                           .read_event_callback   = cb,
                           .userdata              = userdata,
                           .writer_buffer_channel = NULL,
                           .reader_message_pool   = masterpoolCreateWithCapacity(RAM_PROFILE * 2),
                           .reader_buffer_pool    = reader_bpool,
                           .writer_buffer_pool    = writer_bpool,
                           .mtu                   = mtu,
                           .packets_queued        = 0};

    if (pipe(tdev->linux_pipe_fds) != 0)
    {
        LOGE("TunDevice: failed to create stop pipe");
        memoryFree(tdev->name);
        bufferpoolDestroy(tdev->reader_buffer_pool);
        bufferpoolDestroy(tdev->writer_buffer_pool);
        masterpoolDestroy(tdev->reader_message_pool);
        close(tdev->handle);
        memoryFree(tdev);
        return NULL;
    }

    masterpoolInstallCallBacks(tdev->reader_message_pool, allocTunMsgPoolHandle, destroyTunMsgPoolHandle);

    return tdev;
}

void tundeviceDestroy(tun_device_t *tdev)
{
    if (tdev->up)
    {
        tundeviceBringDown(tdev);
    }
    memoryFree(tdev->name);
    bufferpoolDestroy(tdev->reader_buffer_pool);
    bufferpoolDestroy(tdev->writer_buffer_pool);
    masterpoolMakeEmpty(tdev->reader_message_pool, NULL);
    masterpoolDestroy(tdev->reader_message_pool);
    close(tdev->handle);
    close(tdev->linux_pipe_fds[0]);
    close(tdev->linux_pipe_fds[1]);
    memoryFree(tdev);
}

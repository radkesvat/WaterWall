#include "devices/device_flow_affinity.h"
#include "devices/device_reader_session.h"
#include "devices/device_writer_channel.h"
#include "devices/tun/tun_io_error.h"
#include "devices/tun/tun_lifecycle.h"
#include "generic_pool.h"
#include "global_state.h"
#include "loggers/internal_logger.h"
#include "tun.h"
#include "watomic.h"
#include "wchan.h"
#include "wproc.h"
#include "wthread.h"

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

static_assert(kMaxReadDistributeQueueSize <= UINT16_MAX, "TUN read batch count must fit in the reader session");

struct tun_device_s
{
    char *name;
    int   handle;
    int   linux_pipe_fds[2]; // used for signaling read thread to stop

    void     *userdata;
    wthread_t read_thread;
    wthread_t write_thread;

    wthread_routine routine_reader;
    wthread_routine routine_writer;

    device_reader_session_t *reader_session;
    buffer_pool_t           *reader_buffer_pool;
    buffer_pool_t           *writer_buffer_pool;

    TunReadEventHandle read_event_callback;

    device_writer_channel_t writer_channel;
    uint16_t                mtu;

    atomic_int lifecycle;

    // Whether read_thread / write_thread hold a started, unjoined thread. These
    // -- not `up` -- decide what bring-down must join, so a device whose thread
    // already exited on its own is still torn down completely. Owner-thread only.
    bool reader_joinable;
    bool writer_joinable;
};

static inline uint16_t tunDeviceMtu(const tun_device_t *tdev)
{
    assert(tdev->mtu > 0);
    return tdev->mtu;
}

bool tundeviceIsUp(const tun_device_t *tdev)
{
    return tdev != NULL && tunLifecycleLoad(&tdev->lifecycle) == kTunLifecycleUp;
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

    memoryZero(bytes, 16);
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
    memoryZero(&ifr, sizeof(ifr));
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
    memoryZero(&ifr, sizeof(ifr));
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

static void tunDeliverPacket(void *device, sbuf_t *buf, wid_t wid)
{
    tun_device_t *tdev = device;
    tdev->read_event_callback(tdev, tdev->userdata, buf, wid);
}

// Hands whatever the drain cycle has already read to the reader session. Every
// exit from tunDrainPackets() goes through this, so a device error never
// strands packets that were read successfully before it.
static bool tunFlushReadBatch(tun_device_t *tdev, sbuf_t **bufs, uint16_t queued_count)
{
    return queued_count == 0 || deviceFlowAffinityPostBatch(tdev->reader_session, bufs, queued_count);
}

// Drains packets from the TUN device after POLLIN. Every accumulated buffer is
// handed to the reader session before returning, on every path.
static tun_drain_result_t tunDrainPackets(tun_device_t *tdev)
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
            return tunFlushReadBatch(tdev, bufs, queued_count) ? kTunDrainEndOfStream : kTunDrainDeviceError;
        }

        if (nread < 0)
        {
            // errno is only meaningful right here: recycling the buffer and the
            // loggers below can both overwrite it.
            const int saved_errno = errno;
            bufferpoolReuseBuffer(tdev->reader_buffer_pool, bufs[queued_count]);
            if (! tunFlushReadBatch(tdev, bufs, queued_count))
            {
                return kTunDrainDeviceError;
            }

            if (tunIoErrnoIsTransient(saved_errno))
            {
                // No more packets for now; end this cycle and go back to poll().
                return kTunDrainAgain;
            }

            /*
             * Anything else (EIO, EBADF, ENODEV, ENXIO, ...) means this handle
             * will not produce packets again. Returning "keep polling" here made
             * the reader spin on a permanently readable dead fd while every
             * packet vanished, so the loss is reported instead. Mirrors
             * tun_linux.c.
             */
            LOGE("TunDevice: unrecoverable read error on device %s, errno is %d (%s)",
                 tdev->name,
                 saved_errno,
                 strerror(saved_errno));
            return kTunDrainDeviceError;
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
                 sbufGetLength(bufs[queued_count]),
                 tunDeviceMtu(tdev));
            LOGF("TunDevice: This is related to the MTU size, please set a correct value for TunDevice 'device-mtu'");
            bufferpoolReuseBuffer(tdev->reader_buffer_pool, bufs[queued_count]);

            /*
             * A misconfigured MTU is fatal for the process, but this runs on the
             * device reader thread. Release everything this thread owns - the
             * oversized buffer above, plus the batch accumulated so far - and
             * report the loss so the read routine leaves through its normal exit
             * path. tundeviceNoteUnexpectedThreadExit() then publishes the
             * failure and owns the shutdown decision. Mirrors tun_linux.c.
             */
            discard tunFlushReadBatch(tdev, bufs, queued_count);
            return kTunDrainDeviceError;
        }

        queued_count++;
    }

    if (! tunFlushReadBatch(tdev, bufs, queued_count))
    {
        return kTunDrainDeviceError;
    }

    return kTunDrainAgain;
}

static WTHREAD_ROUTINE(routineReadFromTun)
{
    tun_device_t *tdev = userdata;

    struct pollfd fds[2];
    fds[0].fd     = tdev->handle;
    fds[1].fd     = tdev->linux_pipe_fds[0];
    fds[0].events = POLLIN;
    fds[1].events = POLLIN;

    while (tunLifecycleIsActive(tunLifecycleLoad(&tdev->lifecycle)))
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
                 (fds[0].revents & POLLERR) ? "POLLERR " : "",
                 (fds[0].revents & POLLHUP) ? "POLLHUP " : "",
                 (fds[0].revents & POLLNVAL) ? "POLLNVAL " : "");
            break;
        }

        if (fds[0].revents & POLLIN)
        {
            const tun_drain_result_t drain_res = tunDrainPackets(tdev);
            if (drain_res != kTunDrainAgain)
            {
                // The device is gone. Leaving the loop is what lets the thread
                // wrapper publish FAILED and request the orderly shutdown.
                LOGE("TunDevice: Exit read routine due to %s",
                     drain_res == kTunDrainEndOfStream ? "End Of File" : "an unrecoverable device read error");
                return 0;
            }
            continue;
        }

        LOGE("TunDevice: Exit read routine due to unexpected poll events - fd[0].revents=0x%x, fd[1].revents=0x%x",
             fds[0].revents,
             fds[1].revents);
        return 0;
    }

    return 0;
}

static WTHREAD_ROUTINE(routineWriteToTun)
{
    tun_device_t   *tdev = userdata;
    sbuf_t         *buf;
    struct wchan_s *writer_channel = deviceWriterChannelGetConsumerChannel(&tdev->writer_channel);

    while (tunLifecycleIsActive(tunLifecycleLoad(&tdev->lifecycle)))
    {
        if (! chanRecv(writer_channel, (void *) &buf))
        {
            LOGD("TunDevice: routine write will exit due to channel closed");
            return 0;
        }

        if (UNLIKELY(tunDeviceMtu(tdev) < sbufGetLength(buf)))
        {
            LOGW("TunDevice: WriteThread: discarded a packet -> size %d exceeds device MTU %u",
                 sbufGetLength(buf),
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

        ssize_t nwrite = writev(tdev->handle, iov, 2);
        // errno is only meaningful right here. Recycling the buffer and every
        // logger below may overwrite it, so classification must read this copy.
        const int write_errno = (nwrite < 0) ? errno : 0;
        ssize_t   expected    = (ssize_t) (sizeof(family) + sbufGetLength(buf));
        bufferpoolReuseBuffer(tdev->writer_buffer_pool, buf);

        if (nwrite == 0)
        {
            LOGW("TunDevice: Exit write routine due to End Of File");
            return 0;
        }

        if (nwrite < 0)
        {
            if (tunIoErrnoIsTransient(write_errno) || tunWriteErrnoIsPacketLocal(write_errno))
            {
                LOGW("TunDevice: discarded a packet, writing to device %s failed with errno %d (%s)",
                     tdev->name,
                     write_errno,
                     strerror(write_errno));
                continue;
            }

            if (write_errno == EMSGSIZE)
            {
                LOGF("TunDevice: This is related to the MTU size, please set a correct value for TunDevice "
                     "'device-mtu'");
            }

            /*
             * The device will not accept packets again. The buffer was already
             * recycled above and this thread holds nothing else, so just leave
             * the write routine through its normal exit.
             * tundeviceNoteUnexpectedThreadExit() publishes the failure and owns
             * the shutdown decision. Returning to the loop instead would discard
             * every packet from here on while the device still looked usable.
             * Mirrors tun_linux.c.
             */
            LOGE("TunDevice: Exit write routine due to an unrecoverable write error on device %s, errno %d (%s)",
                 tdev->name,
                 write_errno,
                 strerror(write_errno));
            return 0;
        }

        if (UNLIKELY(nwrite != expected))
        {
            LOGW("TunDevice: partial utun write, wrote %d of %d bytes", (int) nwrite, (int) expected);
        }
    }
    return 0;
}

bool tundeviceGetLuid(tun_device_t *tdev, uint64_t *out)
{
    discard tdev;
    *out = 0;
    return false;
}

bool tundeviceDetectDefaultInterface(tun_default_route_t *out)
{
    memoryZero(out, sizeof(*out));
    return false;
}

bool tundeviceDisableReversePathFiltering(const char *ifname)
{
    discard ifname;
    return true;
}

bool tundeviceWrite(tun_device_t *tdev, sbuf_t *buf)
{
    assert(sbufGetLength(buf) > 0);

    switch (deviceWriterChannelTrySend(&tdev->writer_channel, buf))
    {
    case kDeviceWriterSendOk:
        return true;
    case kDeviceWriterSendDown:
        LOGE("TunDevice: write failed, device is down");
        return false;
    case kDeviceWriterSendClosed:
        LOGE("TunDevice: write failed, channel was closed");
        return false;
    case kDeviceWriterSendFull:
        LOGE("TunDevice: write failed, ring is full");
        return false;
    }

    return false;
}

static void tundeviceCloseLifetimeGates(tun_device_t *tdev)
{
    deviceWriterChannelClose(&tdev->writer_channel);
    deviceReaderSessionEnd(tdev->reader_session);
}

static void tundeviceDrainStopPipe(tun_device_t *tdev)
{
    struct pollfd fd = {.fd = tdev->linux_pipe_fds[0], .events = POLLIN};

    for (;;)
    {
        int ret = poll(&fd, 1, 0);
        if (ret < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }
            LOGW("TunDevice: failed to poll stop pipe while draining: %s", strerror(errno));
            return;
        }

        if (ret == 0 || ! (fd.revents & POLLIN))
        {
            return;
        }

        char    buf[64];
        ssize_t read_res = read(tdev->linux_pipe_fds[0], buf, sizeof(buf));
        if (read_res < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }
            LOGW("TunDevice: failed to drain stop pipe: %s", strerror(errno));
            return;
        }

        if (read_res == 0)
        {
            return;
        }
    }
}

bool tundeviceAssignIP(tun_device_t *tdev, const char *ip_presentation, unsigned int subnet)
{
    if (subnet <= 32)
    {
        struct ifaliasreq ifra;
        memoryZero(&ifra, sizeof(ifra));
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
        memoryZero(&ifra, sizeof(ifra));
        stringCopyN(ifra.ifra_name, tdev->name, IFNAMSIZ);
        ifra.ifra_name[IFNAMSIZ - 1]   = '\0';
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
    memoryZero(&ifr, sizeof(ifr));
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
    memoryZero(&ifr6, sizeof(ifr6));
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

bool tundeviceSetDnsServers(tun_device_t *tdev, const char *const *servers, size_t count)
{
    if (count == 0)
    {
        return true;
    }

    if (count > kTunDeviceMaxDnsServers)
    {
        LOGE("TunDevice: at most %d DNS servers are supported", kTunDeviceMaxDnsServers);
        return false;
    }

    LOGE("TunDevice: DNS configuration is not supported on macOS TUN devices");
    discard tdev;
    discard servers;
    return false;
}

bool tundeviceClearDnsServers(tun_device_t *tdev)
{
    discard tdev;

    LOGE("TunDevice: DNS configuration is not supported on macOS TUN devices");
    return false;
}

/*
 * Single place where an unexpected TUN I/O thread exit becomes process policy.
 * Keep this behaviorally identical to the tun_linux.c and tun_windows.c copies.
 *
 * A device I/O routine that returns while the lifecycle is STARTING or UP was
 * not asked to stop: it hit a real error (poll failure, EOF, an unrecoverable
 * write). Such exits used to leave the device published as healthy while reads
 * had silently stopped and writes piled into a channel nobody drains.
 *
 * The routine has already returned, so it has released or transferred every
 * buffer it owned, and this wrapper owns no locks. That is what makes it the
 * correct point to request shutdown: requestProgramShutdown() returns, the
 * wrapper returns, and worker 0 is then free to join this thread.
 *
 * Deliberately NOT done here: closing channels, waking the peer,
 * tundeviceBringDown(), pre-down scripts, route/DNS restoration, or joining
 * threads. A device thread that did any of those would eventually join itself.
 * Worker 0 reaches all of it through nodemanagerStop() and TunDevice::onStop.
 */
static void tundeviceNoteUnexpectedThreadExit(tun_device_t *tdev, const char *which)
{
    tun_lifecycle_state_t failed_from;
    if (! tunLifecycleTransitionToFailed(&tdev->lifecycle, &failed_from))
    {
        // Either normal teardown already moved the device to STOPPING (this
        // routine returned because it was asked to), or the peer thread already
        // published the failure. Neither case logs or requests again.
        return;
    }

    LOGE("TunDevice: %s thread for device %s exited unexpectedly; the device is no longer usable", which, tdev->name);

    /*
     * STARTING -> FAILED is a startup failure: tundeviceBringUp() observes the
     * failed publication, rolls back what it owns and returns false, and the
     * main-thread TunDevice::onStart path decides what happens next. Requesting
     * shutdown from here would race that synchronous rollback.
     *
     * UP -> FAILED is an already published device losing a required I/O thread
     * at runtime. The packet chain cannot continue correctly, so this is
     * process-fatal: request the orderly, worker-0-owned shutdown.
     */
    if (failed_from == kTunLifecycleUp && ! requestProgramShutdown(1))
    {
        abortProgramNow(1);
    }
}

static WTHREAD_ROUTINE(tundeviceReaderThreadMain) // NOLINT
{
    // Auxiliary device thread: it must stay unregistered and use only
    // device-owned pools/channels, posting work to explicit event workers.
    assert(! currentThreadHasRegisteredWID());
    tun_device_t *tdev = userdata;
    discard       tdev->routine_reader(tdev);
    tundeviceNoteUnexpectedThreadExit(tdev, "reader");
    return 0;
}

static WTHREAD_ROUTINE(tundeviceWriterThreadMain) // NOLINT
{
    // Auxiliary device thread: it must stay unregistered and use only
    // device-owned pools/channels, posting work to explicit event workers.
    assert(! currentThreadHasRegisteredWID());
    tun_device_t *tdev = userdata;
    discard       tdev->routine_writer(tdev);
    tundeviceNoteUnexpectedThreadExit(tdev, "writer");
    return 0;
}

bool tundeviceBringUp(tun_device_t *tdev)
{
    if (! tunLifecycleTransitionDownToStarting(&tdev->lifecycle))
    {
        LOGE("TunDevice: device cannot be started in current lifecycle state");
        return false;
    }

    /*
     * Device bring-up/creation runs on an event worker even though the reader
     * and writer threads it manages stay unregistered. Read that worker's pool
     * geometry once here and copy it onto the device-owned pools; the auxiliary
     * threads never touch worker-local state themselves.
     */
    buffer_pool_t *worker_pool = getCurrentEventWorkerBufferPool();

    bufferpoolUpdateAllocationPaddings(tdev->reader_buffer_pool,
                                       bufferpoolGetLargeBufferPadding(worker_pool),
                                       bufferpoolGetSmallBufferPadding(worker_pool));

    bufferpoolUpdateAllocationPaddings(tdev->writer_buffer_pool,
                                       bufferpoolGetLargeBufferPadding(worker_pool),
                                       bufferpoolGetSmallBufferPadding(worker_pool));

    if (! deviceWriterChannelOpen(&tdev->writer_channel, kTunWriteChannelQueueMax))
    {
        LOGE("TunDevice: failed to open writer channel");
        tunLifecycleTransitionStoppingToDown(&tdev->lifecycle);
        return false;
    }
    if (deviceReaderSessionBegin(tdev->reader_session) == 0)
    {
        LOGE("TunDevice: failed to open reader delivery generation");
        deviceWriterChannelClose(&tdev->writer_channel);
        discard deviceWriterChannelRetireCurrent(&tdev->writer_channel);
        tunLifecycleTransitionStoppingToDown(&tdev->lifecycle);
        return false;
    }

    if (! tunSetStateByName(tdev->name, true))
    {
        LOGE("TunDevice: error bringing device %s up", tdev->name);
        tundeviceCloseLifetimeGates(tdev);
        discard deviceWriterChannelRetireCurrent(&tdev->writer_channel);
        tunLifecycleTransitionStoppingToDown(&tdev->lifecycle);
        return false;
    }

    if (tdev->read_event_callback != NULL)
    {
        tundeviceDrainStopPipe(tdev);
        wthread_error_t error = threadCreate(&tdev->read_thread, tundeviceReaderThreadMain, tdev);
        if (UNLIKELY(error != kWThreadErrorNone))
        {
            LOGE("TunDevice: failed to create reader thread: error %u (%s)", error, strerror((int) error));
            goto rollback;
        }
        tdev->reader_joinable = true;

        if (tunLifecycleLoad(&tdev->lifecycle) == kTunLifecycleFailed)
        {
            goto rollback;
        }
    }

    wthread_error_t error = threadCreate(&tdev->write_thread, tundeviceWriterThreadMain, tdev);
    if (UNLIKELY(error != kWThreadErrorNone))
    {
        LOGE("TunDevice: failed to create writer thread: error %u (%s)", error, strerror((int) error));
        goto rollback;
    }

    tdev->writer_joinable = true;

    if (! tunLifecycleTransitionStartingToUp(&tdev->lifecycle))
    {
        LOGE("TunDevice: an I/O thread failed during startup");
        goto rollback;
    }

    LOGI("TunDevice: device %s is now up", tdev->name);
    return true;

rollback:
    tunLifecycleTransitionToStopping(&tdev->lifecycle);
    tundeviceCloseLifetimeGates(tdev);

    bool rollback_ok = tunSetStateByName(tdev->name, false);
    if (! rollback_ok)
    {
        LOGE("TunDevice: error restoring %s down after startup failure", tdev->name);
    }

    if (tdev->reader_joinable)
    {
        ssize_t write_res = write(tdev->linux_pipe_fds[1], "x", 1);
        discard write_res;

        if (safeThreadJoin(tdev->read_thread))
        {
            tundeviceDrainStopPipe(tdev);
            tdev->reader_joinable = false;
            // Close, join, retire: End poisons the fragment generation but leaves
            // its staged reader buffers alone, because the reader still owned this
            // pool. Only here does the lifecycle thread own it.
            bufferpoolResetThreadOwnership(tdev->reader_buffer_pool);
            deviceReaderSessionRetireGenerationBuffers(tdev->reader_session);
        }
        else
        {
            LOGE("TunDevice: failed to join reader during startup rollback");
            rollback_ok = false;
        }
    }
    if (tdev->writer_joinable)
    {
        if (safeThreadJoin(tdev->write_thread))
        {
            tdev->writer_joinable = false;
            bufferpoolResetThreadOwnership(tdev->writer_buffer_pool);
        }
        else
        {
            LOGE("TunDevice: failed to join writer during startup rollback");
            rollback_ok = false;
        }
    }

    if (! tdev->reader_joinable && ! tdev->writer_joinable && ! deviceWriterChannelRetireCurrent(&tdev->writer_channel))
    {
        rollback_ok = false;
    }

    if (rollback_ok)
    {
        tunLifecycleTransitionStoppingToDown(&tdev->lifecycle);
    }
    return false;
}

bool tundeviceBringDown(tun_device_t *tdev)
{
    // A previous interface-down failure retains STOPPING after the threads and
    // channel have been released. Keep retrying until that last owned operation
    // succeeds and DOWN can be published.
    if (tunLifecycleLoad(&tdev->lifecycle) == kTunLifecycleDown && ! tdev->reader_joinable && ! tdev->writer_joinable &&
        ! deviceWriterChannelHasCurrent(&tdev->writer_channel))
    {
        LOGE("TunDevice: device is already down");
        return true;
    }

    tunLifecycleTransitionToStopping(&tdev->lifecycle);
    tundeviceCloseLifetimeGates(tdev);

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

    if (tdev->reader_joinable)
    {
        ssize_t write_res = write(tdev->linux_pipe_fds[1], "x", 1);
        discard write_res;

        if (safeThreadJoin(tdev->read_thread))
        {
            tundeviceDrainStopPipe(tdev);
            tdev->reader_joinable = false;
            // Close, join, retire: End poisons the fragment generation but leaves
            // its staged reader buffers alone, because the reader still owned this
            // pool. Only here does the lifecycle thread own it.
            bufferpoolResetThreadOwnership(tdev->reader_buffer_pool);
            deviceReaderSessionRetireGenerationBuffers(tdev->reader_session);
        }
        else
        {
            LOGE("TunDevice: failed to join reader thread; retaining reader resources");
            bring_down_ok = false;
        }
    }
    if (tdev->writer_joinable)
    {
        if (safeThreadJoin(tdev->write_thread))
        {
            tdev->writer_joinable = false;
            bufferpoolResetThreadOwnership(tdev->writer_buffer_pool);
        }
        else
        {
            LOGE("TunDevice: failed to join writer thread; retaining writer resources");
            bring_down_ok = false;
        }
    }

    if (! tdev->reader_joinable && ! tdev->writer_joinable && ! deviceWriterChannelRetireCurrent(&tdev->writer_channel))
    {
        bring_down_ok = false;
    }

    if (bring_down_ok)
    {
        tunLifecycleTransitionStoppingToDown(&tdev->lifecycle);
    }

    return bring_down_ok;
}

static int tunDarwinOpen(const char *name, char actual_name[IFNAMSIZ])
{
    struct ctl_info     ci;
    struct sockaddr_ctl sc;
    int                 fd = -1;

    memoryZero(&ci, sizeof(ci));
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

    memoryZero(&sc, sizeof(sc));
    sc.sc_id      = ci.ctl_id;
    sc.sc_len     = sizeof(sc);
    sc.sc_family  = AF_SYSTEM;
    sc.ss_sysaddr = AF_SYS_CONTROL;
    sc.sc_unit    = 0;

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

    if (! tunSetNonBlocking(fd))
    {
        close(fd);
        return -1;
    }
    return fd;
}

tun_device_t *tundeviceCreate(const char *name, bool offload, uint16_t mtu, void *userdata, TunReadEventHandle cb)
{
    discard offload;
    if (mtu <= 16)
    {
        LOGE("TunDevice: Invalid MTU size: %u", mtu);
        return NULL;
    }

    char actual_name[IFNAMSIZ];
    memoryZero(actual_name, sizeof(actual_name));

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

    /*
     * Device bring-up/creation runs on an event worker even though the reader
     * and writer threads it manages stay unregistered. Read that worker's pool
     * geometry once here and copy it onto the device-owned pools; the auxiliary
     * threads never touch worker-local state themselves.
     */
    buffer_pool_t *worker_pool = getCurrentEventWorkerBufferPool();

    uint32_t worker_large_buffer_size = bufferpoolGetLargeBufferSize(worker_pool);
    uint32_t worker_small_buffer_size = bufferpoolGetSmallBufferSize(worker_pool);
    worker_small_buffer_size          = max(worker_small_buffer_size, (uint32_t) mtu + sizeof(uint32_t));

    buffer_pool_t *reader_bpool = bufferpoolCreate(GSTATE.masterpool_buffer_pools_large,
                                                   GSTATE.masterpool_buffer_pools_small,
                                                   RAM_PROFILE,
                                                   worker_large_buffer_size,
                                                   worker_small_buffer_size);
    if (UNLIKELY(reader_bpool == NULL))
    {
        LOGE("TunDevice: failed to construct reader buffer pool");
        close(fd);
        return NULL;
    }

    buffer_pool_t *writer_bpool = bufferpoolCreate(GSTATE.masterpool_buffer_pools_large,
                                                   GSTATE.masterpool_buffer_pools_small,
                                                   RAM_PROFILE,
                                                   worker_large_buffer_size,
                                                   worker_small_buffer_size);
    if (UNLIKELY(writer_bpool == NULL))
    {
        LOGE("TunDevice: failed to construct writer buffer pool");
        bufferpoolDestroy(reader_bpool);
        close(fd);
        return NULL;
    }

    tun_device_t *tdev = memoryAllocate(sizeof(tun_device_t));
    if (UNLIKELY(tdev == NULL))
    {
        bufferpoolDestroy(reader_bpool);
        bufferpoolDestroy(writer_bpool);
        close(fd);
        return NULL;
    }
    char *device_name = stringDuplicate(actual_name);
    if (UNLIKELY(device_name == NULL))
    {
        memoryFree(tdev);
        bufferpoolDestroy(reader_bpool);
        bufferpoolDestroy(writer_bpool);
        close(fd);
        return NULL;
    }
    *tdev = (tun_device_t) {.name                = device_name,
                            .routine_reader      = routineReadFromTun,
                            .routine_writer      = routineWriteToTun,
                            .handle              = fd,
                            .read_event_callback = cb,
                            .userdata            = userdata,
                            .reader_session      = NULL,
                            .reader_buffer_pool  = reader_bpool,
                            .writer_buffer_pool  = writer_bpool,
                            .mtu                 = mtu};
    atomic_init(&tdev->lifecycle, kTunLifecycleDown);
    deviceWriterChannelInit(&tdev->writer_channel);
    tdev->reader_session =
        deviceReaderSessionCreate(RAM_PROFILE * 2, kMaxReadDistributeQueueSize, tdev, tunDeliverPacket, reader_bpool);
    if (UNLIKELY(tdev->reader_session == NULL))
    {
        LOGE("TunDevice: failed to allocate reader session");
        discard deviceWriterChannelDestroy(&tdev->writer_channel);
        memoryFree(tdev->name);
        bufferpoolDestroy(tdev->reader_buffer_pool);
        bufferpoolDestroy(tdev->writer_buffer_pool);
        close(tdev->handle);
        memoryFree(tdev);
        return NULL;
    }

    if (pipe(tdev->linux_pipe_fds) != 0)
    {
        LOGE("TunDevice: failed to create stop pipe");
        memoryFree(tdev->name);
        deviceReaderSessionRetireProducerBuffers(tdev->reader_session);
        bufferpoolDestroy(tdev->reader_buffer_pool);
        bufferpoolDestroy(tdev->writer_buffer_pool);
        deviceReaderSessionUnref(tdev->reader_session);
        close(tdev->handle);
        memoryFree(tdev);
        return NULL;
    }

    return tdev;
}

void tundeviceDestroy(tun_device_t *tdev)
{
    // Unconditional: bring-down is a no-op when nothing is owned, and gating this
    // on readiness would skip cleanup after a thread died on its own.
    if (! tundeviceBringDown(tdev))
    {
        /*
         * Interface cleanup did not complete, so the validity of the remaining
         * device state is unknown and continuing to free it would be a
         * use-after-free risk. Hard-abort with an explicit diagnostic rather
         * than trying to run more cleanup. Mirrors tun_linux.c.
         */
        LOGF("TunDevice: refusing to destroy device while interface cleanup is incomplete");
        abortProgramNow(1);
    }
    /*
     * Device destruction follows worker/lwIP shutdown, so no producer can
     * retain a generation pointer while retired queues are reclaimed.
     */
    if (! deviceWriterChannelDestroy(&tdev->writer_channel))
    {
        LOGF("TunDevice: refusing to destroy a published writer generation");
        abortProgramNow(1);
    }
    memoryFree(tdev->name);
    deviceReaderSessionRetireProducerBuffers(tdev->reader_session);
    bufferpoolDestroy(tdev->reader_buffer_pool);
    bufferpoolDestroy(tdev->writer_buffer_pool);
    close(tdev->handle);
    close(tdev->linux_pipe_fds[0]);
    close(tdev->linux_pipe_fds[1]);
    deviceReaderSessionUnref(tdev->reader_session);
    memoryFree(tdev);
}

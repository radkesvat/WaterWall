#include "devices/device_flow_affinity.h"
#include "devices/device_reader_session.h"
#include "devices/device_writer_channel.h"
#include "devices/tun/tun_io_error.h"
#include "devices/tun/tun_lifecycle.h"
#include "generic_pool.h"
#include "global_state.h"
#include "loggers/internal_logger.h"
#include "tun.h"
#include "tun_linux_internal.h"
#include "watomic.h"
#include "wchan.h"
#include "wplatform.h"
#include "wproc.h"
#include "wthread.h"
#include "wtime.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <poll.h>
#include <sys/ioctl.h>

#ifdef OS_LINUX
#include <linux/if.h>
#include <linux/if_tun.h>
#include <linux/ipv6.h>
#elif defined(OS_BSD)
#include <net/if.h>
#include <net/if_tun.h>
#else
#error "Unsupported OS"
#endif

enum
{
    kTunWriteChannelQueueMax    = 128 * 1024,
    kMaxReadDistributeQueueSize = 512,
    kTunReaderStopPollMs        = 100,
    kLinuxRouteFlagUp           = 0x1,
    kLinuxRouteFlagGateway      = 0x2
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
    bool reader_generation_open;
};

static inline uint16_t tunDeviceMtu(const tun_device_t *tdev)
{
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

static bool tunSetCloseOnExec(int fd)
{
    int flags = fcntl(fd, F_GETFD, 0);
    return flags >= 0 && fcntl(fd, F_SETFD, flags | FD_CLOEXEC) == 0;
}

static bool tunCreateStopPipe(int fds[2])
{
#if defined(OS_LINUX)
    if (pipe2(fds, O_NONBLOCK | O_CLOEXEC) == 0)
    {
        return true;
    }
    if (errno != ENOSYS && errno != EINVAL)
    {
        return false;
    }
#endif
    if (pipe(fds) != 0)
    {
        return false;
    }
    if (tunSetNonBlocking(fds[0]) && tunSetNonBlocking(fds[1]) && tunSetCloseOnExec(fds[0]) &&
        tunSetCloseOnExec(fds[1]))
    {
        return true;
    }
    discard close(fds[0]);
    discard close(fds[1]);
    fds[0] = -1;
    fds[1] = -1;
    return false;
}

static bool tunSetMtuByName(const char *name, uint16_t mtu)
{
    int sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock_fd < 0)
    {
        LOGE("TunDevice: failed to create socket for MTU setting");
        return false;
    }

    struct ifreq ifr;
    memoryZero(&ifr, sizeof(ifr));
    stringCopyN(ifr.ifr_name, name, IFNAMSIZ);
    ifr.ifr_name[IFNAMSIZ - 1] = '\0';
    ifr.ifr_mtu                = mtu;

    bool ok = true;
    if (ioctl(sock_fd, SIOCSIFMTU, &ifr) < 0)
    {
        LOGE("TunDevice: failed to set MTU to %u for %s: %s", mtu, ifr.ifr_name, strerror(errno));
        ok = false;
    }

    close(sock_fd);
    return ok;
}

static bool tunSetStateByName(const char *name, bool up)
{
    int sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock_fd < 0)
    {
        LOGE("TunDevice: failed to create socket for interface state setting");
        return false;
    }

    struct ifreq ifr;
    memoryZero(&ifr, sizeof(ifr));
    stringCopyN(ifr.ifr_name, name, IFNAMSIZ);
    ifr.ifr_name[IFNAMSIZ - 1] = '\0';

    bool ok = true;
    if (ioctl(sock_fd, SIOCGIFFLAGS, &ifr) < 0)
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

    if (ioctl(sock_fd, SIOCSIFFLAGS, &ifr) < 0)
    {
        LOGE("TunDevice: failed to set interface flags for %s: %s", name, strerror(errno));
        ok = false;
    }

done:
    close(sock_fd);
    return ok;
}

#ifdef OS_LINUX
static bool tunDefaultRouteHexIsZero(const char *hex)
{
    for (const char *p = hex; *p != '\0'; ++p)
    {
        if (*p != '0')
        {
            return false;
        }
    }
    return true;
}

static bool tunGetIfIndexByName(const char *name, uint32_t *out_index)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
    {
        return false;
    }

    struct ifreq ifr;
    memoryZero(&ifr, sizeof(ifr));
    stringCopyN(ifr.ifr_name, name, IFNAMSIZ);
    ifr.ifr_name[IFNAMSIZ - 1] = '\0';

    bool ok = ioctl(fd, SIOCGIFINDEX, &ifr) == 0 && ifr.ifr_ifindex > 0;
    if (ok)
    {
        *out_index = (uint32_t) ifr.ifr_ifindex;
    }

    close(fd);
    return ok;
}

static bool tunDetectDefaultRouteV4(char *ifname, size_t ifname_len)
{
    FILE *fp = fopen("/proc/net/route", "r");
    if (fp == NULL)
    {
        return false;
    }

    char line[512];
    if (fgets(line, sizeof(line), fp) == NULL)
    {
        fclose(fp);
        return false;
    }

    char         best_iface[64] = {0};
    unsigned int best_metric    = UINT32_MAX;
    bool         found          = false;
    while (fgets(line, sizeof(line), fp) != NULL)
    {
        char          iface[64];
        unsigned long destination = 0;
        unsigned long gateway     = 0;
        unsigned int  flags       = 0;
        unsigned int  refcnt      = 0;
        unsigned int  use         = 0;
        unsigned int  metric      = 0;
        unsigned long mask        = 0;

        int fields = sscanf(
            line, "%63s %lx %lx %x %u %u %u %lx", iface, &destination, &gateway, &flags, &refcnt, &use, &metric, &mask);
        discard gateway;
        discard refcnt;
        discard use;

        if (fields == 8 && destination == 0 && mask == 0 &&
            (flags & (kLinuxRouteFlagUp | kLinuxRouteFlagGateway)) == (kLinuxRouteFlagUp | kLinuxRouteFlagGateway) &&
            metric < best_metric)
        {
            stringCopyN(best_iface, iface, sizeof(best_iface));
            best_metric = metric;
            found       = true;
        }
    }

    if (found)
    {
        stringCopyN(ifname, best_iface, ifname_len);
    }

    fclose(fp);
    return found;
}

static bool tunDetectDefaultRouteV6(char *ifname, size_t ifname_len)
{
    FILE *fp = fopen("/proc/net/ipv6_route", "r");
    if (fp == NULL)
    {
        return false;
    }

    char         line[512];
    char         best_iface[64] = {0};
    unsigned int best_metric    = UINT32_MAX;
    bool         found          = false;
    while (fgets(line, sizeof(line), fp) != NULL)
    {
        char         destination[33];
        unsigned int destination_prefix = 0;
        char         source[33];
        unsigned int source_prefix = 0;
        char         next_hop[33];
        unsigned int metric = 0;
        unsigned int refcnt = 0;
        unsigned int use    = 0;
        unsigned int flags  = 0;
        char         iface[64];

        int     fields = sscanf(line,
                            "%32s %x %32s %x %32s %x %x %x %x %63s",
                            destination,
                            &destination_prefix,
                            source,
                            &source_prefix,
                            next_hop,
                            &metric,
                            &refcnt,
                            &use,
                            &flags,
                            iface);
        discard source;
        discard source_prefix;
        discard next_hop;
        discard refcnt;
        discard use;

        if (fields == 10 && destination_prefix == 0 && tunDefaultRouteHexIsZero(destination) &&
            (flags & (kLinuxRouteFlagUp | kLinuxRouteFlagGateway)) == (kLinuxRouteFlagUp | kLinuxRouteFlagGateway) &&
            metric < best_metric)
        {
            stringCopyN(best_iface, iface, sizeof(best_iface));
            best_metric = metric;
            found       = true;
        }
    }

    if (found)
    {
        stringCopyN(ifname, best_iface, ifname_len);
    }

    fclose(fp);
    return found;
}

bool tundeviceDetectDefaultInterface(tun_default_route_t *out)
{
    memoryZero(out, sizeof(*out));

    char ifname_v4[64] = {0};
    char ifname_v6[64] = {0};

    if (tunDetectDefaultRouteV4(ifname_v4, sizeof(ifname_v4)))
    {
        out->have_v4 = tunGetIfIndexByName(ifname_v4, &out->ifindex_v4);
    }

    if (tunDetectDefaultRouteV6(ifname_v6, sizeof(ifname_v6)))
    {
        out->have_v6 = tunGetIfIndexByName(ifname_v6, &out->ifindex_v6);
    }

    if (out->have_v4)
    {
        stringCopyN(out->ifname, ifname_v4, sizeof(out->ifname));
    }
    else if (out->have_v6)
    {
        stringCopyN(out->ifname, ifname_v6, sizeof(out->ifname));
    }

    return out->have_v4 || out->have_v6;
}
#else
bool tundeviceDetectDefaultInterface(tun_default_route_t *out)
{
    memoryZero(out, sizeof(*out));
    return false;
}
#endif

#ifdef OS_LINUX
enum
{
    kTunRpFilterPollMs   = 10,
    kTunRpFilterStableMs = 300,
    kTunRpFilterBudgetMs = 2000
};

static bool tunReversePathFilterScopeIsSafe(const char *scope)
{
    if (scope == NULL || scope[0] == '\0' || stringCompare(scope, ".") == 0 || stringCompare(scope, "..") == 0)
    {
        return false;
    }

    for (const char *p = scope; *p != '\0'; ++p)
    {
        if (! (isalnum((unsigned char) *p) || *p == '_' || *p == '-' || *p == '.' || *p == ':'))
        {
            return false;
        }
    }

    return true;
}

static bool tunReversePathFilterPath(const char *scope, char *path, size_t path_size)
{
    static const char proc_conf_dir[] = "/proc/sys/net/ipv4/conf";

    if (! tunReversePathFilterScopeIsSafe(scope))
    {
        LOGE("TunDevice: invalid reverse path filter interface scope %s", scope != NULL ? scope : "<null>");
        return false;
    }

    int written = stringNPrintf(path, path_size, "%s/%s/rp_filter", proc_conf_dir, scope);
    if (written < 0 || (size_t) written >= path_size)
    {
        LOGE("TunDevice: reverse path filter path is too long for interface scope %s", scope);
        return false;
    }

    return true;
}

static bool tunWriteReversePathFilterValue(const char *path, int value)
{
    int fd;
    do
    {
        fd = open(path, O_WRONLY | O_CLOEXEC);
    } while (fd < 0 && errno == EINTR);

    if (fd < 0)
    {
        if (errno == ENOENT)
        {
            return true;
        }
        LOGE("TunDevice: failed to open %s for reverse path filter update: %s", path, strerror(errno));
        return false;
    }

    char value_buf[16];
    int  written = stringNPrintf(value_buf, sizeof(value_buf), "%d\n", value);
    if (written < 0 || (size_t) written >= sizeof(value_buf))
    {
        LOGE("TunDevice: reverse path filter value is too large for %s", path);
        close(fd);
        return false;
    }

    const char *cursor = value_buf;
    size_t      left   = (size_t) written;
    bool        ok     = true;

    while (left > 0)
    {
        ssize_t nwrite = write(fd, cursor, left);
        if (nwrite < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }
            LOGE("TunDevice: failed to write %s: %s", path, strerror(errno));
            ok = false;
            break;
        }

        if (nwrite == 0)
        {
            LOGE("TunDevice: short write while updating %s", path);
            ok = false;
            break;
        }

        cursor += nwrite;
        left -= (size_t) nwrite;
    }

    if (close(fd) != 0)
    {
        LOGE("TunDevice: failed to close %s after reverse path filter update: %s", path, strerror(errno));
        ok = false;
    }

    return ok;
}

static int tunReadReversePathFilterValue(const char *path)
{
    int fd;
    do
    {
        fd = open(path, O_RDONLY | O_CLOEXEC);
    } while (fd < 0 && errno == EINTR);

    if (fd < 0)
    {
        return -1;
    }

    char    value_buf[16];
    ssize_t nread;
    do
    {
        nread = read(fd, value_buf, sizeof(value_buf) - 1);
    } while (nread < 0 && errno == EINTR);

    close(fd);

    if (nread <= 0)
    {
        return -1;
    }

    value_buf[nread] = '\0';
    return (int) strtol(value_buf, NULL, 10);
}

/*
 * Writing the per-interface entry once is not enough on a freshly created
 * device. udev fires an "add" event for every new interface, and the systemd
 * rule that ships with 99-systemd.rules answers it by running
 *
 *     systemd-sysctl --prefix=/net/ipv4/conf/<ifname> ...
 *
 * which re-applies the "net.ipv4.conf.*.rp_filter" pattern from sysctl.d and
 * puts the distribution default straight back. That pass lands a few
 * milliseconds after the interface appears, so it reliably lands after the
 * write here. It is a one-shot per device, so re-apply the value until it has
 * survived untouched for kTunRpFilterStableMs and the udev pass is provably
 * over.
 */
static bool tunHoldReversePathFilterValue(const char *path, int value)
{
    if (! tunWriteReversePathFilterValue(path, value))
    {
        return false;
    }

    const unsigned int started_at   = getTickMS();
    unsigned int       stable_since = started_at;

    for (;;)
    {
        unsigned int now = getTickMS();
        if (now - stable_since >= kTunRpFilterStableMs)
        {
            return true;
        }

        if (now - started_at >= kTunRpFilterBudgetMs)
        {
            LOGE("TunDevice: %s keeps being reset by the system; reverse path filtering stays enabled", path);
            return false;
        }

        wwSleepMS(kTunRpFilterPollMs);

        int current = tunReadReversePathFilterValue(path);
        if (current < 0)
        {
            // The entry went away with the interface; nothing left to hold down.
            return true;
        }

        if (current != value)
        {
            if (! tunWriteReversePathFilterValue(path, value))
            {
                return false;
            }
            stable_since = getTickMS();
        }
    }
}

static bool tunDisableReversePathFilterScope(const char *scope, bool hold)
{
    char path[256];
    if (! tunReversePathFilterPath(scope, path, sizeof(path)))
    {
        return false;
    }

    if (hold)
    {
        return tunHoldReversePathFilterValue(path, 0);
    }

    return tunWriteReversePathFilterValue(path, 0);
}

bool tundeviceDisableReversePathFiltering(const char *ifname)
{
    bool ok = true;

    /*
     * The kernel filters on max(conf.all.rp_filter, conf.<ifname>.rp_filter),
     * so both scopes have to reach 0 before packets arriving on the TUN stop
     * being dropped. Only the per-interface entry races the udev pass described
     * above, so only that one is held down.
     */
    ok = tunDisableReversePathFilterScope("all", false) && ok;
    ok = tunDisableReversePathFilterScope(ifname, true) && ok;
    if (ok)
    {
        LOGI("TunDevice: disabled Linux reverse path filtering for all and %s", ifname);
    }

    return ok;
}
#else
bool tundeviceDisableReversePathFiltering(const char *ifname)
{
    discard ifname;
    return true;
}
#endif

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

static bool routeTableArgIsSafe(const char *route_table)
{
    if (route_table == NULL)
    {
        return true;
    }

    if (route_table[0] == '\0')
    {
        return false;
    }

    for (const char *p = route_table; *p != '\0'; ++p)
    {
        if (! (isalnum((unsigned char) *p) || *p == '_' || *p == '-' || *p == '.'))
        {
            return false;
        }
    }

    return true;
}

static int tunRunCommand(const char *command_name, const char *const argv[])
{
    long  open_max = execCmdOpenMax();
    pid_t childpid = fork();
    if (childpid < 0)
    {
        LOGE("TunDevice: failed to fork for %s: %s", command_name, strerror(errno));
        return -1;
    }

    if (childpid == 0)
    {
        execCmdCloseInheritedFds(open_max);
        execvp(command_name, (char *const *) argv);
        perror(command_name);
        _exit(127);
    }

    int status = 0;
    while (waitpid(childpid, &status, 0) < 0)
    {
        if (errno == EINTR)
        {
            continue;
        }

        LOGE("TunDevice: failed to wait for %s: %s", command_name, strerror(errno));
        return -1;
    }

    if (WIFEXITED(status))
    {
        return WEXITSTATUS(status);
    }

    if (WIFSIGNALED(status))
    {
        LOGE("TunDevice: %s terminated by signal %d", command_name, WTERMSIG(status));
    }

    return -1;
}

#ifndef OS_LINUX
static bool tunFormatIpPrefixArg(char *buffer, size_t buffer_size, const char *ip_presentation, unsigned int subnet)
{
    int written = stringNPrintf(buffer, buffer_size, "%s/%u", ip_presentation, subnet);
    return written >= 0 && (size_t) written < buffer_size;
}
#endif

static void tunDeliverPacket(void *device, sbuf_t *buf, wid_t wid)
{
    tun_device_t *tdev = device;
    tdev->read_event_callback(tdev, tdev->userdata, buf, wid);
}

// Hands whatever the drain cycle has already read to the reader session. Every
// exit from tunDrainPackets() goes through this, so a device error never
// strands packets that were read successfully before it.
static void tunFlushReadBatch(tun_device_t *tdev, sbuf_t **bufs, uint16_t queued_count)
{
    if (queued_count > 0)
    {
        deviceFlowAffinityPostBatch(tdev->reader_session, bufs, queued_count);
    }
}

// Drains packets from the TUN device after POLLIN. Every accumulated buffer is
// handed to the reader session before returning, on every path.
static tun_drain_result_t tunDrainPackets(tun_device_t *tdev)
{
    uint16_t queued_count = 0;
    sbuf_t  *bufs[kMaxReadDistributeQueueSize];
    uint32_t read_size = tunDeviceMtu(tdev);

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
            tunFlushReadBatch(tdev, bufs, queued_count);
            return kTunDrainEndOfStream;
        }

        if (nread < 0)
        {
            // errno is only meaningful right here: recycling the buffer and the
            // loggers below can both overwrite it.
            const int saved_errno = errno;
            bufferpoolReuseBuffer(tdev->reader_buffer_pool, bufs[queued_count]);
            tunFlushReadBatch(tdev, bufs, queued_count);

            if (tunIoErrnoIsTransient(saved_errno))
            {
                // No more packets for now; end this cycle and go back to poll().
                return kTunDrainAgain;
            }

            /*
             * Anything else (EIO, EBADF, ENODEV, ENXIO, ...) means this handle
             * will not produce packets again. Returning "keep polling" here made
             * the reader spin on a permanently readable dead fd while every
             * packet vanished, so the loss is reported instead.
             */
            LOGE("TunDevice: unrecoverable read error on device %s, errno is %d (%s)",
                 tdev->name,
                 saved_errno,
                 strerror(saved_errno));
            return kTunDrainDeviceError;
        }

        if (TUN_LOG_EVERYTHING)
        {
            LOGD("TunDevice: read %d bytes from device %s", nread, tdev->name);
        }

        sbufSetLength(bufs[queued_count], nread);

        if (UNLIKELY(sbufGetLength(bufs[queued_count]) > read_size))
        {
            LOGE("TunDevice: ReadThread: read packet size %d exceeds device MTU %u",
                 sbufGetLength(bufs[queued_count]),
                 read_size);
            LOGF("TunDevice: This is related to the MTU size, please set a correct value for TunDevice 'device-mtu'");
            bufferpoolReuseBuffer(tdev->reader_buffer_pool, bufs[queued_count]);

            /*
             * A misconfigured MTU is fatal for the process, but this runs on the
             * device reader thread. Release everything this thread owns - the
             * oversized buffer above, plus the batch accumulated so far - and
             * report the loss so the read routine leaves through its normal exit
             * path. tundeviceNoteUnexpectedThreadExit() then publishes the
             * failure and owns the shutdown decision.
             */
            tunFlushReadBatch(tdev, bufs, queued_count);
            return kTunDrainDeviceError;
        }

        queued_count++;
    }

    // Distribute all accumulated packets in one batch
    tunFlushReadBatch(tdev, bufs, queued_count);

    return kTunDrainAgain;
}

static void tunLogReaderPollError(tun_device_t *tdev, short revents)
{
    int       socket_error = 0;
    socklen_t err_len      = sizeof(socket_error);
    getsockopt(tdev->handle, SOL_SOCKET, SO_ERROR, &socket_error, &err_len);
    LOGE("TunDevice: Exit read routine due to socket error event: %s%s%s, socket error: %d (%s)",
         (revents & POLLERR) ? "POLLERR " : "",
         (revents & POLLHUP) ? "POLLHUP " : "",
         (revents & POLLNVAL) ? "POLLNVAL " : "",
         socket_error,
         strerror(socket_error));
}

// Routine to read from TUN device
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
        int ret = poll(fds, 2, kTunReaderStopPollMs);

        if (ret < 0)
        {
            if (errno == EINTR)
            {
                continue; // Interrupted by signal, just retry
            }
            LOGE("TunDevice: Exit read routine due to poll failed with error %d (%s)", errno, strerror(errno));
            break;
        }

        if (ret == 0)
        {
            continue;
        }

        if (fds[1].revents & POLLIN)
        {
            char    drain_byte;
            ssize_t drain_res = read(tdev->linux_pipe_fds[0], &drain_byte, 1);
            discard drain_res;
            LOGW("TunDevice: Exit read routine due to pipe event");
            break;
        }

        // Check for socket errors
        if (fds[0].revents & (POLLERR | POLLHUP | POLLNVAL))
        {
            tunLogReaderPollError(tdev, fds[0].revents);
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

        // If we get here, poll returned > 0 but none of our expected events occurred
        LOGE("TunDevice: Exit read routine due to unexpected poll events - fd[0].revents=0x%x, fd[1].revents=0x%x",
             fds[0].revents,
             fds[1].revents);
        return 0;
    }

    return 0;
}

// Routine to write to TUN device
static WTHREAD_ROUTINE(routineWriteToTun)
{
    tun_device_t   *tdev = userdata;
    sbuf_t         *buf;
    ssize_t         nwrite;
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

        nwrite = write(tdev->handle, sbufGetRawPtr(buf), sbufGetLength(buf));
        // errno is only meaningful right here. Recycling the buffer and every
        // logger below may overwrite it, so classification must read this copy.
        const int write_errno = (nwrite < 0) ? errno : 0;
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
             */
            LOGE("TunDevice: Exit write routine due to an unrecoverable write error on device %s, errno %d (%s)",
                 tdev->name,
                 write_errno,
                 strerror(write_errno));
            return 0;
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

/* Failure-only TLS sampler. Full is ordinary bounded overload and deliberately
 * silent; Down/Closed keep sparse lifecycle evidence without a shared limiter. */
static bool tundeviceShouldLogRefusal(void)
{
    static thread_local uint32_t refusal_count;
    const uint32_t               ordinal = ++refusal_count;

    return ordinal == 1 || (ordinal & (ordinal - 1U)) == 0;
}

// Write to TUN device
bool tundeviceWrite(tun_device_t *tdev, sbuf_t *buf)
{
#if ! defined(OS_BSD)
    assert(sbufGetLength(buf) > sizeof(struct iphdr));
#endif

    switch (deviceWriterChannelTrySend(&tdev->writer_channel, buf))
    {
    case kDeviceWriterSendOk:
        return true;
    case kDeviceWriterSendDown:
        if (tundeviceShouldLogRefusal())
        {
            LOGE("TunDevice: write failed, device is down");
        }
        return false;
    case kDeviceWriterSendClosed:
        if (tundeviceShouldLogRefusal())
        {
            LOGE("TunDevice: write failed, channel was closed");
        }
        return false;
    case kDeviceWriterSendFull:
        return false;
    }

    return false;
}

static void tundeviceCloseLifetimeGates(tun_device_t *tdev)
{
    deviceWriterChannelClose(&tdev->writer_channel);
    deviceReaderSessionEndRequest(tdev->reader_session);
}

static void tundeviceRetireReaderGeneration(tun_device_t *tdev)
{
    if (! tdev->reader_generation_open)
    {
        return;
    }
    bufferpoolResetThreadOwnership(tdev->reader_buffer_pool);
    deviceReaderSessionRetireGenerationBuffers(tdev->reader_session);
    tdev->reader_generation_open = false;
}

static bool tundeviceSignalReaderStop(tun_device_t *tdev)
{
    if (! tdev->reader_joinable)
    {
        return true;
    }

    ssize_t write_res;
    do
    {
        write_res = write(tdev->linux_pipe_fds[1], "x", 1);
    } while (write_res < 0 && errno == EINTR);

    return write_res == 1 || (write_res < 0 && (errno == EAGAIN || errno == EWOULDBLOCK));
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

// Unassign IP address from TUN device
bool tundeviceUnAssignIP(tun_device_t *tdev, const char *ip_presentation, unsigned int subnet)
{
#ifdef OS_LINUX
    int family = strchr(ip_presentation, ':') != NULL ? AF_INET6 : AF_INET;
    int fd     = socket(family, SOCK_DGRAM, 0);
    if (fd < 0)
    {
        LOGE("TunDevice: failed to create socket for IP removal: %s", strerror(errno));
        return false;
    }

    bool ok = true;
    if (family == AF_INET)
    {
        struct ifreq ifr;
        memoryZero(&ifr, sizeof(ifr));
        stringCopyN(ifr.ifr_name, tdev->name, IFNAMSIZ);
        ifr.ifr_name[IFNAMSIZ - 1] = '\0';

        struct sockaddr_in *addr = (struct sockaddr_in *) &ifr.ifr_addr;
        addr->sin_family         = AF_INET;
        if (inet_pton(AF_INET, ip_presentation, &addr->sin_addr) != 1)
        {
            LOGE("TunDevice: Cannot unset IP -> Invalid IPv4 address: %s", ip_presentation);
            ok = false;
            goto linux_done;
        }

        if (ioctl(fd, SIOCDIFADDR, &ifr) < 0 && errno != EADDRNOTAVAIL)
        {
            LOGE("TunDevice: error unassigning IPv4 address from %s: %s", tdev->name, strerror(errno));
            ok = false;
        }
    }
    else
    {
        struct ifreq ifr;
        memoryZero(&ifr, sizeof(ifr));
        stringCopyN(ifr.ifr_name, tdev->name, IFNAMSIZ);
        ifr.ifr_name[IFNAMSIZ - 1] = '\0';
        if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0)
        {
            LOGE("TunDevice: failed to get interface index for %s: %s", tdev->name, strerror(errno));
            ok = false;
            goto linux_done;
        }

        struct in6_ifreq ifr6;
        memoryZero(&ifr6, sizeof(ifr6));
        ifr6.ifr6_ifindex   = ifr.ifr_ifindex;
        ifr6.ifr6_prefixlen = subnet;
        if (inet_pton(AF_INET6, ip_presentation, &ifr6.ifr6_addr) != 1)
        {
            LOGE("TunDevice: Cannot unset IP -> Invalid IPv6 address: %s", ip_presentation);
            ok = false;
            goto linux_done;
        }

        if (ioctl(fd, SIOCDIFADDR, &ifr6) < 0 && errno != EADDRNOTAVAIL)
        {
            LOGE("TunDevice: error unassigning IPv6 address from %s: %s", tdev->name, strerror(errno));
            ok = false;
        }
    }

linux_done:
    close(fd);
    if (ok)
    {
        LOGD("TunDevice: ip address removed from %s", tdev->name);
    }
    return ok;
#else
    char ip_prefix[INET6_ADDRSTRLEN + 12];

    if (! tunFormatIpPrefixArg(ip_prefix, sizeof(ip_prefix), ip_presentation, subnet))
    {
        LOGE("TunDevice: ip address argument is too long");
        return false;
    }

    const char *const argv[] = {"ifconfig", tdev->name, "inet", ip_prefix, "-alias", NULL};
    if (tunRunCommand("ifconfig", argv) != 0)
    {
        LOGE("TunDevice: error unassigning ip address");
        return false;
    }
    LOGD("TunDevice: ip address removed from %s", tdev->name);
    return true;
#endif
}

// Assign IP address to TUN device
bool tundeviceAssignIP(tun_device_t *tdev, const char *ip_presentation, unsigned int subnet)
{
#ifdef OS_LINUX
    if (subnet <= 32)
    {
        struct ifreq ifr;
        memoryZero(&ifr, sizeof(ifr));
        stringCopyN(ifr.ifr_name, tdev->name, IFNAMSIZ);
        ifr.ifr_name[IFNAMSIZ - 1] = '\0';

        struct sockaddr_in *addr = (struct sockaddr_in *) &ifr.ifr_addr;
        addr->sin_family         = AF_INET;
        if (inet_pton(AF_INET, ip_presentation, &addr->sin_addr) == 1)
        {
            int fd = socket(AF_INET, SOCK_DGRAM, 0);
            if (fd < 0)
            {
                LOGE("TunDevice: failed to create socket for IPv4 assignment: %s", strerror(errno));
                return false;
            }

            bool ok = true;
            if (ioctl(fd, SIOCSIFADDR, &ifr) < 0)
            {
                LOGE("TunDevice: error setting IPv4 address on %s: %s", tdev->name, strerror(errno));
                ok = false;
            }

            if (ok)
            {
                struct sockaddr_in *mask = (struct sockaddr_in *) &ifr.ifr_netmask;
                memoryZero(mask, sizeof(*mask));
                mask->sin_family      = AF_INET;
                mask->sin_addr.s_addr = ipv4PrefixToMask(subnet);
                if (ioctl(fd, SIOCSIFNETMASK, &ifr) < 0)
                {
                    LOGE("TunDevice: error setting IPv4 netmask on %s: %s", tdev->name, strerror(errno));
                    ok = false;
                }
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
        struct in6_addr in6_addr;
        if (inet_pton(AF_INET6, ip_presentation, &in6_addr) == 1)
        {
            int fd = socket(AF_INET6, SOCK_DGRAM, 0);
            if (fd < 0)
            {
                LOGE("TunDevice: failed to create socket for IPv6 assignment: %s", strerror(errno));
                return false;
            }

            struct ifreq ifr;
            memoryZero(&ifr, sizeof(ifr));
            stringCopyN(ifr.ifr_name, tdev->name, IFNAMSIZ);
            ifr.ifr_name[IFNAMSIZ - 1] = '\0';
            if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0)
            {
                LOGE("TunDevice: failed to get interface index for %s: %s", tdev->name, strerror(errno));
                close(fd);
                return false;
            }

            struct in6_ifreq ifr6;
            memoryZero(&ifr6, sizeof(ifr6));
            ifr6.ifr6_addr      = in6_addr;
            ifr6.ifr6_prefixlen = subnet;
            ifr6.ifr6_ifindex   = ifr.ifr_ifindex;

            bool ok = true;
            if (ioctl(fd, SIOCSIFADDR, &ifr6) < 0 && errno != EEXIST)
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
#else
    char ip_prefix[INET6_ADDRSTRLEN + 12];

    if (! tunFormatIpPrefixArg(ip_prefix, sizeof(ip_prefix), ip_presentation, subnet))
    {
        LOGE("TunDevice: ip address argument is too long");
        return false;
    }

    const char *const argv[] = {"ifconfig", tdev->name, "inet", ip_prefix, "-alias", NULL};
    if (tunRunCommand("ifconfig", argv) != 0)
    {
        LOGE("TunDevice: error setting ip address");
        return false;
    }
    LOGD("TunDevice: ip address %s/%d assigned to dev %s", ip_presentation, subnet, tdev->name);
    return true;
#endif
}

bool tundeviceAddRoute(tun_device_t *tdev, const char *cidr, const char *route_table)
{
    if (! routeCommandArgIsSafe(tdev->name) || ! routeCommandArgIsSafe(cidr) || ! routeTableArgIsSafe(route_table))
    {
        LOGE("TunDevice: invalid route argument");
        return false;
    }

#ifdef OS_LINUX
    const char *family = stringChr(cidr, ':') != NULL ? "-6" : "-4";

    if (routeTableIsMain(route_table))
    {
        const char *const argv[] = {"ip", family, "route", "add", cidr, "dev", tdev->name, NULL};
        if (tunRunCommand("ip", argv) != 0)
        {
            LOGE("TunDevice: failed to add system route %s on %s", cidr, tdev->name);
            return false;
        }
    }
    else
    {
        const char *const argv[] = {"ip", family, "route", "add", cidr, "dev", tdev->name, "table", route_table, NULL};
        if (tunRunCommand("ip", argv) != 0)
        {
            LOGE("TunDevice: failed to add system route %s on %s", cidr, tdev->name);
            return false;
        }
    }

    LOGI("TunDevice: added system route %s on %s", cidr, tdev->name);
    return true;
#elif defined(OS_BSD)
    if (! routeTableIsMain(route_table))
    {
        LOGE("TunDevice: route-table '%s' is not supported on this platform", route_table);
        return false;
    }

    const char       *family = stringChr(cidr, ':') != NULL ? "-inet6" : "-inet";
    const char *const argv[] = {"route", "-n", "add", family, cidr, "-interface", tdev->name, NULL};
    if (tunRunCommand("route", argv) != 0)
    {
        LOGE("TunDevice: failed to add system route %s on %s", cidr, tdev->name);
        return false;
    }

    LOGI("TunDevice: added system route %s on %s", cidr, tdev->name);
    return true;
#else
#error "Unsupported OS"
#endif
}

bool tundeviceRemoveRoute(tun_device_t *tdev, const char *cidr, const char *route_table)
{
    if (! routeCommandArgIsSafe(tdev->name) || ! routeCommandArgIsSafe(cidr) || ! routeTableArgIsSafe(route_table))
    {
        LOGE("TunDevice: invalid route argument");
        return false;
    }

#ifdef OS_LINUX
    const char *family = stringChr(cidr, ':') != NULL ? "-6" : "-4";

    if (routeTableIsMain(route_table))
    {
        const char *const argv[] = {"ip", family, "route", "del", cidr, "dev", tdev->name, NULL};
        if (tunRunCommand("ip", argv) != 0)
        {
            LOGE("TunDevice: failed to remove system route %s on %s", cidr, tdev->name);
            return false;
        }
    }
    else
    {
        const char *const argv[] = {"ip", family, "route", "del", cidr, "dev", tdev->name, "table", route_table, NULL};
        if (tunRunCommand("ip", argv) != 0)
        {
            LOGE("TunDevice: failed to remove system route %s on %s", cidr, tdev->name);
            return false;
        }
    }

    LOGI("TunDevice: removed system route %s on %s", cidr, tdev->name);
    return true;
#elif defined(OS_BSD)
    if (! routeTableIsMain(route_table))
    {
        LOGE("TunDevice: route-table '%s' is not supported on this platform", route_table);
        return false;
    }

    const char       *family = stringChr(cidr, ':') != NULL ? "-inet6" : "-inet";
    const char *const argv[] = {"route", "-n", "delete", family, cidr, "-interface", tdev->name, NULL};
    if (tunRunCommand("route", argv) != 0)
    {
        LOGE("TunDevice: failed to remove system route %s on %s", cidr, tdev->name);
        return false;
    }

    LOGI("TunDevice: removed system route %s on %s", cidr, tdev->name);
    return true;
#else
#error "Unsupported OS"
#endif
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

    if (! routeCommandArgIsSafe(tdev->name))
    {
        LOGE("TunDevice: invalid DNS interface argument");
        return false;
    }

    for (size_t i = 0; i < count; ++i)
    {
        if (! routeCommandArgIsSafe(servers[i]))
        {
            LOGE("TunDevice: invalid DNS server argument");
            return false;
        }
    }

#ifdef OS_LINUX
    const char *argv_dns[3 + kTunDeviceMaxDnsServers + 1] = {"resolvectl", "dns", tdev->name, NULL};
    for (size_t i = 0; i < count; ++i)
    {
        argv_dns[3 + i] = servers[i];
    }

    if (tunRunCommand("resolvectl", argv_dns) != 0)
    {
        LOGE("TunDevice: failed to set DNS servers on %s with resolvectl; Linux DNS setup requires systemd-resolved",
             tdev->name);
        return false;
    }

    const char *const argv_domain[] = {"resolvectl", "domain", tdev->name, "~.", NULL};
    if (tunRunCommand("resolvectl", argv_domain) != 0)
    {
        LOGE("TunDevice: failed to set DNS routing domain on %s with resolvectl; reverting DNS settings", tdev->name);
        discard tundeviceClearDnsServers(tdev);
        return false;
    }

    LOGI("TunDevice: configured %zu DNS server(s) on %s", count, tdev->name);
    return true;
#elif defined(OS_BSD)
    LOGE("TunDevice: DNS configuration is not supported on this platform");
    return false;
#else
#error "Unsupported OS"
#endif
}

bool tundeviceClearDnsServers(tun_device_t *tdev)
{
    if (! routeCommandArgIsSafe(tdev->name))
    {
        LOGE("TunDevice: invalid DNS interface argument");
        return false;
    }

#ifdef OS_LINUX
    const char *const argv[] = {"resolvectl", "revert", tdev->name, NULL};
    if (tunRunCommand("resolvectl", argv) != 0)
    {
        LOGE("TunDevice: failed to clear DNS servers on %s with resolvectl", tdev->name);
        return false;
    }

    LOGI("TunDevice: cleared DNS servers on %s", tdev->name);
    return true;
#elif defined(OS_BSD)
    LOGE("TunDevice: DNS configuration is not supported on this platform");
    return false;
#else
#error "Unsupported OS"
#endif
}

/*
 * Single place where an unexpected TUN I/O thread exit becomes process policy.
 * Keep this behaviorally identical to the tun_darwin.c and tun_windows.c copies.
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
 * The lifecycle coordinator reaches all of it through the quiesce/wait hooks.
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
    assert(! currentThreadHasRegisteredWID());
    tun_device_t *tdev = userdata;
    discard       tdev->routine_reader(tdev);
    tundeviceNoteUnexpectedThreadExit(tdev, "reader");
    return 0;
}

static WTHREAD_ROUTINE(tundeviceWriterThreadMain) // NOLINT
{
    assert(! currentThreadHasRegisteredWID());
    tun_device_t *tdev = userdata;
    discard       tdev->routine_writer(tdev);
    tundeviceNoteUnexpectedThreadExit(tdev, "writer");
    return 0;
}

// Bring TUN device up
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
    tdev->reader_generation_open = true;

    if (! tunSetStateByName(tdev->name, true))
    {
        LOGE("TunDevice: error bringing device %s up", tdev->name);
        tundeviceCloseLifetimeGates(tdev);
        deviceReaderSessionEndWait(tdev->reader_session);
        tundeviceRetireReaderGeneration(tdev);
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
    discard tundeviceSignalReaderStop(tdev);
    deviceReaderSessionEndWait(tdev->reader_session);

    bool rollback_ok = tunSetStateByName(tdev->name, false);
    if (! rollback_ok)
    {
        LOGE("TunDevice: error restoring %s down after startup failure", tdev->name);
    }

    if (tdev->reader_joinable)
    {
        if (safeThreadJoin(tdev->read_thread))
        {
            tundeviceDrainStopPipe(tdev);
            tdev->reader_joinable = false;
        }
        else
        {
            LOGE("TunDevice: failed to join reader during startup rollback");
            rollback_ok = false;
        }
    }
    if (! tdev->reader_joinable)
    {
        tundeviceRetireReaderGeneration(tdev);
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

bool tundeviceRequestStop(tun_device_t *tdev)
{
    tunLifecycleTransitionToStopping(&tdev->lifecycle);
    tundeviceCloseLifetimeGates(tdev);

    return tundeviceSignalReaderStop(tdev);
}

// Bring TUN device down
bool tundeviceBringDown(tun_device_t *tdev)
{
    // A previous interface-down failure retains STOPPING after the threads and
    // channel have been released. Keep retrying until that last owned operation
    // succeeds and DOWN can be published.
    if (tunLifecycleLoad(&tdev->lifecycle) == kTunLifecycleDown && ! tdev->reader_joinable && ! tdev->writer_joinable &&
        ! deviceWriterChannelHasCurrent(&tdev->writer_channel))
    {
        return true;
    }

    bool bring_down_ok = tundeviceRequestStop(tdev);
    deviceReaderSessionEndWait(tdev->reader_session);

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
        if (safeThreadJoin(tdev->read_thread))
        {
            tundeviceDrainStopPipe(tdev);
            tdev->reader_joinable = false;
        }
        else
        {
            LOGE("TunDevice: failed to join reader thread; retaining reader resources");
            bring_down_ok = false;
        }
    }
    if (! tdev->reader_joinable)
    {
        tundeviceRetireReaderGeneration(tdev);
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

tun_device_t *tundeviceCreate(const char *name, bool offload, uint16_t mtu, void *userdata, TunReadEventHandle cb)
{
    discard offload; // todo (send/receive offloading)

    if (mtu <= 16)
    {
        LOGE("TunDevice: Invalid MTU size: %u", mtu);
        return NULL;
    }

    struct ifreq ifr;
#ifdef OS_BSD
    int fd = -1;

    // Open the TUN device
    char tun_path[64];
    snprintf(tun_path, sizeof(tun_path), "/dev/%s", name);
    if ((fd = open(tun_path, O_RDWR)) < 0)
    {
        LOGE("TunDevice: opening %s failed", tun_path);
        return NULL;
    }

    // Prepare the ifreq structure to configure the TUN device
    memoryZero(&ifr, sizeof(ifr));
    strncpy(ifr.ifr_name, name, IFNAMSIZ - 1);
    ifr.ifr_name[IFNAMSIZ - 1] = '\0';

    // Set the interface flags (IFF_UP to bring the interface up)
    ifr.ifr_flags = IFF_UP;

    // Configure the TUN device using ioctl
    if (ioctl(fd, SIOCSIFFLAGS, &ifr) < 0)
    {
        LOGE("TunDevice: ioctl(SIOCSIFFLAGS) failed");
        close(fd);
        return NULL;
    }

    if (! tunSetMtuByName(ifr.ifr_name, mtu))
    {
        close(fd);
        return NULL;
    }

    // The reader drains until EAGAIN after every readiness notification, so a
    // blocking descriptor cannot be published safely.
    if (! tunSetNonBlocking(fd))
    {
        close(fd);
        return NULL;
    }

#else

    int fd = open("/dev/net/tun", O_RDWR);
    if (fd < 0)
    {
        LOGE("TunDevice: opening /dev/net/tun failed");
        return NULL;
    }

    memoryZero(&ifr, sizeof(ifr));
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

    if (! tunSetMtuByName(ifr.ifr_name, mtu))
    {
        close(fd);
        return NULL;
    }

    // The reader drains until EAGAIN after every readiness notification, so a
    // blocking descriptor cannot be published safely.
    if (! tunSetNonBlocking(fd))
    {
        close(fd);
        return NULL;
    }
#endif

    /*
     * Device bring-up/creation runs on an event worker even though the reader
     * and writer threads it manages stay unregistered. Read that worker's pool
     * geometry once here and copy it onto the device-owned pools; the auxiliary
     * threads never touch worker-local state themselves.
     */
    buffer_pool_t *worker_pool = getCurrentEventWorkerBufferPool();

    uint32_t worker_large_buffer_size = bufferpoolGetLargeBufferSize(worker_pool);
    uint32_t worker_small_buffer_size = bufferpoolGetSmallBufferSize(worker_pool);
    worker_small_buffer_size          = max(worker_small_buffer_size, (uint32_t) mtu);

    buffer_pool_t *reader_bpool = bufferpoolCreate(GSTATE.masterpool_buffer_pools_large,
                                                   GSTATE.masterpool_buffer_pools_small,
                                                   RAM_PROFILE,
                                                   worker_large_buffer_size,
                                                   worker_small_buffer_size

    );
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
                                                   worker_small_buffer_size

    );
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

    char *device_name = stringDuplicate(ifr.ifr_name);
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

    if (! tunCreateStopPipe(tdev->linux_pipe_fds))
    {
        LOGE("TunDevice: failed to create pipe for linux_pipe_fds");
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
// Destroy TUN device
void tundeviceDestroy(tun_device_t *tdev)
{
    // Unconditional: bring-down is a no-op when nothing is owned, and gating this
    // on readiness would skip cleanup after a thread died on its own.
    if (! tundeviceBringDown(tdev))
    {
        /*
         * Category D: interface cleanup did not complete, so the validity of the
         * remaining device state is unknown and continuing to free it would be a
         * use-after-free risk. Hard-abort with an explicit diagnostic rather than
         * trying to run more cleanup.
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

#if defined(OS_LINUX)

device_reader_session_t *tunLinuxReaderSession(tun_device_t *tdev)
{
    return tdev->reader_session;
}

buffer_pool_t *tunLinuxWriterBufferPool(tun_device_t *tdev)
{
    return tdev->writer_buffer_pool;
}

device_writer_channel_t *tunLinuxWriterChannel(tun_device_t *tdev)
{
    return &tdev->writer_channel;
}

int tunLinuxStopPipeWriteFD(const tun_device_t *tdev)
{
    return tdev->linux_pipe_fds[1];
}

void tunLinuxSetReaderRoutine(tun_device_t *tdev, wthread_routine routine)
{
    tdev->routine_reader = routine;
}

void tunLinuxSetWriterRoutine(tun_device_t *tdev, wthread_routine routine)
{
    tdev->routine_writer = routine;
}

tun_lifecycle_state_t tunLinuxLifecycleState(const tun_device_t *tdev)
{
    return tunLifecycleLoad(&tdev->lifecycle);
}

bool tunLinuxWriterChannelIsUnpublished(const tun_device_t *tdev)
{
    return ! deviceWriterChannelHasCurrent(&tdev->writer_channel) && tdev->writer_channel.retired == NULL &&
           tdev->writer_channel.retired_generation_count == 0 &&
           atomicLoadExplicit(&tdev->writer_channel.published_generation, memory_order_acquire) == (uintptr_t) NULL;
}

#endif

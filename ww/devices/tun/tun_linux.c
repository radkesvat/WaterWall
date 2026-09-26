#include "devices/device_flow_affinity.h"
#include "devices/device_reader_session.h"
#include "devices/device_writer_channel.h"
#include "devices/tun/tun_io_error.h"
#include "devices/tun/tun_lifecycle.h"
#ifdef OS_LINUX
#include "devices/tun/tun_linux_gso_limits.h"
#include "devices/tun/tun_linux_offload.h"
#endif
#include "generic_pool.h"
#include "global_state.h"
#include "loggers/internal_logger.h"
#include "loggers/log_rate_limiter.h"
#include "tun.h"
#include "tun_linux_internal.h"
#include "watomic.h"
#include "wchan.h"
#include "wplatform.h"
#include "wproc.h"
#include "wthread.h"
#include "wtime.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/uio.h>
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
    kTunWriteChannelQueueMax       = 128 * 1024,
    kMaxReadDistributeQueueSize    = 512,
    kTunReaderStopPollMs           = 100,
    kTunPacketFailureLogIntervalMs = 5000,
#ifdef OS_LINUX
    kTunGsoPacketStorageCapacity = 65536,
    kTunGsoPendingPacketLimit    = 512,
    kTunGsoPendingChargeLimit    = 8 * 1024 * 1024,
    kTunGsoLogIntervalMs         = 5000,
#endif
    kLinuxRouteFlagUp      = 0x1,
    kLinuxRouteFlagGateway = 0x2
};

static_assert(kMaxReadDistributeQueueSize <= UINT16_MAX, "TUN read batch count must fit in the reader session");

static atomic_log_rate_limiter_t tun_write_packet_failure_log;

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
    bool                    gso_enabled;
#ifdef OS_LINUX
    /* Allocated before publication so unavailable GSO storage can fall back. */
    sbuf_t *gso_scratch;
#endif

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

#ifdef OS_LINUX
typedef struct tun_offload_reader_s
{
    sbuf_t                  *scratch;
    tun_linux_offload_plan_t pending_plan;
    uint32_t                 next_payload_offset;
    bool                     pending;
    bool                     waiting_for_capacity;
    uint64_t                 ordinary_records;
    uint64_t                 gso_aggregates;
    uint64_t                 generated_segments;
    uint64_t                 checksum_completions;
    uint64_t                 malformed_records;
    uint64_t                 unsupported_records;
    uint64_t                 oversized_records;
} tun_offload_reader_t;

static atomic_log_rate_limiter_t tun_offload_reject_log;

static const char *tunOffloadRejectName(tun_linux_offload_reject_t reject)
{
    switch (reject)
    {
    case kTunLinuxOffloadMalformed:
        return "malformed";
    case kTunLinuxOffloadUnsupported:
        return "unsupported offload metadata";
    case kTunLinuxOffloadOversized:
        return "oversized";
    case kTunLinuxOffloadAccept:
        break;
    }
    return "unexpected";
}

static void tunOffloadCountReject(tun_device_t *tdev, tun_offload_reader_t *reader, tun_linux_offload_reject_t reject)
{
    switch (reject)
    {
    case kTunLinuxOffloadMalformed:
        reader->malformed_records++;
        break;
    case kTunLinuxOffloadUnsupported:
        reader->unsupported_records++;
        break;
    case kTunLinuxOffloadOversized:
        reader->oversized_records++;
        break;
    case kTunLinuxOffloadAccept:
        return;
    }
    if (atomicLogRateLimiterShouldLog(&tun_offload_reject_log, kTunGsoLogIntervalMs))
    {
        LOGW("TunDevice: dropping %s TUN offload record on %s", tunOffloadRejectName(reject), tdev->name);
    }
}

static void tunOffloadReaderInit(tun_device_t *tdev, tun_offload_reader_t *reader)
{
    reader->scratch = tdev->gso_scratch;
    if (UNLIKELY(reader->scratch == NULL))
    {
        LOGF("TunDevice: GSO reader started without its receive scratch");
        abortProgramNow(1);
    }
    sbufReset(reader->scratch);
    if (UNLIKELY(sbufGetLeftCapacity(reader->scratch) < kTunVirtioHeaderSize ||
                 sbufGetMaximumWriteableSize(reader->scratch) < kTunGsoPacketStorageCapacity))
    {
        LOGF("TunDevice: published GSO scratch violates required geometry");
        abortProgramNow(1);
    }
}

static void tunOffloadReaderCleanup(tun_device_t *tdev, tun_offload_reader_t *reader)
{
    /* The device retains scratch through a later BringUp; the reader has
     * exclusive access only while its thread is running. */
    reader->scratch = NULL;
    LOGI("TunDevice: %s GSO reader summary: ordinary=%llu aggregates=%llu generated=%llu deferred-checksum=%llu "
         "malformed=%llu unsupported=%llu oversized=%llu",
         tdev->name,
         (unsigned long long) reader->ordinary_records,
         (unsigned long long) reader->gso_aggregates,
         (unsigned long long) reader->generated_segments,
         (unsigned long long) reader->checksum_completions,
         (unsigned long long) reader->malformed_records,
         (unsigned long long) reader->unsupported_records,
         (unsigned long long) reader->oversized_records);
}

static void tunCompletePreparedGsoSegment(sbuf_t *buf)
{
    tunLinuxOffloadCompleteSegment(sbufGetMutablePtr(buf), sbufGetLength(buf));
}

/* A pending aggregate keeps the scratch buffer until every segment has either
 * been submitted or stop closes producer admission. Capacity is reserved before
 * each allocation; an exhausted budget leaves the remainder in scratch. */
static void tunOffloadEmitPending(tun_device_t *tdev, tun_offload_reader_t *reader)
{
    sbuf_t        *bufs[kMaxReadDistributeQueueSize];
    size_t         charges[kMaxReadDistributeQueueSize];
    uint16_t       queued_count  = 0;
    const uint32_t output_budget = min((uint32_t) RAM_PROFILE, (uint32_t) kMaxReadDistributeQueueSize);
    const uint8_t *aggregate     = sbufGetRawPtr(reader->scratch);

    reader->waiting_for_capacity = false;
    while (reader->pending && queued_count < output_budget && tunLifecycleIsActive(tunLifecycleLoad(&tdev->lifecycle)))
    {
        const uint32_t    remaining      = reader->pending_plan.payload_length - reader->next_payload_offset;
        const uint32_t    payload_length = min(reader->pending_plan.gso_size, remaining);
        const uint32_t    segment_length = reader->pending_plan.header_length + payload_length;
        const uint16_t    padding        = bufferpoolGetSmallBufferPadding(tdev->reader_buffer_pool);
        buffer_pool_fit_t fit;
        if (UNLIKELY(! bufferpoolQueryBestFit(tdev->reader_buffer_pool, segment_length, padding, &fit)))
        {
            LOGF("TunDevice: preflighted GSO segment has unrepresentable buffer geometry");
            abortProgramNow(1);
        }
        if (! deviceReaderSessionTryReserveOutput(tdev->reader_session, fit.allocation_charge))
        {
            reader->waiting_for_capacity = true;
            break;
        }

        sbuf_t *output = bufferpoolGetBestFit(tdev->reader_buffer_pool, segment_length, padding);
        if (UNLIKELY(output == NULL))
        {
            deviceReaderSessionReleaseOutput(tdev->reader_session, fit.allocation_charge);
            LOGF("TunDevice: failed to allocate reserved GSO output storage");
            abortProgramNow(1);
        }
        if (UNLIKELY(sbufGetAllocationCharge(output) != fit.allocation_charge))
        {
            LOGF("TunDevice: GSO output allocation differs from its budget reservation");
            abortProgramNow(1);
        }
        uint32_t built_length = 0;
        if (UNLIKELY(! tunLinuxOffloadPrepareSegment(aggregate,
                                                     &reader->pending_plan,
                                                     reader->next_payload_offset,
                                                     sbufGetMutablePtr(output),
                                                     sbufGetMaximumWriteableSize(output),
                                                     &built_length) ||
                     built_length != segment_length))
        {
            LOGF("TunDevice: GSO segment generation violated successful aggregate preflight");
            abortProgramNow(1);
        }
        sbufSetLength(output, built_length);
        bufs[queued_count]    = output;
        charges[queued_count] = fit.allocation_charge;
        queued_count++;
        reader->generated_segments++;
        reader->next_payload_offset += payload_length;
        reader->pending = reader->next_payload_offset < reader->pending_plan.payload_length;
    }

    if (queued_count > 0)
    {
        if (tunLifecycleIsActive(tunLifecycleLoad(&tdev->lifecycle)))
        {
            deviceFlowAffinityPostGsoBatch(
                tdev->reader_session, bufs, charges, queued_count, tunCompletePreparedGsoSegment);
        }
        else
        {
            for (uint16_t i = 0; i < queued_count; ++i)
            {
                bufferpoolReuseBuffer(tdev->reader_buffer_pool, bufs[i]);
                deviceReaderSessionReleaseOutput(tdev->reader_session, charges[i]);
            }
        }
    }
}

/* One bounded read drain. A GSO record stops further reads; the outer reader
 * loop emits its pending segments before polling or reading another record. */
static tun_drain_result_t tunDrainOffloadPackets(tun_device_t *tdev, tun_offload_reader_t *reader)
{
    sbuf_t            *bufs[kMaxReadDistributeQueueSize];
    uint16_t           queued_count  = 0;
    const uint32_t     output_budget = min((uint32_t) RAM_PROFILE, (uint32_t) kMaxReadDistributeQueueSize);
    tun_drain_result_t result        = kTunDrainAgain;

    for (uint32_t attempt = 0; attempt < RAM_PROFILE && queued_count < output_budget; ++attempt)
    {
        if (! tunLifecycleIsActive(tunLifecycleLoad(&tdev->lifecycle)))
        {
            break;
        }

        sbufReset(reader->scratch);
        sbufShiftLeft(reader->scratch, kTunVirtioHeaderSize);
        uint8_t *record = sbufGetMutablePtr(reader->scratch);
        assert(sbufGetMaximumWriteableSize(reader->scratch) >= kTunVirtioHeaderSize + kTunGsoPacketStorageCapacity);

        ssize_t nread;
        for (;;)
        {
            nread = read(tdev->handle, record, kTunVirtioHeaderSize + kTunGsoPacketStorageCapacity);
            if (nread < 0 && errno == EINTR)
            {
                continue;
            }
            break;
        }
        if (nread == 0)
        {
            result = kTunDrainEndOfStream;
            break;
        }
        if (nread < 0)
        {
            const int saved_errno = errno;
            if (! tunIoErrnoIsTransient(saved_errno))
            {
                LOGE("TunDevice: unrecoverable GSO read error on %s, errno %d (%s)",
                     tdev->name,
                     saved_errno,
                     strerror(saved_errno));
                result = kTunDrainDeviceError;
            }
            break;
        }
        if (nread < kTunVirtioHeaderSize)
        {
            tunOffloadCountReject(tdev, reader, kTunLinuxOffloadMalformed);
            continue;
        }

        uint8_t metadata[kTunVirtioHeaderSize];
        memoryCopy(metadata, record, sizeof(metadata));
        sbufSetLength(reader->scratch, (uint32_t) nread);
        sbufShiftRight(reader->scratch, kTunVirtioHeaderSize);
        uint8_t       *ip        = sbufGetMutablePtr(reader->scratch);
        const uint32_t ip_length = sbufGetLength(reader->scratch);

        tun_linux_offload_plan_t         plan   = {0};
        const tun_linux_offload_reject_t reject = tunLinuxOffloadPreflight(metadata, ip, ip_length, tdev->mtu, &plan);
        if (reject != kTunLinuxOffloadAccept)
        {
            tunOffloadCountReject(tdev, reader, reject);
            continue;
        }
        if (plan.action == kTunLinuxOffloadSegment)
        {
            reader->pending_plan        = plan;
            reader->next_payload_offset = 0;
            reader->pending             = true;
            reader->gso_aggregates++;
            break;
        }

        if (plan.action == kTunLinuxOffloadChecksum)
        {
            tunLinuxOffloadCompleteChecksum(ip, &plan);
            reader->checksum_completions++;
        }
        sbuf_t *output = bufferpoolGetBestFit(
            tdev->reader_buffer_pool, ip_length, bufferpoolGetSmallBufferPadding(tdev->reader_buffer_pool));
        if (UNLIKELY(output == NULL))
        {
            LOGE("TunDevice: failed to allocate ordinary offload-framed packet");
            result = kTunDrainDeviceError;
            break;
        }
        memoryCopy(sbufGetMutablePtr(output), ip, ip_length);
        sbufSetLength(output, ip_length);
        bufs[queued_count++] = output;
        reader->ordinary_records++;
    }

    if (queued_count > 0)
    {
        if (tunLifecycleIsActive(tunLifecycleLoad(&tdev->lifecycle)))
        {
            tunFlushReadBatch(tdev, bufs, queued_count);
        }
        else
        {
            for (uint16_t i = 0; i < queued_count; ++i)
            {
                bufferpoolReuseBuffer(tdev->reader_buffer_pool, bufs[i]);
            }
        }
    }
    return result;
}
#endif

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

    struct pollfd fds[3];
    fds[0].fd         = tdev->handle;
    fds[1].fd         = tdev->linux_pipe_fds[0];
    fds[0].events     = POLLIN;
    fds[1].events     = POLLIN;
    nfds_t poll_count = 2;

#ifdef OS_LINUX
    tun_offload_reader_t offload_reader = {0};
    if (tdev->gso_enabled)
    {
        tunOffloadReaderInit(tdev, &offload_reader);
        fds[2].fd  = deviceReaderSessionOutputWakeFd(tdev->reader_session);
        poll_count = 3;
    }
#endif

    while (tunLifecycleIsActive(tunLifecycleLoad(&tdev->lifecycle)))
    {
#ifdef OS_LINUX
        if (tdev->gso_enabled && offload_reader.pending && ! offload_reader.waiting_for_capacity)
        {
            tunOffloadEmitPending(tdev, &offload_reader);
            if (! offload_reader.pending || ! offload_reader.waiting_for_capacity)
            {
                continue;
            }
        }
        fds[0].events = tdev->gso_enabled && offload_reader.waiting_for_capacity ? 0 : POLLIN;
        if (tdev->gso_enabled)
        {
            fds[2].events = offload_reader.waiting_for_capacity ? POLLIN : 0;
        }
#endif
        int ret = poll(fds, poll_count, kTunReaderStopPollMs);

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

#ifdef OS_LINUX
        if (tdev->gso_enabled && offload_reader.waiting_for_capacity && (fds[2].revents & POLLIN))
        {
            deviceReaderSessionDrainOutputWake(tdev->reader_session);
            offload_reader.waiting_for_capacity = false;
            continue;
        }
        if (tdev->gso_enabled && (fds[2].revents & (POLLERR | POLLHUP | POLLNVAL)))
        {
            LOGE("TunDevice: GSO output-capacity notification failed");
            break;
        }
#endif

        // Check for socket errors
        if (fds[0].revents & (POLLERR | POLLHUP | POLLNVAL))
        {
            tunLogReaderPollError(tdev, fds[0].revents);
            break;
        }

        if (fds[0].revents & POLLIN)
        {
            tun_drain_result_t drain_res;
#ifdef OS_LINUX
            drain_res = tdev->gso_enabled ? tunDrainOffloadPackets(tdev, &offload_reader) : tunDrainPackets(tdev);
#else
            drain_res = tunDrainPackets(tdev);
#endif
            if (drain_res != kTunDrainAgain)
            {
                // The device is gone. Leaving the loop is what lets the thread
                // wrapper publish FAILED and request the orderly shutdown.
                LOGE("TunDevice: Exit read routine due to %s",
                     drain_res == kTunDrainEndOfStream ? "End Of File" : "an unrecoverable device read error");
                break;
            }
            continue;
        }

#ifdef OS_LINUX
        if (tdev->gso_enabled && offload_reader.waiting_for_capacity)
        {
            continue;
        }
#endif

        // If we get here, poll returned > 0 but none of our expected events occurred
        LOGE("TunDevice: Exit read routine due to unexpected poll events - fd[0].revents=0x%x, fd[1].revents=0x%x",
             fds[0].revents,
             fds[1].revents);
        break;
    }

#ifdef OS_LINUX
    if (tdev->gso_enabled)
    {
        tunOffloadReaderCleanup(tdev, &offload_reader);
    }
#endif
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
            if (atomicLogRateLimiterShouldLog(&tun_write_packet_failure_log, kTunPacketFailureLogIntervalMs))
            {
                LOGW("TunDevice: WriteThread: discarded a packet -> size %d exceeds device MTU %u",
                     sbufGetLength(buf), tunDeviceMtu(tdev));
            }

            bufferpoolReuseBuffer(tdev->writer_buffer_pool, buf);
            continue;
        }

        const size_t packet_length   = sbufGetLength(buf);
        const size_t expected_length = packet_length + (tdev->gso_enabled ? kTunVirtioHeaderSize : 0U);
        if (tdev->gso_enabled)
        {
            const uint8_t virtio_header[kTunVirtioHeaderSize] = {0};
            struct iovec  iov[2]                              = {
                {.iov_base = (void *) virtio_header, .iov_len = sizeof(virtio_header)},
                {.iov_base = (void *) sbufGetRawPtr(buf), .iov_len = packet_length},
            };
            do
            {
                nwrite = writev(tdev->handle, iov, 2);
            } while (nwrite < 0 && errno == EINTR);
        }
        else
        {
            nwrite = write(tdev->handle, sbufGetRawPtr(buf), packet_length);
        }
        // errno is only meaningful right here. Recycling the buffer and every
        // logger below may overwrite it, so classification must read this copy.
        const int write_errno = (nwrite < 0) ? errno : 0;
        bufferpoolReuseBuffer(tdev->writer_buffer_pool, buf);

        if (nwrite > 0 && (size_t) nwrite != expected_length)
        {
            if (atomicLogRateLimiterShouldLog(&tun_write_packet_failure_log, kTunPacketFailureLogIntervalMs))
            {
                LOGW("TunDevice: discarded a packet after a short device write (%zd of %zu bytes)", nwrite,
                     expected_length);
            }
            continue;
        }

        if (nwrite == 0)
        {
            LOGW("TunDevice: Exit write routine due to End Of File");
            return 0;
        }

        if (nwrite < 0)
        {
            if (tunIoErrnoIsTransient(write_errno) || tunWriteErrnoIsPacketLocal(write_errno))
            {
                if (atomicLogRateLimiterShouldLog(&tun_write_packet_failure_log, kTunPacketFailureLogIntervalMs))
                {
                    LOGW("TunDevice: discarded a packet, writing to device %s failed with errno %d (%s)",
                         tdev->name, write_errno, strerror(write_errno));
                }
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
                                       bufferpoolGetMediumBufferPadding(worker_pool),
                                       bufferpoolGetSmallBufferPadding(worker_pool),
                                       bufferpoolGetSpliceBufferPadding(worker_pool));

    bufferpoolUpdateAllocationPaddings(tdev->writer_buffer_pool,
                                       bufferpoolGetLargeBufferPadding(worker_pool),
                                       bufferpoolGetMediumBufferPadding(worker_pool),
                                       bufferpoolGetSmallBufferPadding(worker_pool),
                                       bufferpoolGetSpliceBufferPadding(worker_pool));

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

#ifdef OS_LINUX
typedef enum tun_linux_open_result_e
{
    kTunLinuxOpenOk = 0,
    kTunLinuxOpenOffloadUnavailable,
    kTunLinuxOpenNameConflict,
    kTunLinuxOpenFailure
} tun_linux_open_result_t;

static tun_linux_open_result_t tunLinuxOpenAttempt(const char *name, bool offload, bool exclusive, uint16_t mtu,
                                                   int *out_fd, struct ifreq *out_ifr, const char **out_reason,
                                                   int *out_errno)
{
    int fd = open("/dev/net/tun", O_RDWR);
    if (fd < 0)
    {
        *out_reason = "opening /dev/net/tun";
        *out_errno  = errno;
        return kTunLinuxOpenFailure;
    }

    if (offload)
    {
        unsigned int features       = 0;
        const int    feature_result = ioctl(fd, TUNGETFEATURES, &features);
        if (feature_result < 0 || (features & IFF_VNET_HDR) == 0)
        {
            *out_reason = "IFF_VNET_HDR capability check";
            *out_errno  = feature_result < 0 ? errno : EOPNOTSUPP;
            close(fd);
            return kTunLinuxOpenOffloadUnavailable;
        }
    }

    struct ifreq ifr;
    memoryZero(&ifr, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI | (offload ? IFF_VNET_HDR : 0) | (exclusive ? IFF_TUN_EXCL : 0);
    if (*name)
    {
        stringCopyN(ifr.ifr_name, name, IFNAMSIZ);
        ifr.ifr_name[IFNAMSIZ - 1] = '\0';
    }

    if (ioctl(fd, TUNSETIFF, (void *) &ifr) < 0)
    {
        const int saved_errno = errno;
        *out_reason           = "TUNSETIFF";
        *out_errno            = saved_errno;
        close(fd);
        if (saved_errno == EBUSY || saved_errno == EEXIST)
        {
            return kTunLinuxOpenNameConflict;
        }
        return offload ? kTunLinuxOpenOffloadUnavailable : kTunLinuxOpenFailure;
    }

    if (offload)
    {
        int header_size   = kTunVirtioHeaderSize;
        int little_endian = 1;
        if (ioctl(fd, TUNSETVNETHDRSZ, &header_size) < 0)
        {
            *out_reason = "TUNSETVNETHDRSZ";
            *out_errno  = errno;
            close(fd);
            return kTunLinuxOpenOffloadUnavailable;
        }
        if (ioctl(fd, TUNSETVNETLE, &little_endian) < 0)
        {
            *out_reason = "TUNSETVNETLE";
            *out_errno  = errno;
            close(fd);
            return kTunLinuxOpenOffloadUnavailable;
        }
        if (ioctl(fd, TUNSETOFFLOAD, (unsigned long) (TUN_F_CSUM | TUN_F_TSO4)) < 0)
        {
            *out_reason = "TUNSETOFFLOAD(CSUM|TSO4)";
            *out_errno  = errno;
            close(fd);
            return kTunLinuxOpenOffloadUnavailable;
        }

        uint32_t active_max_segments = 0;
        if (tunLinuxGsoMaxSegmentsConfigure(ifr.ifr_name, kTunLinuxRequestedGsoMaxSegments, &active_max_segments))
        {
            LOGI("TunDevice: %s kernel GSO max segments set to %u", ifr.ifr_name, active_max_segments);
        }
        else
        {
            const int limit_errno = errno;
            LOGW("TunDevice: %s could not set/verify kernel GSO max segments %u (active %u; errno %d: %s); "
                 "continuing with bounded reader output",
                 ifr.ifr_name,
                 kTunLinuxRequestedGsoMaxSegments,
                 active_max_segments,
                 limit_errno,
                 strerror(limit_errno));
        }
    }

    if (! tunSetMtuByName(ifr.ifr_name, mtu))
    {
        *out_reason = "setting MTU";
        *out_errno  = errno;
        close(fd);
        return kTunLinuxOpenFailure;
    }
    if (! tunSetNonBlocking(fd))
    {
        *out_reason = "setting nonblocking I/O";
        *out_errno  = errno;
        close(fd);
        return kTunLinuxOpenFailure;
    }

    *out_fd  = fd;
    *out_ifr = ifr;
    return kTunLinuxOpenOk;
}
#endif

tun_device_t *tundeviceCreate(const char *name, bool offload, uint16_t mtu, void *userdata, TunReadEventHandle cb,
                              device_fragment_policy_t fragment_policy)
{
    if (mtu <= 16)
    {
        LOGE("TunDevice: Invalid MTU size: %u", mtu);
        return NULL;
    }

    struct ifreq ifr;
#ifdef OS_BSD
    discard offload;
    int     fd = -1;

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
    int                     fd            = -1;
    bool                    gso_enabled   = false;
    const char             *reason        = NULL;
    int                     failure_errno = 0;
    tun_linux_open_result_t result        = kTunLinuxOpenFailure;
    if (offload)
    {
        result = tunLinuxOpenAttempt(name, true, true, mtu, &fd, &ifr, &reason, &failure_errno);
        if (result == kTunLinuxOpenOk)
        {
            gso_enabled = true;
        }
        else if (result == kTunLinuxOpenOffloadUnavailable)
        {
            LOGW("TunDevice: GSO setup unavailable for %s at %s (errno %d: %s); falling back to raw-IP TUN",
                 name,
                 reason,
                 failure_errno,
                 strerror(failure_errno));
        }
    }
    if (! gso_enabled)
    {
        if (result == kTunLinuxOpenNameConflict || (offload && result == kTunLinuxOpenFailure))
        {
            LOGE("TunDevice: cannot open %s: %s (errno %d: %s)", name, reason, failure_errno, strerror(failure_errno));
            return NULL;
        }
        result = tunLinuxOpenAttempt(name, false, offload, mtu, &fd, &ifr, &reason, &failure_errno);
        if (result != kTunLinuxOpenOk)
        {
            LOGE("TunDevice: raw-IP TUN setup failed for %s at %s (errno %d: %s)",
                 name,
                 reason,
                 failure_errno,
                 strerror(failure_errno));
            return NULL;
        }
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
                                                   GSTATE.masterpool_buffer_pools_medium,
                                                   GSTATE.masterpool_buffer_pools_small,
                                                   GSTATE.masterpool_buffer_pools_splice,
                                                   PROPER_BUFFER_POOL_WIDTH(RAM_PROFILE),
                                                   worker_large_buffer_size,
                                                   bufferpoolGetMediumBufferSize(worker_pool),
                                                   worker_small_buffer_size,
                                                   bufferpoolGetSplicePayloadLimit(worker_pool),
                                                   bufferpoolGetWaitingBudgetBasis(worker_pool));
    if (UNLIKELY(reader_bpool == NULL))
    {
        LOGE("TunDevice: failed to construct reader buffer pool");
        close(fd);
        return NULL;
    }

    buffer_pool_t *writer_bpool = bufferpoolCreate(GSTATE.masterpool_buffer_pools_large,
                                                   GSTATE.masterpool_buffer_pools_medium,
                                                   GSTATE.masterpool_buffer_pools_small,
                                                   GSTATE.masterpool_buffer_pools_splice,
                                                   PROPER_BUFFER_POOL_WIDTH(RAM_PROFILE),
                                                   worker_large_buffer_size,
                                                   bufferpoolGetMediumBufferSize(worker_pool),
                                                   worker_small_buffer_size,
                                                   bufferpoolGetSplicePayloadLimit(worker_pool),
                                                   bufferpoolGetWaitingBudgetBasis(worker_pool));
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
                            .mtu                 = mtu,
#ifdef OS_LINUX
                            .gso_enabled = gso_enabled,
                            .gso_scratch = NULL
#else
                            .gso_enabled = false
#endif
    };
    atomic_init(&tdev->lifecycle, kTunLifecycleDown);
    deviceWriterChannelInit(&tdev->writer_channel);
    tdev->reader_session = deviceReaderSessionCreate(
        RAM_PROFILE * 2, kMaxReadDistributeQueueSize, tdev, tunDeliverPacket, reader_bpool, fragment_policy);
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

#ifdef OS_LINUX
    bool gso_fallback = false;
    if (tdev->gso_enabled)
    {
        const uint16_t    padding = bufferpoolGetLargeBufferPadding(tdev->reader_buffer_pool);
        buffer_pool_fit_t scratch_fit;
        if (! bufferpoolQueryBestFit(tdev->reader_buffer_pool,
                                     kTunGsoPacketStorageCapacity,
                                     max(padding, (uint16_t) kTunVirtioHeaderSize),
                                     &scratch_fit))
        {
            LOGW("TunDevice: GSO receive scratch geometry unavailable for %s; falling back to raw-IP TUN", tdev->name);
            gso_fallback = true;
        }
        else if ((tdev->gso_scratch =
                      sbufTryCreateWithPadding(scratch_fit.payload_capacity, scratch_fit.left_padding)) == NULL)
        {
            LOGW("TunDevice: GSO receive scratch unavailable for %s; falling back to raw-IP TUN", tdev->name);
            gso_fallback = true;
        }
        else if (UNLIKELY(sbufGetLeftCapacity(tdev->gso_scratch) < kTunVirtioHeaderSize ||
                          sbufGetMaximumWriteableSize(tdev->gso_scratch) < kTunGsoPacketStorageCapacity))
        {
            LOGF("TunDevice: GSO scratch allocation violates required geometry");
            abortProgramNow(1);
        }
        else if (! deviceReaderSessionConfigureOutputBudget(
                     tdev->reader_session, kTunGsoPendingChargeLimit, kTunGsoPendingPacketLimit))
        {
            const int budget_errno = errno;
            LOGW("TunDevice: GSO output-budget setup failed for %s (errno %d: %s); falling back to raw-IP TUN",
                 tdev->name,
                 budget_errno,
                 strerror(budget_errno));
            gso_fallback = true;
        }
    }
    if (gso_fallback)
    {
        if (tdev->gso_scratch != NULL)
        {
            sbufDestroy(tdev->gso_scratch);
            tdev->gso_scratch = NULL;
        }
        close(tdev->handle);
        tdev->handle        = -1;
        int          raw_fd = -1;
        struct ifreq raw_ifr;
        result = tunLinuxOpenAttempt(name, false, true, mtu, &raw_fd, &raw_ifr, &reason, &failure_errno);
        if (result != kTunLinuxOpenOk)
        {
            LOGE("TunDevice: raw-IP fallback failed for %s at %s (errno %d: %s)",
                 name,
                 reason,
                 failure_errno,
                 strerror(failure_errno));
            goto fail_after_session;
        }
        tdev->handle      = raw_fd;
        tdev->gso_enabled = false;
        LOGI("TunDevice: %s opened with raw IP after GSO setup fallback", tdev->name);
    }
#endif

    if (! tunCreateStopPipe(tdev->linux_pipe_fds))
    {
        LOGE("TunDevice: failed to create pipe for linux_pipe_fds");
        goto fail_after_session;
    }

#ifdef OS_LINUX
    LOGI("TunDevice: %s configured framing: %s (GSO requested: %s)",
         tdev->name,
         tdev->gso_enabled ? "TCPv4 GSO" : "raw IP",
         offload ? "yes" : "no");
#endif

    return tdev;

fail_after_session:
    memoryFree(tdev->name);
#ifdef OS_LINUX
    if (tdev->gso_scratch != NULL)
    {
        sbufDestroy(tdev->gso_scratch);
    }
#endif
    deviceReaderSessionRetireProducerBuffers(tdev->reader_session);
    bufferpoolDestroy(tdev->reader_buffer_pool);
    bufferpoolDestroy(tdev->writer_buffer_pool);
    deviceReaderSessionUnref(tdev->reader_session);
    if (tdev->handle >= 0)
    {
        close(tdev->handle);
    }
    memoryFree(tdev);
    return NULL;
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
#ifdef OS_LINUX
    if (tdev->gso_scratch != NULL)
    {
        sbufDestroy(tdev->gso_scratch);
    }
#endif
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

#endif

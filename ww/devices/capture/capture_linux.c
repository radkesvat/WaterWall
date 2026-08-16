#include "capture.h"
#include "capture_linux_checksum.h"
#include "capture_linux_internal.h"
#include "devices/device_flow_affinity.h"
#include "devices/device_frag_affinity.h"
#include "generic_pool.h"
#include "global_state.h"
#include "loggers/internal_logger.h"
#include "worker.h"
#include "wproc.h"
#include "wtime.h"
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/if_ether.h>
#include <linux/ipv6.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_queue.h>
#include <linux/netlink.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

enum
{
    kNetfilterReadBufferSize    = kCaptureLinuxNetfilterReadBufferSize,
    kMaxReadDistributeQueueSize = 512,
    kNetfilterQueueLen          = 64 * 1024,
    kNetfilterSocketRecvBuffer  = 64 * 1024 * 1024,

    // Two independent timeout layers guard every Capture iptables command. The
    // numeric xtables lock wait only bounds lock acquisition inside iptables; the
    // parent-side command deadline is authoritative and also covers a hung
    // executable or wrapper. Mutations and sysctls should produce little output,
    // so 64 KiB bounds a broken tool. INPUT inspection legitimately scales with
    // firewall size and therefore gets the same 1 MiB cap used by socket-manager
    // iptables inspection.
    kCaptureIptablesLockWaitSeconds  = 5,
    kCaptureCommandTimeoutMs         = 7000,
    kCaptureCommandTerminateGraceMs  = 250,
    kCaptureMutationMaxOutputBytes   = 64 * 1024,
    kCaptureInspectionMaxOutputBytes = 1024 * 1024,

    // The stop pipe is the fast way out of poll(), but it is not a guaranteed
    // one: BringDown's wake write can fail hard, and then no token ever arrives.
    // A bounded poll makes `running == false` an independent exit condition, so
    // BringDown's join always completes and its failure becomes observable
    // instead of hanging. An idle capture device therefore wakes twice a second,
    // and a lost wake token costs at most one timeout of shutdown latency.
    kCaptureReaderPollTimeoutMs     = 500,
    kCaptureReaderReadyTimeoutMs    = 5000,
    kCaptureDiscardReportIntervalMs = 1000,

    // Configuration and verdict traffic shares the queue socket with the
    // reader. Keep every individual netlink transaction short so a full kernel
    // send buffer cannot hold device teardown indefinitely. Residual teardown
    // uses one such absolute deadline for the whole drain, plus a modest packet
    // budget, instead of renewing this allowance for every queued packet.
    kNetfilterIoDeadlineMs         = 250,
    kNetfilterResidualPacketBudget = 4096,
    kNetfilterAckBufferSize        = 4096,

    // A deterministic syscall seam or a signal storm may return EINTR without
    // advancing the monotonic clock. Bound consecutive interrupted attempts in
    // addition to every absolute deadline/Stop predicate.
    kCaptureInterruptedRetryBudget = 64
};

#define NETFILTER_MAX_PAYLOAD_SIZE sizeof(struct nfqnl_msg_verdict_hdr)
#define NETFILTER_MESSAGE_BUFFER_SIZE                                                                                  \
    (NLMSG_ALIGN(NLMSG_LENGTH(sizeof(struct nfgenmsg))) + NFA_ALIGN(NFA_LENGTH(NETFILTER_MAX_PAYLOAD_SIZE)))

static_assert(SMALL_BUFFER_SIZE >= kNetfilterReadBufferSize, "Linux capture requires 4096-byte small buffers");
static_assert(kCaptureCommandTimeoutMs > kCaptureIptablesLockWaitSeconds * 1000,
              "the parent command deadline must stay strictly longer than the numeric xtables lock wait");
static_assert(kMaxAllowedPacketLength <= kNetfilterReadBufferSize, "packet policy must fit in netlink read buffer");
static_assert(kMaxReadDistributeQueueSize <= UINT16_MAX, "capture read batch count must fit in the reader session");
static_assert(sizeof(struct nfqnl_msg_config_cmd) <= NETFILTER_MAX_PAYLOAD_SIZE,
              "NFQUEUE command payload must fit in message storage");
static_assert(sizeof(struct nfqnl_msg_config_params) <= NETFILTER_MAX_PAYLOAD_SIZE,
              "NFQUEUE parameter payload must fit in message storage");
static_assert(sizeof(uint32_t) <= NETFILTER_MAX_PAYLOAD_SIZE,
              "NFQUEUE queue-length payload must fit in message storage");
static_assert(_Alignof(ww_max_align_t) >= _Alignof(struct nlmsghdr), "netlink storage must align nlmsghdr");
static_assert(_Alignof(ww_max_align_t) >= _Alignof(struct nlmsgerr), "netlink storage must align nlmsgerr");
static_assert(_Alignof(ww_max_align_t) >= _Alignof(struct nfgenmsg), "netlink storage must align nfgenmsg");
static_assert(_Alignof(ww_max_align_t) >= _Alignof(struct nfattr), "netlink storage must align nfattr");
static_assert(NLMSG_HDRLEN % _Alignof(struct nfgenmsg) == 0, "nfgenmsg geometry must preserve alignment");
static_assert(NLMSG_HDRLEN % _Alignof(struct nlmsgerr) == 0, "nlmsgerr geometry must preserve alignment");
static_assert(NLMSG_ALIGN(NLMSG_LENGTH(sizeof(struct nfgenmsg))) % _Alignof(struct nfattr) == 0,
              "nfattr geometry must preserve alignment");

static atomic_uint netfilter_sequence = ATOMIC_VAR_INIT(0);

typedef enum netfilter_packet_result_e
{
    kNetfilterPacketError = -1,
    kNetfilterPacketWouldBlock,
    kNetfilterPacketEof,
    kNetfilterPacketAccepted,
    kNetfilterPacketDiscarded,
    kNetfilterPacketMalformedDiscarded,
    kNetfilterPacketReady
} netfilter_packet_result_t;

// Each setting is passed to sysctl as a single argv element after `-w`, so a
// multi-value setting such as "net.ipv4.tcp_rmem=4096 87380 134217728" arrives
// as one argument. No shell is involved, so no quoting variant is needed.
typedef struct capturedevice_sysctl_setting_s
{
    const char *argv_setting;
} capturedevice_sysctl_setting_t;

static const capturedevice_sysctl_setting_t sysctl_settings[] = {{"net.core.rmem_max=134217728"},
                                                                 {"net.core.wmem_max=134217728"},
                                                                 {"net.ipv4.tcp_rmem=4096 87380 134217728"},
                                                                 {"net.ipv4.tcp_wmem=4096 65536 134217728"},
                                                                 {"net.core.netdev_max_backlog=250000"},
                                                                 {"net.core.somaxconn=65535"},
                                                                 {"net.ipv4.tcp_window_scaling=1"},
                                                                 {"net.ipv4.tcp_timestamps=0"},
                                                                 {"net.ipv4.tcp_sack=1"},
                                                                 {"net.ipv4.tcp_no_metrics_save=1"},
                                                                 {"net.ipv4.tcp_mtu_probing=1"},
                                                                 {"net.ipv4.tcp_tw_reuse=1"},
                                                                 {"net.ipv4.tcp_fin_timeout=15"},
                                                                 {"net.ipv4.ip_local_port_range=10000 65535"}};

// -----------------------------------------------------------------------------
// Stop-pipe helpers
// -----------------------------------------------------------------------------
//
// The stop pipe lives for the whole lifetime of capture_device_t, so a wake
// token left behind by one BringDown would be consumed by the *next* BringUp's
// reader, which would then exit immediately while the device still reported
// success. Both lifecycle boundaries therefore enforce the same invariant: the
// pipe is empty. Both ends are nonblocking so neither draining nor a corrupted
// or unexpectedly full wake channel can block lifecycle teardown.

// Make one stop-pipe descriptor nonblocking while preserving its other flags.
bool capturedeviceMakeStopPipeNonblocking(int pipe_fd)
{
    int flags = fcntl(pipe_fd, F_GETFL, 0);
    if (flags < 0)
    {
        LOGE("CaptureDevice: failed to read stop pipe flags: %s", strerror(errno));
        return false;
    }
    if ((flags & O_NONBLOCK) != 0)
    {
        return true;
    }
    if (fcntl(pipe_fd, F_SETFL, flags | O_NONBLOCK) < 0)
    {
        LOGE("CaptureDevice: failed to set the stop pipe nonblocking: %s", strerror(errno));
        return false;
    }
    return true;
}

static bool capturedeviceRetryInterrupted(uint32_t *interruptions)
{
    *interruptions += 1U;
    if (*interruptions >= (uint32_t) kCaptureInterruptedRetryBudget)
    {
        errno = EINTR;
        return false;
    }
    return true;
}

// Read the stop pipe until it is empty. Never blocks: the read end is
// nonblocking, so EAGAIN/EWOULDBLOCK is the normal successful terminator. EOF
// means the write end is gone, which is a lifecycle failure rather than an empty
// pipe, and is reported as such.
bool capturedeviceDrainStopPipe(capture_device_t *cdev)
{
    uint32_t interruptions = 0;
    for (;;)
    {
        char    drain_buffer[64];
        ssize_t drained = read(cdev->linux_pipe_fds[0], drain_buffer, sizeof(drain_buffer));
        if (drained > 0)
        {
            continue;
        }
        if (drained == 0)
        {
            LOGE("CaptureDevice: stop pipe reported EOF while draining; its write end is gone");
            return false;
        }
        if (errno == EINTR)
        {
            if (! capturedeviceRetryInterrupted(&interruptions))
            {
                LOGE("CaptureDevice: stop-pipe drain exceeded its interrupted-syscall budget");
                return false;
            }
            continue;
        }
        if (errno == EAGAIN || errno == EWOULDBLOCK)
        {
            return true;
        }
        LOGE("CaptureDevice: failed to drain the stop pipe: %d (%s)", errno, strerror(errno));
        return false;
    }
}

// Write exactly one wake token so a reader blocked in poll() leaves its loop.
static bool capturedeviceWriteStopToken(capture_device_t *cdev)
{
    uint32_t interruptions = 0;
    for (;;)
    {
        ssize_t written = write(cdev->linux_pipe_fds[1], "x", 1);
        if (written == 1)
        {
            return true;
        }
        if (written < 0 && errno == EINTR)
        {
            if (! capturedeviceRetryInterrupted(&interruptions))
            {
                LOGE("CaptureDevice: stop-token delivery exceeded its interrupted-syscall budget");
                return false;
            }
            continue;
        }
        LOGE("CaptureDevice: failed to wake the reader through the stop pipe: wrote %zd, errno %d (%s)",
             written,
             errno,
             strerror(errno));
        return false;
    }
}

static uint8_t capturedeviceIpv4MaskPrefixLength(const ip_addr_t *mask)
{
    uint32_t mask_host = lwip_ntohl(mask->u_addr.ip4.addr);
    uint8_t  prefix    = 0;

    while ((mask_host & 0x80000000U) != 0)
    {
        ++prefix;
        mask_host <<= 1U;
    }

    return prefix;
}

static void capturedeviceFormatIpv4(uint32_t addr_host, char *dest, size_t dest_len)
{
    stringNPrintf(dest,
                  dest_len,
                  "%u.%u.%u.%u",
                  (addr_host >> 24U) & 0xFFU,
                  (addr_host >> 16U) & 0xFFU,
                  (addr_host >> 8U) & 0xFFU,
                  addr_host & 0xFFU);
}

static void capturedeviceFormatCidr(const ipmask_t *range, char *dest, size_t dest_len)
{
    char    ip[16];
    uint8_t prefix = capturedeviceIpv4MaskPrefixLength(&range->mask);

    capturedeviceFormatIpv4(lwip_ntohl(range->ip.u_addr.ip4.addr), ip, sizeof(ip));
    stringNPrintf(dest, dest_len, "%s/%u", ip, prefix);
}

static void capturedeviceFormatCommand(const char *const argv[], char *dest, size_t dest_len)
{
    size_t offset = 0;

    if (dest_len == 0)
    {
        return;
    }

    dest[0] = '\0';

    for (size_t i = 0; argv[i] != NULL && offset < dest_len; ++i)
    {
        int written = stringNPrintf(dest + offset, dest_len - offset, "%s%s", i == 0 ? "" : " ", argv[i]);
        if (written < 0)
        {
            break;
        }

        if ((size_t) written >= dest_len - offset)
        {
            offset = dest_len - 1;
            break;
        }

        offset += (size_t) written;
    }
}

// Thin adapter over the generic deadline-aware process supervisor. The command
// is executed directly through execvp(); the formatted string built here is a
// debug diagnostic only and is never handed to a shell. When captured_output is
// non-NULL, ownership of successful stdout is transferred to the caller.
static capturedevice_command_status_t capturedeviceRunCommandCapture(const char *command_name, const char *const argv[],
                                                                     size_t max_output_bytes, char **captured_output)
{
    if (captured_output != NULL)
    {
        *captured_output = NULL;
    }

    char command[512];
    capturedeviceFormatCommand(argv, command, sizeof(command));
    LOGD("CaptureDevice: Running command: %s", command);

    const proc_command_options_t options = {.timeout_ms         = kCaptureCommandTimeoutMs,
                                            .terminate_grace_ms = kCaptureCommandTerminateGraceMs,
                                            .max_output_bytes   = max_output_bytes};

    proc_command_result_t result;
    const bool            ok = procRunArgvWithDeadline(command_name, argv, &options, &result);

    capturedevice_command_status_t status = kCapturedeviceCommandOk;
    if (! ok)
    {
        if (result.timed_out)
        {
            // Logged distinctly from a nonzero exit: this is the status that tells
            // the caller the command path itself hung.
            LOGE("CaptureDevice: command %s exceeded its %u ms deadline and was terminated",
                 command_name,
                 (unsigned int) kCaptureCommandTimeoutMs);
            status = kCapturedeviceCommandTimedOut;
        }
        else if (result.output_too_large)
        {
            LOGE("CaptureDevice: command %s exceeded its %zu-byte output limit and was terminated",
                 command_name,
                 max_output_bytes);
            status = kCapturedeviceCommandOutputTooLarge;
        }
        else if (result.spawn_failed)
        {
            LOGE("CaptureDevice: failed to execute command %s", command_name);
            status = kCapturedeviceCommandSpawnFailed;
        }
        else
        {
            status = kCapturedeviceCommandFailed;
        }
    }

    if (status == kCapturedeviceCommandOk && captured_output != NULL)
    {
        *captured_output  = result.output;
        result.output     = NULL;
        result.output_len = 0;
    }

    procCommandResultDrop(&result);
    return status;
}

static capturedevice_command_status_t capturedeviceRunCommand(const char *command_name, const char *const argv[])
{
    return capturedeviceRunCommandCapture(command_name, argv, kCaptureMutationMaxOutputBytes, NULL);
}

static capturedevice_command_status_t capturedeviceSetSysctl(const capturedevice_sysctl_setting_t *setting)
{
    const char *const argv[] = {"sysctl", "-w", setting->argv_setting, NULL};
    return capturedeviceRunCommand("sysctl", argv);
}

// Best-effort kernel tuning: an ordinary nonzero sysctl exit only warns and the
// batch continues. A timeout, output-limit termination, or parent-side execution
// failure stops the remaining attempts instead: the command path is unusable, so
// re-running it for every setting would turn one bounded failure into fourteen.
// Either way Capture creation continues.
void capturedeviceApplySysctls(void)
{
    for (size_t i = 0; i < sizeof(sysctl_settings) / sizeof(sysctl_settings[0]); ++i)
    {
        const capturedevice_command_status_t status = capturedeviceSetSysctl(&sysctl_settings[i]);
        if (status == kCapturedeviceCommandOk)
        {
            continue;
        }

        LOGW("CaptureDevice: failed to apply sysctl setting %s", sysctl_settings[i].argv_setting);
        if (status == kCapturedeviceCommandTimedOut || status == kCapturedeviceCommandSpawnFailed ||
            status == kCapturedeviceCommandOutputTooLarge)
        {
            LOGW("CaptureDevice: skipping the remaining sysctl tuning after an unusable sysctl command");
            return;
        }
    }
}

static void capturedeviceLogSocketBufferSize(int socket_fd, int option, const char *name)
{
    int       actual = 0;
    socklen_t len    = sizeof(actual);

    if (getsockopt(socket_fd, SOL_SOCKET, option, &actual, &len) != 0)
    {
        LOGW("CaptureDevice: failed to read actual %s: %s", name, strerror(errno));
        return;
    }

    LOGD("CaptureDevice: actual %s is %d bytes", name, actual);
}

capturedevice_command_status_t capturedeviceRunIptablesQueueRule(const char *operation, const char *cidr,
                                                                 uint32_t queue_number, const char *rule_comment)
{
    char queue_number_arg[16];
    stringNPrintf(queue_number_arg, sizeof(queue_number_arg), "%u", queue_number);

    char lock_wait_arg[16];
    stringNPrintf(lock_wait_arg, sizeof(lock_wait_arg), "%d", kCaptureIptablesLockWaitSeconds);

    const char *const argv[] = {"iptables",
                                "-w",
                                lock_wait_arg,
                                operation,
                                "INPUT",
                                "-s",
                                cidr,
                                "-m",
                                "comment",
                                "--comment",
                                rule_comment,
                                "-j",
                                "NFQUEUE",
                                "--queue-num",
                                queue_number_arg,
                                "--queue-bypass",
                                NULL};
    return capturedeviceRunCommand("iptables", argv);
}

capturedevice_command_status_t capturedeviceReadIptablesInputRules(char **input_rules)
{
    char lock_wait_arg[16];
    stringNPrintf(lock_wait_arg, sizeof(lock_wait_arg), "%d", kCaptureIptablesLockWaitSeconds);

    const char *const                    argv[] = {"iptables", "-w", lock_wait_arg, "-S", "INPUT", NULL};
    const capturedevice_command_status_t status =
        capturedeviceRunCommandCapture("iptables", argv, kCaptureInspectionMaxOutputBytes, input_rules);

    // `iptables -S INPUT` always prints at least the chain policy line, so an
    // empty snapshot after a clean exit means the output was lost. Accepting it
    // would make every NFQUEUE number look unused.
    if (status == kCapturedeviceCommandOk && (*input_rules == NULL || **input_rules == '\0'))
    {
        memoryFree(*input_rules);
        *input_rules = NULL;
        return kCapturedeviceCommandFailed;
    }

    return status;
}

static const char *capturedeviceCommandStatusName(capturedevice_command_status_t status)
{
    switch (status)
    {
    case kCapturedeviceCommandOk:
        return "success";
    case kCapturedeviceCommandFailed:
        return "nonzero exit";
    case kCapturedeviceCommandSpawnFailed:
        return "spawn failure";
    case kCapturedeviceCommandTimedOut:
        return "timeout";
    case kCapturedeviceCommandOutputTooLarge:
        return "output limit exceeded";
    default:
        return "unknown failure";
    }
}

static bool capturedeviceCommandOutcomeMayBeUnknown(capturedevice_command_status_t status)
{
    return status == kCapturedeviceCommandTimedOut || status == kCapturedeviceCommandSpawnFailed ||
           status == kCapturedeviceCommandOutputTooLarge;
}

static void capturedeviceMarkQueueOption(const char *input_rules, const char *option, bool is_range, bool *used)
{
    const size_t option_len = stringLength(option);
    const char  *cursor     = input_rules;

    while ((cursor = strstr(cursor, option)) != NULL)
    {
        cursor += option_len;
        if (*cursor != ' ' && *cursor != '\t')
        {
            continue;
        }

        while (*cursor == ' ' || *cursor == '\t')
        {
            ++cursor;
        }

        char         *end   = NULL;
        unsigned long first = strtoul(cursor, &end, 10);
        if (end == cursor || first > UINT16_MAX)
        {
            continue;
        }

        unsigned long last = first;
        if (is_range)
        {
            if (*end != ':')
            {
                cursor = end;
                continue;
            }
            cursor             = end + 1;
            unsigned long high = strtoul(cursor, &end, 10);
            if (end == cursor || high > UINT16_MAX || high < first)
            {
                continue;
            }
            last = high;
        }

        for (unsigned long queue = first; queue <= last; ++queue)
        {
            used[queue] = true;
        }
        cursor = end;
    }
}

bool capturedeviceSelectUnusedQueueNumber(const char *input_rules, uint16_t start, uint16_t *selected)
{
    if (input_rules == NULL || selected == NULL)
    {
        return false;
    }

    bool *used = memoryAllocateZero(((size_t) UINT16_MAX + 1U) * sizeof(*used));
    if (UNLIKELY(used == NULL))
    {
        return false;
    }
    capturedeviceMarkQueueOption(input_rules, "--queue-num", false, used);
    capturedeviceMarkQueueOption(input_rules, "--queue-balance", true, used);

    for (uint32_t offset = 0; offset <= UINT16_MAX; ++offset)
    {
        const uint16_t candidate = (uint16_t) ((uint32_t) start + offset);
        if (! used[candidate])
        {
            *selected = candidate;
            memoryFree(used);
            return true;
        }
    }

    memoryFree(used);
    return false;
}

static bool capturedeviceChooseQueueNumber(uint16_t *selected)
{
    char                          *input_rules = NULL;
    capturedevice_command_status_t status      = capturedeviceReadIptablesInputRules(&input_rules);
    if (status != kCapturedeviceCommandOk)
    {
        LOGE("CaptureDevice: cannot safely select an NFQUEUE number because INPUT rules could not be read (%s)",
             capturedeviceCommandStatusName(status));
        return false;
    }

    const bool found =
        capturedeviceSelectUnusedQueueNumber(input_rules, GSTATE.capturedevice_queue_start_number, selected);
    memoryFree(input_rules);
    if (! found)
    {
        LOGE("CaptureDevice: every NFQUEUE number is already referenced by an INPUT rule");
        return false;
    }

    return true;
}

enum
{
    kCaptureRuleCommentSize = 40
};

static void capturedeviceFormatRuleComment(const capture_device_t *cdev, uint32_t index, char *comment,
                                           size_t comment_size)
{
    stringNPrintf(
        comment, comment_size, "WWCAP_%016llX_%08X", (unsigned long long) cdev->rule_token, (unsigned int) index);
}

static uint32_t capturedevicePendingRuleCount(const capture_device_t *cdev)
{
    uint32_t pending = 0;
    for (uint32_t i = 0; i < cdev->capture_range_count; ++i)
    {
        if (cdev->rule_states[i] != kCaptureRuleAbsent)
        {
            ++pending;
        }
    }
    return pending;
}

static bool capturedeviceReconcileUnknownRules(capture_device_t *cdev)
{
    bool has_unknown = false;
    for (uint32_t i = 0; i < cdev->capture_range_count; ++i)
    {
        has_unknown = has_unknown || cdev->rule_states[i] == kCaptureRuleOutcomeUnknown;
    }
    if (! has_unknown)
    {
        return true;
    }

    char                          *input_rules = NULL;
    capturedevice_command_status_t status      = capturedeviceReadIptablesInputRules(&input_rules);
    if (status != kCapturedeviceCommandOk)
    {
        LOGE("CaptureDevice: could not reconcile outcome-unknown NFQUEUE rules (%s)",
             capturedeviceCommandStatusName(status));
        return false;
    }

    for (uint32_t i = 0; i < cdev->capture_range_count; ++i)
    {
        if (cdev->rule_states[i] != kCaptureRuleOutcomeUnknown)
        {
            continue;
        }

        char comment[kCaptureRuleCommentSize];
        capturedeviceFormatRuleComment(cdev, i, comment, sizeof(comment));
        cdev->rule_states[i] = strstr(input_rules, comment) != NULL ? kCaptureRuleInstalled : kCaptureRuleAbsent;
    }

    memoryFree(input_rules);
    return true;
}

static bool capturedeviceRemoveInstalledRules(capture_device_t *cdev)
{
    if (! capturedeviceReconcileUnknownRules(cdev))
    {
        return false;
    }

    for (uint32_t i = cdev->capture_range_count; i > 0; --i)
    {
        const uint32_t index = i - 1;
        if (cdev->rule_states[index] == kCaptureRuleAbsent)
        {
            continue;
        }

        assert(cdev->rule_states[index] == kCaptureRuleInstalled);
        char comment[kCaptureRuleCommentSize];
        capturedeviceFormatRuleComment(cdev, index, comment, sizeof(comment));
        const capturedevice_command_status_t status =
            capturedeviceRunIptablesQueueRule("-D", cdev->capture_cidrs[index], cdev->queue_number, comment);
        if (status != kCapturedeviceCommandOk)
        {
            if (capturedeviceCommandOutcomeMayBeUnknown(status))
            {
                cdev->rule_states[index] = kCaptureRuleOutcomeUnknown;
            }

            LOGE("CaptureDevice: failed to remove iptables NFQUEUE rule for %s (%s); %u rules remain pending or "
                 "outcome-unknown",
                 cdev->capture_cidrs[index],
                 capturedeviceCommandStatusName(status),
                 capturedevicePendingRuleCount(cdev));
            return false;
        }

        cdev->rule_states[index] = kCaptureRuleAbsent;
    }

    return true;
}

static void capturedeviceDisableQueue(capture_device_t *cdev, const char *reason)
{
    pthread_mutex_lock(&cdev->reader_state_mutex);
    const bool was_restartable = cdev->queue_restartable;
    cdev->queue_restartable    = false;

    int  socket_fd = -1;
    bool deferred  = false;
    if (cdev->reader_thread_joinable && cdev->socket >= 0)
    {
        // The reader may still be using the numeric descriptor it copied
        // during its readiness handshake. Let its wrapper close the queue only
        // after the routine returns, so close()+FD reuse cannot redirect a
        // later poll/recvmsg/verdict to an unrelated object.
        cdev->close_queue_on_reader_exit = true;
        deferred                         = true;
    }
    else
    {
        socket_fd    = cdev->socket;
        cdev->socket = -1;
    }
    pthread_mutex_unlock(&cdev->reader_state_mutex);

    if (! was_restartable && socket_fd < 0 && ! deferred)
    {
        return;
    }
    if (deferred)
    {
        LOGW("CaptureDevice: queue %u will close when its reader exits after %s", cdev->queue_number, reason);
        return;
    }
    if (socket_fd >= 0 && close(socket_fd) != 0)
    {
        LOGE("CaptureDevice: failed to close NFQUEUE socket while making queue %u fail-open: %s",
             cdev->queue_number,
             strerror(errno));
    }

    LOGW("CaptureDevice: queue %u is closed and the device is non-restartable after %s", cdev->queue_number, reason);
}

static char *capturedeviceFormatCidrString(const ipmask_t *range)
{
    char cidr[24];
    capturedeviceFormatCidr(range, cidr, sizeof(cidr));
    return stringDuplicate(cidr);
}

static void capturedeviceFreeCidrs(char **cidrs, uint32_t count)
{
    if (cidrs == NULL)
    {
        return;
    }

    for (uint32_t i = 0; i < count; ++i)
    {
        if (cidrs[i] != NULL)
        {
            memoryFree(cidrs[i]);
        }
    }

    memoryFree(cidrs);
}

static void captureDeliverPacket(void *device, sbuf_t *buf, wid_t wid)
{
    capture_device_t *cdev = device;
    cdev->read_event_callback(cdev, cdev->userdata, buf, wid);
}

static bool netfilterPollUntil(int netfilter_socket, short events, uint64_t deadline_us)
{
    for (;;)
    {
        const uint64_t now_us = (uint64_t) getHRTimeUs();
        if (now_us >= deadline_us)
        {
            errno = ETIMEDOUT;
            return false;
        }

        const uint64_t remaining_us = deadline_us - now_us;
        const int      timeout_ms   = (int) min((remaining_us + 999U) / 1000U, (uint64_t) INT_MAX);
        struct pollfd  pfd          = {
                      .fd     = netfilter_socket,
                      .events = events,
        };
        int result = poll(&pfd, 1, max(timeout_ms, 1));
        if (result < 0 && errno == EINTR)
        {
            continue;
        }
        if (result < 0)
        {
            return false;
        }
        if (result == 0)
        {
            errno = ETIMEDOUT;
            return false;
        }
        if ((pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) != 0)
        {
            errno = EIO;
            return false;
        }
        if ((pfd.revents & events) != 0)
        {
            return true;
        }
    }
}

static bool netfilterRetryInterruptedUntil(uint64_t deadline_us, uint32_t *interruptions)
{
    *interruptions += 1U;
    if (*interruptions >= (uint32_t) kCaptureInterruptedRetryBudget || (uint64_t) getHRTimeUs() >= deadline_us)
    {
        errno = ETIMEDOUT;
        return false;
    }
    return true;
}

static bool netfilterSendBounded(int netfilter_socket, const void *message, size_t size,
                                 const struct sockaddr_nl *nl_addr, uint64_t deadline_us)
{
    uint32_t interruptions = 0;
    for (;;)
    {
        ssize_t result =
            sendto(netfilter_socket, message, size, MSG_DONTWAIT, (const struct sockaddr *) nl_addr, sizeof(*nl_addr));
        if (result == (ssize_t) size)
        {
            return true;
        }
        if (result >= 0)
        {
            errno = EIO;
            return false;
        }
        if (errno == EINTR)
        {
            if (! netfilterRetryInterruptedUntil(deadline_us, &interruptions))
            {
                return false;
            }
            continue;
        }
        if (errno != EAGAIN && errno != EWOULDBLOCK)
        {
            return false;
        }
        if (! netfilterPollUntil(netfilter_socket, POLLOUT, deadline_us))
        {
            return false;
        }
    }
}

static bool netfilterWaitForAck(int netfilter_socket, uint32_t sequence, uint64_t deadline_us)
{
    _Alignas(ww_max_align_t) uint8_t ack_buff[kNetfilterAckBufferSize];
    uint32_t                         interruptions = 0;

    for (;;)
    {
        if (! netfilterPollUntil(netfilter_socket, POLLIN, deadline_us))
        {
            return false;
        }

        struct sockaddr_nl nl_addr;
        struct iovec       iov = {.iov_base = ack_buff, .iov_len = sizeof(ack_buff)};
        struct msghdr      msg = {
                 .msg_name    = &nl_addr,
                 .msg_namelen = sizeof(nl_addr),
                 .msg_iov     = &iov,
                 .msg_iovlen  = 1,
        };
        ssize_t result = recvmsg(netfilter_socket, &msg, MSG_DONTWAIT | MSG_TRUNC);
        if (result < 0 && errno == EINTR)
        {
            if (! netfilterRetryInterruptedUntil(deadline_us, &interruptions))
            {
                return false;
            }
            continue;
        }
        if (result < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
        {
            continue;
        }
        if (result < 0)
        {
            return false;
        }
        if ((msg.msg_flags & MSG_TRUNC) != 0 || result > (ssize_t) sizeof(ack_buff))
        {
            errno = EMSGSIZE;
            return false;
        }
        if (msg.msg_namelen != sizeof(nl_addr) || nl_addr.nl_family != AF_NETLINK || nl_addr.nl_pid != 0 ||
            nl_addr.nl_groups != 0)
        {
            errno = EBADMSG;
            return false;
        }
        bool   matching_ack_seen  = false;
        int    matching_ack_error = 0;
        size_t offset             = 0;
        while (offset < (size_t) result)
        {
            const size_t remaining = (size_t) result - offset;
            if (remaining < sizeof(struct nlmsghdr))
            {
                errno = EBADMSG;
                return false;
            }

            struct nlmsghdr nl_hdr;
            memoryCopy(&nl_hdr, ack_buff + offset, sizeof(nl_hdr));
            if (nl_hdr.nlmsg_len < sizeof(nl_hdr) || nl_hdr.nlmsg_len > remaining)
            {
                errno = EBADMSG;
                return false;
            }

            if (nl_hdr.nlmsg_type == NLMSG_ERROR && nl_hdr.nlmsg_len < NLMSG_LENGTH(sizeof(struct nlmsgerr)))
            {
                errno = EBADMSG;
                return false;
            }

            if (nl_hdr.nlmsg_seq == sequence)
            {
                if (matching_ack_seen || nl_hdr.nlmsg_type != NLMSG_ERROR ||
                    nl_hdr.nlmsg_len < NLMSG_LENGTH(sizeof(struct nlmsgerr)) || (nl_hdr.nlmsg_flags & NLM_F_MULTI) != 0)
                {
                    errno = EBADMSG;
                    return false;
                }

                struct nlmsgerr ack;
                memoryCopy(&ack, ack_buff + offset + NLMSG_HDRLEN, sizeof(ack));
                if (ack.error > 0)
                {
                    errno = EBADMSG;
                    return false;
                }
                matching_ack_seen  = true;
                matching_ack_error = ack.error;
            }

            const size_t aligned_length = NLMSG_ALIGN((size_t) nl_hdr.nlmsg_len);
            if (aligned_length > remaining)
            {
                // A final message need not carry bytes beyond nlmsg_len. Any
                // other short alignment gap would make another header
                // impossible and is therefore malformed.
                if ((size_t) nl_hdr.nlmsg_len == remaining)
                {
                    offset = (size_t) result;
                    break;
                }
                errno = EBADMSG;
                return false;
            }
            offset += aligned_length;
        }

        if (matching_ack_seen)
        {
            if (matching_ack_error == 0)
            {
                return true;
            }
            errno = matching_ack_error == INT_MIN ? EIO : -matching_ack_error;
            return false;
        }
    }
}

/* Send one message and, for configuration requests, its matching ACK before an absolute deadline. */
static bool netfilterSendMessageUntil(int netfilter_socket, uint16_t nl_type, int nfa_type, uint16_t res_id, bool ack,
                                      const void *msg, size_t size, uint64_t deadline_us)
{
    if (size > NETFILTER_MAX_PAYLOAD_SIZE)
    {
        errno = EMSGSIZE;
        return false;
    }

    const size_t nl_size = NLMSG_ALIGN(NLMSG_LENGTH(sizeof(struct nfgenmsg))) + NFA_ALIGN(NFA_LENGTH(size));
    _Alignas(ww_max_align_t) uint8_t buff[NETFILTER_MESSAGE_BUFFER_SIZE];
    memoryZero(buff, nl_size);
    struct nlmsghdr *nl_hdr = (struct nlmsghdr *) buff;

    nl_hdr->nlmsg_len   = NLMSG_LENGTH(sizeof(struct nfgenmsg));
    nl_hdr->nlmsg_flags = NLM_F_REQUEST | (ack ? NLM_F_ACK : 0);
    nl_hdr->nlmsg_type  = (NFNL_SUBSYS_QUEUE << 8) | nl_type;
    nl_hdr->nlmsg_pid   = 0;
    do
    {
        nl_hdr->nlmsg_seq = (uint32_t) atomicAddExplicit(&netfilter_sequence, 1, memory_order_relaxed) + 1U;
    } while (nl_hdr->nlmsg_seq == 0);

    struct nfgenmsg *nl_gen_msg = (struct nfgenmsg *) (nl_hdr + 1);
    nl_gen_msg->version         = NFNETLINK_V0;
    nl_gen_msg->nfgen_family    = AF_UNSPEC;
    nl_gen_msg->res_id          = htons(res_id);

    struct nfattr *nl_attr     = (struct nfattr *) (buff + NLMSG_ALIGN(nl_hdr->nlmsg_len));
    size_t         nl_attr_len = NFA_LENGTH(size);
    nl_hdr->nlmsg_len          = NLMSG_ALIGN(nl_hdr->nlmsg_len) + NFA_ALIGN(nl_attr_len);
    nl_attr->nfa_type          = nfa_type;
    nl_attr->nfa_len           = NFA_LENGTH(size);

    memoryMove(NFA_DATA(nl_attr), msg, size);

    struct sockaddr_nl nl_addr;
    memoryZero(&nl_addr, sizeof(nl_addr));
    nl_addr.nl_family = AF_NETLINK;

    if (! netfilterSendBounded(netfilter_socket, buff, nl_size, &nl_addr, deadline_us))
    {
        return false;
    }

    if (! ack)
    {
        return true;
    }

    return netfilterWaitForAck(netfilter_socket, nl_hdr->nlmsg_seq, deadline_us);
}

/* Send one independently bounded message on the normal configuration/reader path. */
static bool netfilterSendMessage(int netfilter_socket, uint16_t nl_type, int nfa_type, uint16_t res_id, bool ack,
                                 const void *msg, size_t size)
{
    const uint64_t deadline_us = (uint64_t) getHRTimeUs() + (uint64_t) kNetfilterIoDeadlineMs * 1000U;
    return netfilterSendMessageUntil(netfilter_socket, nl_type, nfa_type, res_id, ack, msg, size, deadline_us);
}

/*
 * Set a netfilter configuration option.
 */
static bool netfilterSetConfig(int netfilter_socket, uint8_t cmd, uint16_t qnum, uint16_t pf)
{
    struct nfqnl_msg_config_cmd nl_cmd = {.command = cmd, .pf = htons(pf)};
    return netfilterSendMessage(netfilter_socket, NFQNL_MSG_CONFIG, NFQA_CFG_CMD, qnum, true, &nl_cmd, sizeof(nl_cmd));
}

/*
 * Set the netfilter parameters.
 */
static bool netfilterSetParams(int netfilter_socket, uint16_t qnumber, uint8_t mode, uint32_t range)
{
    struct nfqnl_msg_config_params nl_params = {.copy_mode = mode, .copy_range = htonl(range)};
    return netfilterSendMessage(
        netfilter_socket, NFQNL_MSG_CONFIG, NFQA_CFG_PARAMS, qnumber, true, &nl_params, sizeof(nl_params));
}

/*
 * Set the netfilter queue length.
 */
static bool netfilterSetQueueLength(int netfilter_socket, uint16_t qnumber, uint32_t qlen)
{
    uint32_t qlen_be = htonl(qlen);
    return netfilterSendMessage(
        netfilter_socket, NFQNL_MSG_CONFIG, NFQA_CFG_QUEUE_MAXLEN, qnumber, true, &qlen_be, sizeof(qlen_be));
}

static bool netfilterPointerRangeInside(const uint8_t *base, size_t size, const uint8_t *ptr, size_t len)
{
    uintptr_t base_addr = (uintptr_t) base;
    uintptr_t ptr_addr  = (uintptr_t) ptr;

    if (ptr_addr < base_addr)
    {
        return false;
    }

    size_t offset = ptr_addr - base_addr;
    return offset <= size && len <= size - offset;
}

static void netfilterPacketViewReset(netfilter_packet_view_t *view)
{
    memoryZero(view, sizeof(*view));
}

netfilter_packet_parse_result_t captureLinuxNetfilterParsePacket(uint8_t *message, size_t copied_len,
                                                                 netfilter_packet_view_t *view)
{
    if (message == NULL || view == NULL)
    {
        return kNetfilterPacketParseMalformed;
    }

    netfilterPacketViewReset(view);

    if (copied_len > (size_t) INT_MAX || copied_len <= sizeof(struct nlmsghdr))
    {
        return kNetfilterPacketParseMalformed;
    }

    struct nlmsghdr *nl_hdr          = (struct nlmsghdr *) message;
    int              remaining_bytes = (int) copied_len;
    if (! NLMSG_OK(nl_hdr, (unsigned int) remaining_bytes))
    {
        return kNetfilterPacketParseMalformed;
    }
    if (NFNL_SUBSYS_ID(nl_hdr->nlmsg_type) != NFNL_SUBSYS_QUEUE)
    {
        return kNetfilterPacketParseMalformed;
    }
    if (NFNL_MSG_TYPE(nl_hdr->nlmsg_type) != NFQNL_MSG_PACKET)
    {
        return kNetfilterPacketParseMalformed;
    }

    size_t attr_offset = (size_t) NLMSG_HDRLEN + (size_t) NLMSG_ALIGN(sizeof(struct nfgenmsg));
    if ((size_t) nl_hdr->nlmsg_len < attr_offset)
    {
        return kNetfilterPacketParseMalformed;
    }

    struct nfattr *nl_attr       = NFM_NFA(NLMSG_DATA(nl_hdr));
    int            nl_attr_size  = (int) ((size_t) nl_hdr->nlmsg_len - attr_offset);
    bool           found_payload = false;

    while (nl_attr_size > 0)
    {
        if (! NFA_OK(nl_attr, nl_attr_size))
        {
            return kNetfilterPacketParseMalformed;
        }

        int nl_attr_type    = NFA_TYPE(nl_attr);
        int nl_attr_payload = NFA_PAYLOAD(nl_attr);
        if (UNLIKELY(nl_attr_payload < 0))
        {
            return kNetfilterPacketParseMalformed;
        }
        if (UNLIKELY(! netfilterPointerRangeInside(
                message, (size_t) nl_hdr->nlmsg_len, (const uint8_t *) NFA_DATA(nl_attr), (size_t) nl_attr_payload)))
        {
            return kNetfilterPacketParseMalformed;
        }

        switch (nl_attr_type)
        {
        case NFQA_PAYLOAD:
            if (found_payload)
            {
                return kNetfilterPacketParseMalformed;
            }
            found_payload        = true;
            view->payload        = (const uint8_t *) NFA_DATA(nl_attr);
            view->payload_length = (uint32_t) nl_attr_payload;
            break;
        case NFQA_PACKET_HDR:
            if (view->has_packet_id)
            {
                return kNetfilterPacketParseMalformed;
            }
            if (nl_attr_payload != (int) sizeof(struct nfqnl_msg_packet_hdr))
            {
                return kNetfilterPacketParseMalformed;
            }
            view->has_packet_id = true;
            memoryCopy(&view->packet_id,
                       &((const struct nfqnl_msg_packet_hdr *) NFA_DATA(nl_attr))->packet_id,
                       sizeof(view->packet_id));
            break;
        case NFQA_CAP_LEN: {
            uint32_t raw_capture_length = 0;
            if (view->has_capture_length)
            {
                return kNetfilterPacketParseMalformed;
            }
            if (nl_attr_payload != (int) sizeof(raw_capture_length))
            {
                return kNetfilterPacketParseMalformed;
            }
            view->has_capture_length = true;
            memoryCopy(&raw_capture_length, NFA_DATA(nl_attr), sizeof(raw_capture_length));
            view->capture_length = ntohl(raw_capture_length);
            break;
        }
        case NFQA_SKB_INFO: {
            uint32_t raw_skb_info = 0;
            if (view->has_skb_info || nl_attr_payload != (int) sizeof(raw_skb_info))
            {
                return kNetfilterPacketParseMalformed;
            }
            memoryCopy(&raw_skb_info, NFA_DATA(nl_attr), sizeof(raw_skb_info));
            view->skb_info     = ntohl(raw_skb_info);
            view->has_skb_info = true;
            break;
        }
        default:
            // Ignore other attributes
            break;
        }
        nl_attr = NFA_NEXT(nl_attr, nl_attr_size);
    }

    if (! found_payload || ! view->has_packet_id)
    {
        return kNetfilterPacketParseMalformed;
    }
    if (view->has_capture_length && view->capture_length < view->payload_length)
    {
        return kNetfilterPacketParseMalformed;
    }
    if (view->payload_length > kMaxAllowedPacketLength)
    {
        return kNetfilterPacketParseDiscarded;
    }
    if (view->has_capture_length &&
        (view->capture_length > view->payload_length || view->capture_length > kMaxAllowedPacketLength))
    {
        return kNetfilterPacketParseDiscarded;
    }

    return kNetfilterPacketParseReady;
}

bool captureLinuxNetfilterTryReadPacketIdFromPrefix(const uint8_t *message, size_t copied_len, uint32_t *packet_id)
{
    if (message == NULL || packet_id == NULL || copied_len < sizeof(struct nlmsghdr))
    {
        return false;
    }

    const struct nlmsghdr *nl_hdr = (const struct nlmsghdr *) message;
    if (NFNL_SUBSYS_ID(nl_hdr->nlmsg_type) != NFNL_SUBSYS_QUEUE)
    {
        return false;
    }
    if (NFNL_MSG_TYPE(nl_hdr->nlmsg_type) != NFQNL_MSG_PACKET)
    {
        return false;
    }

    size_t attr_offset = (size_t) NLMSG_HDRLEN + (size_t) NLMSG_ALIGN(sizeof(struct nfgenmsg));
    if ((size_t) nl_hdr->nlmsg_len < attr_offset || copied_len < attr_offset)
    {
        return false;
    }

    size_t nlmsg_limit         = (size_t) nl_hdr->nlmsg_len;
    size_t prefix_limit        = copied_len < nlmsg_limit ? copied_len : nlmsg_limit;
    size_t attr_offset_current = attr_offset;
    while (prefix_limit - attr_offset_current >= sizeof(struct nfattr))
    {
        const struct nfattr *nl_attr  = (const struct nfattr *) (const void *) (message + attr_offset_current);
        size_t               attr_len = (size_t) nl_attr->nfa_len;
        if (attr_len < (size_t) NFA_LENGTH(0))
        {
            return false;
        }
        if (attr_len > prefix_limit - attr_offset_current)
        {
            return false;
        }

        if (NFA_TYPE(nl_attr) == NFQA_PACKET_HDR)
        {
            if (NFA_PAYLOAD(nl_attr) != (int) sizeof(struct nfqnl_msg_packet_hdr))
            {
                return false;
            }
            memoryCopy(
                packet_id, &((const struct nfqnl_msg_packet_hdr *) NFA_DATA(nl_attr))->packet_id, sizeof(*packet_id));
            return true;
        }

        size_t aligned_attr_len = (size_t) NFA_ALIGN(attr_len);
        if (aligned_attr_len == 0 || aligned_attr_len > prefix_limit - attr_offset_current)
        {
            return false;
        }
        attr_offset_current += aligned_attr_len;
    }

    return false;
}

void captureLinuxNetfilterExposePacket(sbuf_t *buff, const uint8_t *message, const netfilter_packet_view_t *view)
{
    assert(buff != NULL);
    assert(message != NULL);
    assert(view != NULL);
    assert(view->payload != NULL);
    assert(view->payload >= message);

    uintptr_t payload_addr   = (uintptr_t) view->payload;
    uintptr_t message_addr   = (uintptr_t) message;
    uint32_t  payload_offset = (uint32_t) (payload_addr - message_addr);

    buff->curpos += payload_offset;
    sbufSetLength(buff, view->payload_length);
}

static bool netfilterSendVerdictUntil(int netfilter_socket, uint16_t qnumber, uint32_t packet_id, uint32_t verdict,
                                      uint64_t deadline_us)
{
    struct nfqnl_msg_verdict_hdr nl_verdict;
    nl_verdict.verdict = htonl(verdict);
    nl_verdict.id      = packet_id;
    return netfilterSendMessageUntil(netfilter_socket,
                                     NFQNL_MSG_VERDICT,
                                     NFQA_VERDICT_HDR,
                                     qnumber,
                                     false,
                                     &nl_verdict,
                                     sizeof(nl_verdict),
                                     deadline_us);
}

static bool netfilterSendVerdict(int netfilter_socket, uint16_t qnumber, uint32_t packet_id, uint32_t verdict)
{
    const uint64_t deadline_us = (uint64_t) getHRTimeUs() + (uint64_t) kNetfilterIoDeadlineMs * 1000U;
    return netfilterSendVerdictUntil(netfilter_socket, qnumber, packet_id, verdict, deadline_us);
}

/*
 * Get a packet from netfilter.
 */
static netfilter_packet_result_t netfilterGetPacketUntil(capture_device_t *cdev, int netfilter_socket, uint16_t qnumber,
                                                         sbuf_t *buff, uint64_t verdict_deadline_us)
{
    assert(sbufGetMaximumWriteableSize(buff) >= kNetfilterReadBufferSize);
    if (UNLIKELY(sbufGetMaximumWriteableSize(buff) < kNetfilterReadBufferSize))
    {
        errno = EMSGSIZE;
        return kNetfilterPacketError;
    }

    // Read a message from netlink (non-blocking)
    struct sockaddr_nl nl_addr;
    memoryZero(&nl_addr, sizeof(nl_addr));
    uint8_t      *message = sbufGetMutablePtr(buff);
    struct iovec  iov     = {.iov_base = message, .iov_len = kNetfilterReadBufferSize};
    struct msghdr msg     = {.msg_name = &nl_addr, .msg_iov = &iov, .msg_iovlen = 1};
    ssize_t       result;
    uint32_t      interruptions = 0;
    for (;;)
    {
        msg.msg_namelen = sizeof(nl_addr);
        msg.msg_flags   = 0;
        result          = recvmsg(netfilter_socket, &msg, MSG_DONTWAIT | MSG_TRUNC);
        if (result >= 0 || errno != EINTR)
        {
            break;
        }
        if (! netfilterRetryInterruptedUntil(verdict_deadline_us, &interruptions))
        {
            return kNetfilterPacketError;
        }
    }

    if (result < 0)
    {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
        {
            return kNetfilterPacketWouldBlock;
        }
        return kNetfilterPacketError;
    }

    if (result == 0)
    {
        return kNetfilterPacketEof;
    }

    if (msg.msg_namelen != sizeof(nl_addr) || nl_addr.nl_pid != 0)
    {
        errno = EINVAL;
        return kNetfilterPacketError;
    }

    size_t copied_len =
        result > (ssize_t) kNetfilterReadBufferSize ? (size_t) kNetfilterReadBufferSize : (size_t) result;
    if ((msg.msg_flags & MSG_TRUNC) != 0 || result > (ssize_t) kNetfilterReadBufferSize)
    {
        uint32_t packet_id = 0;
        if (! captureLinuxNetfilterTryReadPacketIdFromPrefix(message, copied_len, &packet_id))
        {
            LOGW("CaptureDevice: oversized netfilter datagram did not contain a complete packet id");
            errno = EBADMSG;
            return kNetfilterPacketError;
        }
        const bool active = atomicLoadRelaxed(&cdev->capture_active);
        if (! netfilterSendVerdictUntil(
                netfilter_socket, qnumber, packet_id, active ? NF_DROP : NF_ACCEPT, verdict_deadline_us))
        {
            return kNetfilterPacketError;
        }
        return active ? kNetfilterPacketDiscarded : kNetfilterPacketAccepted;
    }

    sbufSetLength(buff, (uint32_t) copied_len);

    netfilter_packet_view_t         packet_view;
    netfilter_packet_parse_result_t parse_result = captureLinuxNetfilterParsePacket(message, copied_len, &packet_view);
    if (parse_result == kNetfilterPacketParseMalformed)
    {
        if (! packet_view.has_packet_id)
        {
            errno = EBADMSG;
            return kNetfilterPacketError;
        }
        const bool active = atomicLoadRelaxed(&cdev->capture_active);
        if (! netfilterSendVerdictUntil(
                netfilter_socket, qnumber, packet_view.packet_id, active ? NF_DROP : NF_ACCEPT, verdict_deadline_us))
        {
            return kNetfilterPacketError;
        }
        return active ? kNetfilterPacketMalformedDiscarded : kNetfilterPacketAccepted;
    }

    const bool active = atomicLoadRelaxed(&cdev->capture_active);
    if (! netfilterSendVerdictUntil(
            netfilter_socket, qnumber, packet_view.packet_id, active ? NF_DROP : NF_ACCEPT, verdict_deadline_us))
    {
        return kNetfilterPacketError;
    }
    if (! active)
    {
        return kNetfilterPacketAccepted;
    }

    if (parse_result == kNetfilterPacketParseDiscarded)
    {
        return kNetfilterPacketDiscarded;
    }

    captureLinuxNetfilterExposePacket(buff, message, &packet_view);

    const device_packet_checksum_provenance_t checksum_provenance =
        captureLinuxChecksumProvenance(packet_view.has_skb_info, packet_view.skb_info);
    if (! deviceIpv4PreparePacketChecksums(sbufGetMutablePtr(buff), sbufGetLength(buff), checksum_provenance))
    {
        return kNetfilterPacketDiscarded;
    }
    return kNetfilterPacketReady;
}

static netfilter_packet_result_t netfilterGetPacket(capture_device_t *cdev, int netfilter_socket, uint16_t qnumber,
                                                    sbuf_t *buff)
{
    const uint64_t deadline_us = (uint64_t) getHRTimeUs() + (uint64_t) kNetfilterIoDeadlineMs * 1000U;
    return netfilterGetPacketUntil(cdev, netfilter_socket, qnumber, buff, deadline_us);
}

static void capturedeviceRecordNetfilterDiscard(capture_device_t *cdev)
{
    log_rate_limiter_report_t report =
        logRateLimiterRecord(&cdev->netfilter_discard_log_limiter, kCaptureDiscardReportIntervalMs);
    if (! report.should_log)
    {
        return;
    }

    LOGW("CaptureDevice: discarded %llu truncated or oversized netfilter packet(s) over %llums (total=%llu)",
         LLU(report.events),
         LLU(report.elapsed_ms),
         LLU(report.total));
}

static void capturedeviceReportPendingNetfilterDiscards(capture_device_t *cdev)
{
    log_rate_limiter_report_t report = logRateLimiterFlush(&cdev->netfilter_discard_log_limiter);
    if (! report.should_log)
    {
        return;
    }

    LOGW("CaptureDevice: discarded %llu truncated or oversized netfilter packet(s) before reader exit (total=%llu)",
         LLU(report.events),
         LLU(report.total));
}

bool captureLinuxReaderPublishReady(capture_device_t *cdev, int *reader_socket)
{
    if (cdev == NULL || reader_socket == NULL)
    {
        return false;
    }

    pthread_mutex_lock(&cdev->reader_state_mutex);
    const bool ready = ! cdev->reader_stop_requested &&
                       captureLifecycleIsActive(captureLifecycleLoad(&cdev->lifecycle)) &&
                       atomicLoadRelaxed(&cdev->running) && ! cdev->reader_failed && cdev->socket >= 0;
    if (ready)
    {
        *reader_socket     = cdev->socket;
        cdev->reader_ready = true;
        pthread_cond_broadcast(&cdev->reader_state_changed);
    }
    pthread_mutex_unlock(&cdev->reader_state_mutex);
    return ready;
}

static WTHREAD_ROUTINE(capturedeviceReaderThreadMain) // NOLINT
{
    assert(! currentThreadHasRegisteredWID());
    capture_device_t *cdev = userdata;
    discard           cdev->routine_reader(cdev);

    capture_lifecycle_state_t failed_from      = kCaptureLifecycleDown;
    bool                      lifecycle_failed = false;
    pthread_mutex_lock(&cdev->reader_state_mutex);
    /*
     * The mutex acquisition order decides whether Stop or reader exit won.
     * `running` is only a loop hint and cannot provide a "fresh" classification
     * of an exit racing the lifecycle owner.
     */
    const bool unexpected_exit = ! cdev->reader_stop_requested;
    cdev->reader_ready         = false;
    if (unexpected_exit)
    {
        lifecycle_failed                 = captureLifecycleTransitionToFailed(&cdev->lifecycle, &failed_from);
        cdev->reader_failed              = true;
        cdev->queue_restartable          = false;
        cdev->close_queue_on_reader_exit = cdev->socket >= 0;
        atomicStoreRelaxed(&cdev->capture_active, false);
        atomicStoreRelaxed(&cdev->up, false);
        atomicStoreRelaxed(&cdev->running, false);
    }

    const bool close_queue = cdev->close_queue_on_reader_exit;
    int        socket_fd   = -1;
    if (close_queue)
    {
        socket_fd                        = cdev->socket;
        cdev->socket                     = -1;
        cdev->close_queue_on_reader_exit = false;
    }

    // The routine has returned, so its copied descriptor is no longer in use.
    // Close before broadcasting failure/exit state to the lifecycle owner.
    if (socket_fd >= 0 && close(socket_fd) != 0)
    {
        LOGE("CaptureDevice: failed to close NFQUEUE socket after reader exit for queue %u: %s",
             cdev->queue_number,
             strerror(errno));
    }
    pthread_cond_broadcast(&cdev->reader_state_changed);
    pthread_mutex_unlock(&cdev->reader_state_mutex);

    if (close_queue)
    {
        LOGW("CaptureDevice: queue %u closed after its reader stopped using the descriptor", cdev->queue_number);
    }
    if (unexpected_exit)
    {
        LOGE("CaptureDevice: reader exited unexpectedly; queue %u was closed to make remaining rules fail-open",
             cdev->queue_number);
    }
    if (lifecycle_failed && failed_from == kCaptureLifecycleUp && ! requestProgramShutdown(1))
    {
        abortProgramNow(1);
    }
    return 0;
}

WTHREAD_ROUTINE(captureLinuxReadRoutine) // NOLINT
{
    capture_device_t *cdev          = userdata;
    int               reader_socket = -1;
    struct pollfd     fds[2];
    fds[1].fd     = cdev->linux_pipe_fds[0];
    fds[0].events = POLLIN;
    fds[1].events = POLLIN;

    // Readiness is published only after all non-socket polling state is built.
    // The handshake supplies the stable socket reference and the next action is
    // entering the bounded poll loop.
    if (! captureLinuxReaderPublishReady(cdev, &reader_socket))
    {
        return 0;
    }
    fds[0].fd = reader_socket;

    while (atomicLoadExplicit(&(cdev->running), memory_order_relaxed))
    {
        int ret = poll(fds, 2, kCaptureReaderPollTimeoutMs);
        if (ret < 0)
        {
            if (errno == EINTR)
            {
                continue; // Interrupted by signal, just retry
            }
            LOGE("CaptureDevice: Exit read routine due to poll failed with error %d (%s)", errno, strerror(errno));
            break;
        }

        if (ret == 0)
        {
            // Bounded-timeout tick. This is the guaranteed exit path: if the wake
            // token could not be written, `running == false` is still observed
            // here, so BringDown's join cannot block forever.
            continue;
        }

        if (fds[1].revents & POLLIN)
        {
            char    drain_byte;
            ssize_t drain_res = read(cdev->linux_pipe_fds[0], &drain_byte, 1);
            discard drain_res;
            LOGW("CaptureDevice: Exit read routine due to pipe event");
            break;
        }

        // Check for socket errors
        if (fds[0].revents & (POLLERR | POLLHUP | POLLNVAL))
        {
            int       socket_error = 0;
            socklen_t err_len      = sizeof(socket_error);
            getsockopt(reader_socket, SOL_SOCKET, SO_ERROR, &socket_error, &err_len);
            LOGE("CaptureDevice: Exit read routine due to socket error event: %s%s%s, socket error: %d (%s)",
                 (fds[0].revents & POLLERR) ? "POLLERR " : "",
                 (fds[0].revents & POLLHUP) ? "POLLHUP " : "",
                 (fds[0].revents & POLLNVAL) ? "POLLNVAL " : "",
                 socket_error,
                 strerror(socket_error));
            break;
        }

        if (fds[0].revents & POLLIN)
        {
            uint16_t queued_count = 0;
            sbuf_t  *bufs[kMaxReadDistributeQueueSize];

            // Drain multiple packets while the socket remains readable
            for (uint32_t i = 0; i < RAM_PROFILE && queued_count < kMaxReadDistributeQueueSize; ++i)
            {
                // Stop may be requested after poll() made the socket readable.
                // Observe it before every packet so one wakeup cannot multiply
                // the verdict deadline across an entire RAM_PROFILE batch.
                if (! atomicLoadExplicit(&cdev->running, memory_order_relaxed))
                {
                    break;
                }

                bool leave_drain_loop = false;
                bufs[queued_count]    = bufferpoolGetSmallBuffer(cdev->reader_buffer_pool);
                bufs[queued_count]    = sbufReserveSpace(bufs[queued_count], kNetfilterReadBufferSize);

                netfilter_packet_result_t packet_result =
                    netfilterGetPacket(cdev, reader_socket, cdev->queue_number, bufs[queued_count]);

                switch (packet_result)
                {
                case kNetfilterPacketReady:
                    // Length was set in netfilterGetPacket via sbufSetLength.
                    if (UNLIKELY(sbufGetLength(bufs[queued_count]) > kMaxAllowedPacketLength))
                    {
                        capturedeviceRecordNetfilterDiscard(cdev);
                        bufferpoolReuseBuffer(cdev->reader_buffer_pool, bufs[queued_count]);
                        continue;
                    }
                    queued_count++;
                    break;

                case kNetfilterPacketAccepted:
                    // Capture is not active yet, or shutdown has begun. The
                    // packet was returned to the host stack with NF_ACCEPT and
                    // must never be dispatched through RawSocket.
                    bufferpoolReuseBuffer(cdev->reader_buffer_pool, bufs[queued_count]);
                    continue;

                case kNetfilterPacketDiscarded:
                    capturedeviceRecordNetfilterDiscard(cdev);
                    bufferpoolReuseBuffer(cdev->reader_buffer_pool, bufs[queued_count]);
                    continue;

                case kNetfilterPacketMalformedDiscarded:
                    LOGW("CaptureDevice: discarded a malformed netfilter packet after sending NF_DROP");
                    bufferpoolReuseBuffer(cdev->reader_buffer_pool, bufs[queued_count]);
                    continue;

                case kNetfilterPacketWouldBlock:
                    bufferpoolReuseBuffer(cdev->reader_buffer_pool, bufs[queued_count]);
                    if (queued_count > 0)
                    {
                        deviceFlowAffinityPostBatch(cdev->reader_session, bufs, queued_count);
                        queued_count = 0;
                    }
                    leave_drain_loop = true;
                    break;

                case kNetfilterPacketEof:
                    bufferpoolReuseBuffer(cdev->reader_buffer_pool, bufs[queued_count]);
                    if (queued_count > 0)
                    {
                        deviceFlowAffinityPostBatch(cdev->reader_session, bufs, queued_count);
                        queued_count = 0;
                    }
                    capturedeviceReportPendingNetfilterDiscards(cdev);
                    LOGE("CaptureDevice: Exit read routine due to End Of File");
                    return 0;

                case kNetfilterPacketError:
                default: {
                    int saved_errno = errno;
                    bufferpoolReuseBuffer(cdev->reader_buffer_pool, bufs[queued_count]);
                    if (queued_count > 0)
                    {
                        deviceFlowAffinityPostBatch(cdev->reader_session, bufs, queued_count);
                        queued_count = 0;
                    }
                    LOGW("CaptureDevice: failed to read a packet from netfilter socket, errno is %d (%s)",
                         saved_errno,
                         strerror(saved_errno));
                    capturedeviceReportPendingNetfilterDiscards(cdev);
                    return 0;
                }
                }

                if (leave_drain_loop)
                {
                    break;
                }
            }

            // Distribute all accumulated packets in one batch
            if (queued_count > 0)
            {
                deviceFlowAffinityPostBatch(cdev->reader_session, bufs, queued_count);
            }
            continue;
        }

        // If we get here, poll returned > 0 but none of our expected events occurred
        LOGE("CaptureDevice: Exit read routine due to unexpected poll events - fd[0].revents=0x%x, fd[1].revents=0x%x",
             fds[0].revents,
             fds[1].revents);
        capturedeviceReportPendingNetfilterDiscards(cdev);
        return 0;
    }

    capturedeviceReportPendingNetfilterDiscards(cdev);
    return 0;
}

static void capturedeviceDeactivate(capture_device_t *cdev)
{
    // These atomics carry mode/status values only; the reader mutex owns the
    // reader lifecycle and descriptor publication.
    atomicStoreRelaxed(&cdev->capture_active, false);
    atomicStoreRelaxed(&cdev->up, false);
    deviceReaderSessionEnd(cdev->reader_session);
}

// Return every packet the kernel still holds for this queue to the host stack.
//
// Removing the last iptables rule stops new packets from being enqueued, but
// anything the kernel queued just before that is still waiting for a verdict.
// The reader cannot be relied on to have taken it: its drain is bounded per
// wakeup, and the stop pipe is handled before the queue socket, so it can exit
// with the socket still readable. On the successful-cleanup path the queue
// socket is then left open, so those packets would sit unverdicted until the
// device is destroyed or brought back up.
//
// Called only after the reader thread has been joined, so this owner has
// exclusive use of the descriptor and no synchronization is needed.
// `capture_active` is already false by then, so netfilterGetPacket() issues
// NF_ACCEPT for each packet on its own.
static bool capturedeviceDrainResidualQueue(capture_device_t *cdev, int socket_fd, uint64_t deadline_us)
{
    // A standalone buffer rather than one from cdev->reader_buffer_pool: that
    // pool is bound to the reader thread on first use, and this runs on the
    // lifecycle owner's thread. Nothing here is dispatched, so one buffer is
    // reused for the whole drain and released on the way out.
    sbuf_t *buf = sbufCreate(kNetfilterReadBufferSize);

    for (uint32_t drained = 0;; ++drained)
    {
        if ((uint64_t) getHRTimeUs() >= deadline_us)
        {
            errno = ETIMEDOUT;
            LOGW("CaptureDevice: residual acceptance deadline expired for queue %u after %u packet(s)",
                 cdev->queue_number,
                 drained);
            sbufDestroy(buf);
            return false;
        }
        if (drained >= (uint32_t) kNetfilterResidualPacketBudget)
        {
            errno = EOVERFLOW;
            LOGW("CaptureDevice: residual acceptance budget for queue %u ended after %u packet(s)",
                 cdev->queue_number,
                 drained);
            sbufDestroy(buf);
            return false;
        }

        sbufReset(buf);
        buf = sbufReserveSpace(buf, kNetfilterReadBufferSize);

        const netfilter_packet_result_t packet_result =
            netfilterGetPacketUntil(cdev, socket_fd, cdev->queue_number, buf, deadline_us);

        // The drain never dispatches: the reader session is already ended, and a
        // verdict was sent for every result except WouldBlock/Eof/Error.
        if (packet_result == kNetfilterPacketWouldBlock || packet_result == kNetfilterPacketEof)
        {
            // The queue is empty: every packet it still held has been verdicted.
            sbufDestroy(buf);
            return true;
        }

        if (packet_result == kNetfilterPacketError)
        {
            // The rules are gone and the reader is stopped, so nothing can
            // recover the remainder. Report it instead of spinning on the error.
            LOGW("CaptureDevice: stopped draining residual packets from queue %u: %s",
                 cdev->queue_number,
                 strerror(errno));
            sbufDestroy(buf);
            return false;
        }
    }
}

static bool capturedeviceStopReader(capture_device_t *cdev)
{
    captureLifecycleTransitionToStopping(&cdev->lifecycle);

    pthread_mutex_lock(&cdev->reader_state_mutex);
    cdev->reader_stop_requested = true;
    const bool      joinable    = cdev->reader_thread_joinable;
    const wthread_t thread      = cdev->read_thread;
    pthread_mutex_unlock(&cdev->reader_state_mutex);

    const bool was_running = atomicExchangeExplicit(&cdev->running, false, memory_order_relaxed);

    bool result = true;
    if (joinable)
    {
        if (was_running)
        {
            result = capturedeviceWriteStopToken(cdev);
        }

        // Safe to join even when the wake write above failed: the reader's poll
        // is bounded and re-checks `running`, so it leaves on its own.
        const bool joined = safeThreadJoin(thread);
        result            = joined && result;

        if (joined)
        {
            pthread_mutex_lock(&cdev->reader_state_mutex);
            cdev->reader_thread_joinable = false;
            cdev->reader_ready           = false;
            // Captured before the pending-close branch below can clear it, so the
            // drain runs on both paths: the queue socket is still open either way.
            const int drain_fd = cdev->socket;
            // Defensive fallback: every lifecycle-created reader runs through
            // the wrapper above, but after join it is safe for this owner to
            // finish any still-pending close without risking descriptor reuse.
            int socket_fd = -1;
            if (cdev->close_queue_on_reader_exit)
            {
                socket_fd                        = cdev->socket;
                cdev->socket                     = -1;
                cdev->close_queue_on_reader_exit = false;
            }
            pthread_mutex_unlock(&cdev->reader_state_mutex);

            // Close, join, retire: End poisons the fragment generation but
            // leaves its staged reader buffers alone, because the reader still
            // owned this pool. Only here does the lifecycle thread own it.
            bufferpoolResetThreadOwnership(cdev->reader_buffer_pool);
            deviceReaderSessionRetireGenerationBuffers(cdev->reader_session);

            // Must precede the close below: closing the queue socket makes the
            // kernel drop whatever is still enqueued.
            if (drain_fd >= 0)
            {
                const uint64_t teardown_deadline_us =
                    (uint64_t) getHRTimeUs() + (uint64_t) kNetfilterIoDeadlineMs * 1000U;
                const bool drain_ok = capturedeviceDrainResidualQueue(cdev, drain_fd, teardown_deadline_us);
                result              = drain_ok && result;
                if (! drain_ok)
                {
                    capturedeviceDisableQueue(cdev, "residual queue drain failure");
                }
            }

            if (socket_fd >= 0 && close(socket_fd) != 0)
            {
                LOGE("CaptureDevice: failed to close NFQUEUE socket after joining queue %u reader: %s",
                     cdev->queue_number,
                     strerror(errno));
            }
        }
        else
        {
            // The reader may still own both the queue descriptor and stop pipe.
            // Do not close, clear joinability, or drain anything until a later
            // teardown attempt successfully joins it.
            return false;
        }
    }

    // Only after joining does the lifecycle owner have exclusive pipe access.
    result = capturedeviceDrainStopPipe(cdev) && result;
    return result;
}

static bool capturedeviceReaderOperational(capture_device_t *cdev)
{
    pthread_mutex_lock(&cdev->reader_state_mutex);
    const bool operational = captureLifecycleIsActive(captureLifecycleLoad(&cdev->lifecycle)) &&
                             cdev->reader_thread_joinable && cdev->reader_ready && ! cdev->reader_failed &&
                             ! cdev->reader_stop_requested && cdev->queue_restartable && cdev->socket >= 0 &&
                             atomicLoadRelaxed(&cdev->running);
    pthread_mutex_unlock(&cdev->reader_state_mutex);
    return operational;
}

static bool capturedeviceStartReader(capture_device_t *cdev)
{
    /*
     * Device bring-up/creation runs on an event worker even though the reader
     * and writer threads it manages stay unregistered. Read that worker's pool
     * geometry once here and copy it onto the device-owned pools; the auxiliary
     * threads never touch worker-local state themselves.
     */
    buffer_pool_t *worker_pool = getCurrentEventWorkerBufferPool();

    bufferpoolUpdateAllocationPaddings(cdev->reader_buffer_pool,
                                       bufferpoolGetLargeBufferPadding(worker_pool),
                                       bufferpoolGetSmallBufferPadding(worker_pool));

    capturedeviceDeactivate(cdev);
    pthread_mutex_lock(&cdev->reader_state_mutex);
    assert(! cdev->reader_thread_joinable);
    cdev->reader_ready               = false;
    cdev->reader_failed              = false;
    cdev->reader_stop_requested      = false;
    cdev->close_queue_on_reader_exit = false;
    pthread_mutex_unlock(&cdev->reader_state_mutex);

    if (deviceReaderSessionBegin(cdev->reader_session) == 0)
    {
        LOGE("CaptureDevice: failed to open reader delivery generation");
        return false;
    }
    atomicStoreRelaxed(&cdev->running, true);
    wthread_error_t error = threadCreate(&cdev->read_thread, capturedeviceReaderThreadMain, cdev);
    if (UNLIKELY(error != kWThreadErrorNone))
    {
        LOGE("CaptureDevice: failed to create reader thread: error %u (%s)", error, strerror((int) error));
        atomicStoreRelaxed(&cdev->running, false);
        capturedeviceDeactivate(cdev);
        return false;
    }

    pthread_mutex_lock(&cdev->reader_state_mutex);
    cdev->reader_thread_joinable      = true;
    const unsigned long long deadline = getTimeOfDayMS() + kCaptureReaderReadyTimeoutMs;
    while (! cdev->reader_ready && ! cdev->reader_failed)
    {
        const unsigned long long now = getTimeOfDayMS();
        if (now >= deadline)
        {
            break;
        }
        const unsigned long long remaining = deadline - now;
        const unsigned int wait_ms = remaining > (unsigned long long) UINT_MAX ? UINT_MAX : (unsigned int) remaining;
        discard            condvarWaitFor(&cdev->reader_state_changed, &cdev->reader_state_mutex, wait_ms);
    }
    const bool ready = cdev->reader_ready && ! cdev->reader_failed;
    if (! ready && ! cdev->reader_failed)
    {
        cdev->reader_failed = true;
    }
    pthread_mutex_unlock(&cdev->reader_state_mutex);

    if (! ready)
    {
        LOGE("CaptureDevice: reader failed or did not become ready within %u ms",
             (unsigned int) kCaptureReaderReadyTimeoutMs);
        capturedeviceDeactivate(cdev);
        discard capturedeviceStopReader(cdev);
        capturedeviceDisableQueue(cdev, "reader readiness failure");
        return false;
    }

    return true;
}

static bool capturedeviceActivate(capture_device_t *cdev)
{
    pthread_mutex_lock(&cdev->reader_state_mutex);
    const bool can_activate = cdev->reader_thread_joinable && cdev->reader_ready && ! cdev->reader_failed &&
                              ! cdev->reader_stop_requested && cdev->queue_restartable && cdev->socket >= 0 &&
                              atomicLoadRelaxed(&cdev->running) &&
                              captureLifecycleTransitionStartingToUp(&cdev->lifecycle);
    if (can_activate)
    {
        atomicStoreRelaxed(&cdev->up, true);
        atomicStoreRelaxed(&cdev->capture_active, true);
    }
    pthread_mutex_unlock(&cdev->reader_state_mutex);
    return can_activate;
}

static void capturedeviceRollbackStartup(capture_device_t *cdev)
{
    captureLifecycleTransitionToStopping(&cdev->lifecycle);
    capturedeviceDeactivate(cdev);
    const bool cleanup_complete = capturedeviceRemoveInstalledRules(cdev);
    if (! cleanup_complete)
    {
        LOGE("CaptureDevice: startup rollback left %u NFQUEUE rules pending or unknown",
             capturedevicePendingRuleCount(cdev));
    }
    if (capturedevicePendingRuleCount(cdev) != 0)
    {
        // Request closure before stopping. The inactive reader keeps accepting
        // packets until it exits, then its wrapper closes the queue without any
        // close()+descriptor-reuse race.
        capturedeviceDisableQueue(cdev, "unresolved startup rollback");
    }
    const bool reader_stop_ok = capturedeviceStopReader(cdev);
    pthread_mutex_lock(&cdev->reader_state_mutex);
    const bool reader_joinable = cdev->reader_thread_joinable;
    pthread_mutex_unlock(&cdev->reader_state_mutex);
    if (! reader_stop_ok)
    {
        LOGE("CaptureDevice: reader shutdown during startup rollback was incomplete");
    }
    if (! reader_joinable)
    {
        captureLifecycleTransitionStoppingToDown(&cdev->lifecycle);
    }
}

bool caputredeviceBringUp(capture_device_t *cdev)
{
    capturedeviceDeactivate(cdev);

    // Pending rules while no reader is running must never keep targeting a bound
    // queue. Close first, retry cleanup, and refuse restart even if that retry
    // succeeds because the NFQUEUE socket cannot be safely reconstructed here.
    if (capturedevicePendingRuleCount(cdev) != 0)
    {
        capturedeviceDisableQueue(cdev, "pending cleanup at bring-up");
        if (! capturedeviceRemoveInstalledRules(cdev))
        {
            LOGE("CaptureDevice: refusing to bring up %s while %u NFQUEUE rules remain pending or unknown",
                 cdev->name,
                 capturedevicePendingRuleCount(cdev));
            return false;
        }
    }

    pthread_mutex_lock(&cdev->reader_state_mutex);
    const bool restartable = cdev->queue_restartable && cdev->socket >= 0 && ! cdev->reader_thread_joinable;
    pthread_mutex_unlock(&cdev->reader_state_mutex);
    if (! restartable)
    {
        LOGE("CaptureDevice: refusing to bring up %s because its queue or reader lifecycle is not restartable",
             cdev->name);
        return false;
    }

    if (! capturedeviceDrainStopPipe(cdev))
    {
        LOGE("CaptureDevice: refusing to bring up %s because its stop pipe could not be drained", cdev->name);
        return false;
    }

    if (! captureLifecycleTransitionDownToStarting(&cdev->lifecycle))
    {
        LOGE("CaptureDevice: device cannot be started in current lifecycle state");
        return false;
    }

    if (! capturedeviceStartReader(cdev))
    {
        captureLifecycleTransitionToStopping(&cdev->lifecycle);
        pthread_mutex_lock(&cdev->reader_state_mutex);
        const bool reader_joinable = cdev->reader_thread_joinable;
        pthread_mutex_unlock(&cdev->reader_state_mutex);
        if (! reader_joinable)
        {
            captureLifecycleTransitionStoppingToDown(&cdev->lifecycle);
        }
        return false;
    }

    bool insertion_failed = false;
    for (uint32_t i = 0; i < cdev->capture_range_count; ++i)
    {
        if (! capturedeviceReaderOperational(cdev))
        {
            LOGE("CaptureDevice: reader failed before NFQUEUE rule %u could be installed", i);
            insertion_failed = true;
            break;
        }

        assert(cdev->rule_states[i] == kCaptureRuleAbsent);
        char comment[kCaptureRuleCommentSize];
        capturedeviceFormatRuleComment(cdev, i, comment, sizeof(comment));
        const capturedevice_command_status_t status =
            capturedeviceRunIptablesQueueRule("-I", cdev->capture_cidrs[i], cdev->queue_number, comment);
        if (status != kCapturedeviceCommandOk)
        {
            if (capturedeviceCommandOutcomeMayBeUnknown(status))
            {
                cdev->rule_states[i] = kCaptureRuleOutcomeUnknown;
            }
            LOGE("CaptureDevice: failed to install iptables NFQUEUE rule for %s (%s)",
                 cdev->capture_cidrs[i],
                 capturedeviceCommandStatusName(status));
            insertion_failed = true;
            break;
        }

        cdev->rule_states[i] = kCaptureRuleInstalled;
        if (! capturedeviceReaderOperational(cdev))
        {
            LOGE("CaptureDevice: reader failed after NFQUEUE rule %u was installed", i);
            insertion_failed = true;
            break;
        }
    }

    if (insertion_failed || ! capturedeviceActivate(cdev))
    {
        capturedeviceRollbackStartup(cdev);
        return false;
    }

    assert(capturedevicePendingRuleCount(cdev) == cdev->capture_range_count);
    LOGI("CaptureDevice: device %s is now up", cdev->name);
    return true;
}

bool capturedeviceRequestStop(capture_device_t *cdev)
{
    captureLifecycleTransitionToStopping(&cdev->lifecycle);
    atomicStoreRelaxed(&cdev->capture_active, false);
    atomicStoreRelaxed(&cdev->up, false);
    deviceReaderSessionEndRequest(cdev->reader_session);
    return true;
}

bool caputredeviceBringDown(capture_device_t *cdev)
{
    captureLifecycleTransitionToStopping(&cdev->lifecycle);

    // From this point every newly received packet is accepted back to the host
    // stack while rules are removed. The raw writer may remain up until this
    // function returns.
    capturedeviceDeactivate(cdev);

    // Keep the reader consuming and accepting while iptables cleanup may block.
    bool result = capturedeviceRemoveInstalledRules(cdev);

    if (capturedevicePendingRuleCount(cdev) != 0)
    {
        // Request closure before stopping. The inactive reader keeps accepting
        // packets until its routine returns, then its wrapper closes the queue.
        capturedeviceDisableQueue(cdev, "incomplete rule cleanup during bring-down");
        result = false;
    }

    const bool reader_stop_ok = capturedeviceStopReader(cdev);
    result                    = reader_stop_ok && result;

    pthread_mutex_lock(&cdev->reader_state_mutex);
    const bool reader_joinable = cdev->reader_thread_joinable;
    pthread_mutex_unlock(&cdev->reader_state_mutex);
    if (! reader_joinable)
    {
        captureLifecycleTransitionStoppingToDown(&cdev->lifecycle);
        LOGI("CaptureDevice: device %s is now down", cdev->name);
    }

    return result;
}

capture_device_t *caputredeviceCreate(const char *name, const ipmask_t *capture_ranges, uint32_t capture_range_count,
                                      void *userdata, CaptureReadEventHandle cb)
{
    if (capture_ranges == NULL || capture_range_count == 0)
    {
        LOGE("CaptureDevice: no capture ranges configured");
        return NULL;
    }

    /* Best-effort kernel tuning; capture startup must continue if a sysctl fails. */
    capturedeviceApplySysctls();

    int socket_netfilter = socket(AF_NETLINK, SOCK_RAW, NETLINK_NETFILTER);
    if (socket_netfilter < 0)
    {
        LOGE("CaptureDevice: unable to create a netfilter socket");
        return NULL;
    }

    struct sockaddr_nl nl_addr;
    memoryZero(&nl_addr, sizeof(nl_addr));
    nl_addr.nl_family = AF_NETLINK;
    nl_addr.nl_pid    = 0;

    if (bind(socket_netfilter, (struct sockaddr *) &nl_addr, sizeof(nl_addr)) != 0)
    {
        LOGE("CaptureDevice: unable to bind netfilter socket to current process");
        close(socket_netfilter);
        return NULL;
    }

    int flags = fcntl(socket_netfilter, F_GETFL, 0);
    if (flags < 0)
    {
        const int saved_errno = errno;
        LOGE("CaptureDevice: failed to get NFQUEUE socket flags for O_NONBLOCK: %s", strerror(saved_errno));
        close(socket_netfilter);
        errno = saved_errno;
        return NULL;
    }
    if (fcntl(socket_netfilter, F_SETFL, flags | O_NONBLOCK) < 0)
    {
        const int saved_errno = errno;
        LOGE("CaptureDevice: failed to set O_NONBLOCK on NFQUEUE socket: %s", strerror(saved_errno));
        close(socket_netfilter);
        errno = saved_errno;
        return NULL;
    }

    // Best-effort: avoid ENOBUFS notifications waking us up.
    {
        int one = 1;
        if (setsockopt(socket_netfilter, SOL_NETLINK, NETLINK_NO_ENOBUFS, &one, sizeof(one)) < 0)
        {
            LOGW("CaptureDevice: failed to set NETLINK_NO_ENOBUFS: %s", strerror(errno));
        }
    }

    if (! netfilterSetConfig(socket_netfilter, NFQNL_CFG_CMD_PF_UNBIND, 0, PF_INET))
    {
        LOGE("CaptureDevice: unable to unbind netfilter from PF_INET");
        close(socket_netfilter);
        return NULL;
    }
    if (! netfilterSetConfig(socket_netfilter, NFQNL_CFG_CMD_PF_BIND, 0, PF_INET))
    {
        LOGE("CaptureDevice: unable to bind netfilter to PF_INET");
        close(socket_netfilter);
        return NULL;
    }
    uint16_t selected_queue_number = 0;
    if (! capturedeviceChooseQueueNumber(&selected_queue_number))
    {
        close(socket_netfilter);
        return NULL;
    }
    int queue_number = selected_queue_number;

    size_t capture_cidrs_size;
    if (! memoryTryComputeArraySize(capture_range_count, sizeof(char *), &capture_cidrs_size))
    {
        LOGE("CaptureDevice: capture range vector is too large");
        close(socket_netfilter);
        return NULL;
    }
    char **capture_cidrs = memoryAllocateZero(capture_cidrs_size);
    if (UNLIKELY(capture_cidrs == NULL))
    {
        LOGE("CaptureDevice: failed to allocate capture range vector");
        close(socket_netfilter);
        return NULL;
    }

    for (uint32_t i = 0; i < capture_range_count; ++i)
    {
        capture_cidrs[i] = capturedeviceFormatCidrString(&capture_ranges[i]);
        if (capture_cidrs[i] == NULL)
        {
            LOGE("CaptureDevice: failed to format capture range");
            close(socket_netfilter);
            capturedeviceFreeCidrs(capture_cidrs, capture_range_count);
            return NULL;
        }
    }

    if (! netfilterSetConfig(socket_netfilter, NFQNL_CFG_CMD_BIND, queue_number, 0))
    {
        LOGE("CaptureDevice: unable to bind netfilter to queue number %u", queue_number);
        close(socket_netfilter);
        capturedeviceFreeCidrs(capture_cidrs, capture_range_count);
        return NULL;
    }

    uint32_t range = kMaxAllowedPacketLength;
    if (! netfilterSetParams(socket_netfilter, queue_number, NFQNL_COPY_PACKET, range))
    {
        LOGE("CaptureDevice: unable to set netfilter into copy packet mode with maximum "
             "packet payload copy size %u",
             range);

        close(socket_netfilter);
        capturedeviceFreeCidrs(capture_cidrs, capture_range_count);
        return NULL;
    }
    if (! netfilterSetQueueLength(socket_netfilter, queue_number, kNetfilterQueueLen))
    {
        LOGE("CaptureDevice: unable to set netfilter queue maximum length to %u", kNetfilterQueueLen);

        close(socket_netfilter);
        capturedeviceFreeCidrs(capture_cidrs, capture_range_count);
        return NULL;
    }
    int rcvbuf_size = kNetfilterSocketRecvBuffer;
    if (setsockopt(socket_netfilter, SOL_SOCKET, SO_RCVBUF, &rcvbuf_size, sizeof(rcvbuf_size)) < 0)
    {
        LOGE("CaptureDevice: failed to set SO_RCVBUF: %s", strerror(errno));
        close(socket_netfilter);
        capturedeviceFreeCidrs(capture_cidrs, capture_range_count);
        return NULL;
    }
    capturedeviceLogSocketBufferSize(socket_netfilter, SO_RCVBUF, "SO_RCVBUF");

    /*
     * Device bring-up/creation runs on an event worker even though the reader
     * and writer threads it manages stay unregistered. Read that worker's pool
     * geometry once here and copy it onto the device-owned pools; the auxiliary
     * threads never touch worker-local state themselves.
     */
    buffer_pool_t *worker_pool = getCurrentEventWorkerBufferPool();

    buffer_pool_t *reader_bpool = bufferpoolCreate(GSTATE.masterpool_buffer_pools_large,
                                                   GSTATE.masterpool_buffer_pools_small,
                                                   RAM_PROFILE,
                                                   bufferpoolGetLargeBufferSize(worker_pool),
                                                   bufferpoolGetSmallBufferSize(worker_pool)

    );
    if (UNLIKELY(reader_bpool == NULL))
    {
        LOGE("CaptureDevice: failed to construct reader buffer pool");
        close(socket_netfilter);
        capturedeviceFreeCidrs(capture_cidrs, capture_range_count);
        return NULL;
    }
    if (UNLIKELY(bufferpoolGetSmallBufferSize(reader_bpool) < kNetfilterReadBufferSize))
    {
        LOGE("CaptureDevice: Linux capture requires small buffers of at least %u bytes, configured size is %u",
             kNetfilterReadBufferSize,
             bufferpoolGetSmallBufferSize(reader_bpool));
        close(socket_netfilter);
        capturedeviceFreeCidrs(capture_cidrs, capture_range_count);
        bufferpoolDestroy(reader_bpool);
        return NULL;
    }

    uint64_t rule_token = 0;
    if (! secureRandomBytes(&rule_token, sizeof(rule_token)))
    {
        LOGE("CaptureDevice: unable to generate a unique NFQUEUE rule token");
        close(socket_netfilter);
        capturedeviceFreeCidrs(capture_cidrs, capture_range_count);
        bufferpoolDestroy(reader_bpool);
        return NULL;
    }

    size_t rule_states_size;
    if (! memoryTryComputeArraySize(capture_range_count, sizeof(capture_rule_state_t), &rule_states_size))
    {
        bufferpoolDestroy(reader_bpool);
        close(socket_netfilter);
        capturedeviceFreeCidrs(capture_cidrs, capture_range_count);
        return NULL;
    }
    capture_rule_state_t *rule_states = memoryAllocateZero(rule_states_size);
    capture_device_t     *cdev        = memoryAllocate(sizeof(capture_device_t));
    if (UNLIKELY(rule_states == NULL || cdev == NULL))
    {
        memoryFree(rule_states);
        memoryFree(cdev);
        bufferpoolDestroy(reader_bpool);
        close(socket_netfilter);
        capturedeviceFreeCidrs(capture_cidrs, capture_range_count);
        return NULL;
    }

    char *device_name = stringDuplicate(name);
    if (UNLIKELY(device_name == NULL))
    {
        memoryFree(rule_states);
        memoryFree(cdev);
        bufferpoolDestroy(reader_bpool);
        close(socket_netfilter);
        capturedeviceFreeCidrs(capture_cidrs, capture_range_count);
        return NULL;
    }

    *cdev = (capture_device_t) {.name                   = device_name,
                                .running                = false,
                                .up                     = false,
                                .routine_reader         = captureLinuxReadRoutine,
                                .socket                 = socket_netfilter,
                                .queue_number           = queue_number,
                                .read_event_callback    = cb,
                                .userdata               = userdata,
                                .reader_session         = NULL,
                                .netfilter_queue_number = queue_number,
                                .capture_cidrs          = capture_cidrs,
                                .capture_range_count    = capture_range_count,
                                .rule_states            = rule_states,
                                .rule_token             = rule_token,
                                .queue_restartable      = true,
                                .reader_buffer_pool     = reader_bpool};
    atomic_init(&cdev->lifecycle, kCaptureLifecycleDown);
    if (pthread_mutex_init(&cdev->reader_state_mutex, NULL) != 0)
    {
        LOGE("CaptureDevice: failed to initialize reader state mutex");
        memoryFree(cdev->name);
        capturedeviceFreeCidrs(cdev->capture_cidrs, cdev->capture_range_count);
        memoryFree(cdev->rule_states);
        bufferpoolDestroy(cdev->reader_buffer_pool);
        close(cdev->socket);
        memoryFree(cdev);
        return NULL;
    }
    if (pthread_cond_init(&cdev->reader_state_changed, NULL) != 0)
    {
        LOGE("CaptureDevice: failed to initialize reader state condition variable");
        pthread_mutex_destroy(&cdev->reader_state_mutex);
        memoryFree(cdev->name);
        capturedeviceFreeCidrs(cdev->capture_cidrs, cdev->capture_range_count);
        memoryFree(cdev->rule_states);
        bufferpoolDestroy(cdev->reader_buffer_pool);
        close(cdev->socket);
        memoryFree(cdev);
        return NULL;
    }
    if (pipe(cdev->linux_pipe_fds) != 0)
    {
        LOGE("CaptureDevice: failed to create pipe for linux_pipe_fds");
        pthread_cond_destroy(&cdev->reader_state_changed);
        pthread_mutex_destroy(&cdev->reader_state_mutex);
        memoryFree(cdev->name);
        capturedeviceFreeCidrs(cdev->capture_cidrs, cdev->capture_range_count);
        memoryFree(cdev->rule_states);
        bufferpoolDestroy(cdev->reader_buffer_pool);
        close(cdev->socket);
        memoryFree(cdev);
        return NULL;
    }

    // Both ends are nonblocking. The read side makes lifecycle draining safe;
    // the write side ensures wake delivery can fail observably instead of
    // blocking before the reader join. The reader also observes `running` on a
    // bounded poll, so one best-effort token is sufficient.
    if (! capturedeviceMakeStopPipeNonblocking(cdev->linux_pipe_fds[0]) ||
        ! capturedeviceMakeStopPipeNonblocking(cdev->linux_pipe_fds[1]))
    {
        close(cdev->linux_pipe_fds[0]);
        close(cdev->linux_pipe_fds[1]);
        pthread_cond_destroy(&cdev->reader_state_changed);
        pthread_mutex_destroy(&cdev->reader_state_mutex);
        memoryFree(cdev->name);
        capturedeviceFreeCidrs(cdev->capture_cidrs, cdev->capture_range_count);
        memoryFree(cdev->rule_states);
        bufferpoolDestroy(cdev->reader_buffer_pool);
        close(cdev->socket);
        memoryFree(cdev);
        return NULL;
    }

    cdev->reader_session = deviceReaderSessionCreate(
        RAM_PROFILE * 2, kMaxReadDistributeQueueSize, cdev, captureDeliverPacket, reader_bpool);
    if (UNLIKELY(cdev->reader_session == NULL))
    {
        LOGE("CaptureDevice: failed to allocate reader session");
        close(cdev->linux_pipe_fds[0]);
        close(cdev->linux_pipe_fds[1]);
        pthread_cond_destroy(&cdev->reader_state_changed);
        pthread_mutex_destroy(&cdev->reader_state_mutex);
        memoryFree(cdev->name);
        capturedeviceFreeCidrs(cdev->capture_cidrs, cdev->capture_range_count);
        memoryFree(cdev->rule_states);
        bufferpoolDestroy(cdev->reader_buffer_pool);
        close(cdev->socket);
        memoryFree(cdev);
        return NULL;
    }

    /* Queue-number ownership is published only with the complete device. */
    GSTATE.capturedevice_queue_start_number = (uint16_t) ((uint32_t) selected_queue_number + 1U);

    return cdev;
}

void capturedeviceDestroy(capture_device_t *cdev)
{
    pthread_mutex_lock(&cdev->reader_state_mutex);
    const bool reader_joinable = cdev->reader_thread_joinable;
    pthread_mutex_unlock(&cdev->reader_state_mutex);
    deviceReaderSessionEnd(cdev->reader_session);
    if (captureLifecycleLoad(&cdev->lifecycle) != kCaptureLifecycleDown || atomicLoadRelaxed(&cdev->up) ||
        reader_joinable)
    {
        discard caputredeviceBringDown(cdev);
    }

    pthread_mutex_lock(&cdev->reader_state_mutex);
    const bool reader_still_joinable = cdev->reader_thread_joinable;
    pthread_mutex_unlock(&cdev->reader_state_mutex);
    if (reader_still_joinable)
    {
        LOGF("CaptureDevice: refusing to destroy device while reader ownership remains");
        abortProgramNow(1);
    }

    if (capturedevicePendingRuleCount(cdev) != 0)
    {
        // A down device has no reader. Close before the final cleanup attempt so
        // any still-installed rule is fail-open throughout that bounded retry.
        capturedeviceDisableQueue(cdev, "pending cleanup during destruction");
        discard capturedeviceRemoveInstalledRules(cdev);
    }
    const uint32_t pending_rule_count = capturedevicePendingRuleCount(cdev);
    if (pending_rule_count != 0)
    {
        LOGE("CaptureDevice: closing queue %u with %u NFQUEUE rules still pending or outcome-unknown; "
             "--queue-bypass prevents an absent-listener traffic drop, and future capture devices will avoid "
             "queue numbers still referenced by INPUT rules",
             cdev->queue_number,
             pending_rule_count);
    }

    pthread_mutex_lock(&cdev->reader_state_mutex);
    const int socket_fd = cdev->socket;
    cdev->socket        = -1;
    pthread_mutex_unlock(&cdev->reader_state_mutex);
    if (socket_fd >= 0)
    {
        close(socket_fd);
    }
    memoryFree(cdev->name);
    capturedeviceFreeCidrs(cdev->capture_cidrs, cdev->capture_range_count);
    memoryFree(cdev->rule_states);
    deviceReaderSessionRetireProducerBuffers(cdev->reader_session);
    bufferpoolDestroy(cdev->reader_buffer_pool);
    deviceReaderSessionUnref(cdev->reader_session);
    close(cdev->linux_pipe_fds[0]);
    close(cdev->linux_pipe_fds[1]);
    pthread_cond_destroy(&cdev->reader_state_changed);
    pthread_mutex_destroy(&cdev->reader_state_mutex);
    memoryFree(cdev);
}

#include "capture_linux_checksum.h"
#include "capture_linux_internal.h"
#include "capture_private.h"
#include "devices/device_flow_affinity.h"
#include "devices/device_packet_checksum.h"
#include "generic_pool.h"
#include "global_state.h"
#include "loggers/internal_logger.h"
#include "worker.h"
#include "wproc.h"
#include "wtime.h"
#include <arpa/inet.h>
#include <fcntl.h>
#include <linux/filter.h>
#include <linux/if_ether.h>
#include <linux/ipv6.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_queue.h>
#include <linux/netfilter/xt_bpf.h>
#include <linux/netlink.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include "capture_linux_nfqueue.h"
#include "capture_linux_private.h"
#include "capture_linux_rules.h"

// Each setting is passed to sysctl as a single argv element after `-w`, so a
// multi-value setting such as "net.ipv4.ip_local_port_range=10000 65535" arrives
// as one argument. No shell is involved, so no quoting variant is needed.
typedef struct capturedevice_sysctl_setting_s
{
    const char *argv_setting;
} capturedevice_sysctl_setting_t;

static const capturedevice_sysctl_setting_t sysctl_settings[] = {{"net.core.netdev_max_backlog=250000"},
                                                                 {"net.core.somaxconn=65535"},
                                                                 {"net.ipv4.tcp_window_scaling=1"},
                                                                 {"net.ipv4.tcp_timestamps=1"},
                                                                 {"net.ipv4.tcp_sack=1"},
                                                                 {"net.ipv4.tcp_no_metrics_save=1"},
                                                                 {"net.ipv4.tcp_mtu_probing=1"},
                                                                 {"net.ipv4.tcp_tw_reuse=1"},
                                                                 {"net.ipv4.tcp_fin_timeout=15"},
                                                                 {"net.ipv4.ip_local_port_range=10000 65535"}};

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
// re-running it for every setting would repeat the same bounded failure.
// Either way Capture creation continues. A true skip_sysctl is an explicit
// per-device opt-out and runs none of the tuning commands.
void capturedeviceApplySysctls(bool skip_sysctl)
{
    if (skip_sysctl)
    {
        return;
    }

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

void captureLinuxBuildProtocolFilter(const capture_protocol_filter_t *filter,
                                     char                             output[kCaptureLinuxProtocolFilterSize])
{
    output[0] = '\0';
    if (captureProtocolFilterIsEmpty(filter))
    {
        return;
    }

    /* One fixed-size cBPF bitmap lookup covers every literal protocol byte,
     * including zero (iptables -p 0 means "all"). X holds the bit index;
     * A selects one of eight 32-bit words, then returns !excluded[protocol].
     * The same bytecode is used by NFQUEUE and NOTRACK, including deletion. */
    enum
    {
        kResultOffset     = 5 + 3 * (kCaptureProtocolWordCount - 1) + 1,
        kInstructionCount = kResultOffset + 4
    };
    static_assert(kInstructionCount <= XT_BPF_MAX_NUM_INSTR, "protocol filter must fit xt_bpf");
    static_assert(kInstructionCount * 32 + 8 <= kCaptureLinuxProtocolFilterSize,
                  "decimal cBPF instructions must fit their fixed text buffer");
    struct sock_filter program[kInstructionCount] = {
        BPF_STMT(BPF_LD | BPF_B | BPF_ABS, 9),
        BPF_STMT(BPF_ALU | BPF_AND | BPF_K, 31),
        BPF_STMT(BPF_MISC | BPF_TAX, 0),
        BPF_STMT(BPF_LD | BPF_B | BPF_ABS, 9),
        BPF_STMT(BPF_ALU | BPF_RSH | BPF_K, 5),
    };
    unsigned int at = 5;
    for (unsigned int word = 0; word < kCaptureProtocolWordCount - 1; ++word)
    {
        program[at++] = (struct sock_filter) BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, word, 0, 2);
        program[at++] = (struct sock_filter) BPF_STMT(BPF_LD | BPF_IMM, filter->excluded[word]);
        program[at]   = (struct sock_filter) BPF_STMT(BPF_JMP | BPF_JA, kResultOffset - at - 1);
        ++at;
    }
    program[at++] = (struct sock_filter) BPF_STMT(BPF_LD | BPF_IMM, filter->excluded[kCaptureProtocolWordCount - 1]);
    program[at++] = (struct sock_filter) BPF_STMT(BPF_ALU | BPF_RSH | BPF_X, 0);
    program[at++] = (struct sock_filter) BPF_STMT(BPF_ALU | BPF_AND | BPF_K, 1);
    program[at++] = (struct sock_filter) BPF_STMT(BPF_ALU | BPF_XOR | BPF_K, 1);
    program[at++] = (struct sock_filter) BPF_STMT(BPF_RET | BPF_A, 0);
    assert(at == kInstructionCount);

    size_t used = stringNPrintf(output, kCaptureLinuxProtocolFilterSize, "%u", (unsigned int) kInstructionCount);
    for (unsigned int i = 0; i < kInstructionCount; ++i)
    {
        used += stringNPrintf(output + used,
                              kCaptureLinuxProtocolFilterSize - used,
                              ",%u %u %u %u",
                              (unsigned int) program[i].code,
                              (unsigned int) program[i].jt,
                              (unsigned int) program[i].jf,
                              program[i].k);
    }
}

/* Both callers reserve four extra argv entries plus the NULL terminator. */
static void capturedeviceAppendProtocolFilter(const char **argv, const char *protocol_filter)
{
    if (protocol_filter[0] == '\0')
    {
        return;
    }
    size_t count = 0;
    while (argv[count] != NULL)
    {
        ++count;
    }
    argv[count++] = "-m";
    argv[count++] = "bpf";
    argv[count++] = "--bytecode";
    argv[count++] = protocol_filter;
    argv[count]   = NULL;
}

capturedevice_command_status_t capturedeviceRunIptablesQueueRule(const char *operation, const char *cidr,
                                                                 uint32_t queue_number, const char *rule_comment,
                                                                 const char *protocol_filter)
{
    char queue_number_arg[16];
    stringNPrintf(queue_number_arg, sizeof(queue_number_arg), "%u", queue_number);

    char lock_wait_arg[16];
    stringNPrintf(lock_wait_arg, sizeof(lock_wait_arg), "%d", kCaptureIptablesLockWaitSeconds);

    const char *argv[21] = {"iptables",
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
    capturedeviceAppendProtocolFilter(argv, protocol_filter);
    return capturedeviceRunCommand("iptables", argv);
}

capturedevice_command_status_t capturedeviceRunIptablesNotrackRule(const char *operation, const char *cidr,
                                                                   const char *rule_comment,
                                                                   const char *protocol_filter)
{
    char lock_wait_arg[16];
    stringNPrintf(lock_wait_arg, sizeof(lock_wait_arg), "%d", kCaptureIptablesLockWaitSeconds);

    // INPUT captures local delivery. Do not exempt transit traffic from
    // conntrack merely because it shares a captured source range. Keep the
    // ordinary raw priority: fragment reassembly still precedes this rule.
    const char *argv[25] = {"iptables", "-w",        lock_wait_arg, "-t",       "raw",        operation,   "PREROUTING",
                            "-s",       cidr,        "-m",          "addrtype", "--dst-type", "LOCAL",     "-m",
                            "comment",  "--comment", rule_comment,  "-j",       "CT",         "--notrack", NULL};
    capturedeviceAppendProtocolFilter(argv, protocol_filter);
    return capturedeviceRunCommand("iptables", argv);
}

static capturedevice_command_status_t capturedeviceReadIptablesRules(bool notrack, char **rules)
{
    char lock_wait_arg[16];
    stringNPrintf(lock_wait_arg, sizeof(lock_wait_arg), "%d", kCaptureIptablesLockWaitSeconds);

    const char *const input_argv[]   = {"iptables", "-w", lock_wait_arg, "-S", "INPUT", NULL};
    const char *const notrack_argv[] = {"iptables", "-w", lock_wait_arg, "-t", "raw", "-S", "PREROUTING", NULL};
    const capturedevice_command_status_t status = capturedeviceRunCommandCapture(
        "iptables", notrack ? notrack_argv : input_argv, kCaptureInspectionMaxOutputBytes, rules);

    // Listing a built-in chain always prints at least the policy line, so an
    // empty snapshot after a clean exit means the output was lost. Accepting it
    // would hide owned rules or make every NFQUEUE number look unused.
    if (status == kCapturedeviceCommandOk && (*rules == NULL || **rules == '\0'))
    {
        memoryFree(*rules);
        *rules = NULL;
        return kCapturedeviceCommandFailed;
    }

    return status;
}

capturedevice_command_status_t capturedeviceReadIptablesInputRules(char **input_rules)
{
    return capturedeviceReadIptablesRules(false, input_rules);
}

capturedevice_command_status_t capturedeviceReadIptablesNotrackRules(char **notrack_rules)
{
    return capturedeviceReadIptablesRules(true, notrack_rules);
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

bool capturedeviceChooseQueueNumber(uint16_t *selected)
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
    kCaptureRuleCommentSize = 48
};

static void capturedeviceFormatRuleComment(const capture_device_t *cdev, uint32_t index, bool notrack, char *comment,
                                           size_t comment_size)
{
    stringNPrintf(comment,
                  comment_size,
                  "%s_%016llX_%08X",
                  notrack ? "WWCAP_NOTRACK" : "WWCAP",
                  (unsigned long long) cdev->rule_token,
                  (unsigned int) index);
}

uint32_t capturedevicePendingRangeCount(const capture_device_t *cdev)
{
    uint32_t pending = 0;
    for (uint32_t i = 0; i < cdev->capture_range_count; ++i)
    {
        if (cdev->rule_states[i].queue != kCaptureRuleAbsent || cdev->rule_states[i].notrack != kCaptureRuleAbsent)
        {
            ++pending;
        }
    }
    return pending;
}

static capture_rule_state_t *capturedeviceRuleState(capture_device_t *cdev, uint32_t index, bool notrack)
{
    return notrack ? &cdev->rule_states[index].notrack : &cdev->rule_states[index].queue;
}

static bool capturedeviceReconcileUnknownRules(capture_device_t *cdev, bool notrack)
{
    bool has_unknown = false;
    for (uint32_t i = 0; i < cdev->capture_range_count; ++i)
    {
        has_unknown = has_unknown || *capturedeviceRuleState(cdev, i, notrack) == kCaptureRuleOutcomeUnknown;
    }
    if (! has_unknown)
    {
        return true;
    }

    char                          *rules  = NULL;
    capturedevice_command_status_t status = capturedeviceReadIptablesRules(notrack, &rules);
    if (status != kCapturedeviceCommandOk)
    {
        LOGE("CaptureDevice: could not reconcile outcome-unknown %s rules (%s)",
             notrack ? "NOTRACK" : "NFQUEUE",
             capturedeviceCommandStatusName(status));
        return false;
    }

    for (uint32_t i = 0; i < cdev->capture_range_count; ++i)
    {
        capture_rule_state_t *state = capturedeviceRuleState(cdev, i, notrack);
        if (*state != kCaptureRuleOutcomeUnknown)
        {
            continue;
        }

        char comment[kCaptureRuleCommentSize];
        capturedeviceFormatRuleComment(cdev, i, notrack, comment, sizeof(comment));
        *state = strstr(rules, comment) != NULL ? kCaptureRuleInstalled : kCaptureRuleAbsent;
    }

    memoryFree(rules);
    return true;
}

static bool capturedeviceRemoveRuleKind(capture_device_t *cdev, bool notrack)
{
    if (! capturedeviceReconcileUnknownRules(cdev, notrack))
    {
        return false;
    }

    for (uint32_t i = cdev->capture_range_count; i > 0; --i)
    {
        const uint32_t        index = i - 1;
        capture_rule_state_t *state = capturedeviceRuleState(cdev, index, notrack);
        if (*state == kCaptureRuleAbsent)
        {
            continue;
        }

        assert(*state == kCaptureRuleInstalled);
        char comment[kCaptureRuleCommentSize];
        capturedeviceFormatRuleComment(cdev, index, notrack, comment, sizeof(comment));
        const capturedevice_command_status_t status =
            notrack
                ? capturedeviceRunIptablesNotrackRule("-D", cdev->capture_cidrs[index], comment, cdev->protocol_filter)
                : capturedeviceRunIptablesQueueRule(
                      "-D", cdev->capture_cidrs[index], cdev->queue_number, comment, cdev->protocol_filter);
        if (status != kCapturedeviceCommandOk)
        {
            if (capturedeviceCommandOutcomeMayBeUnknown(status))
            {
                *state = kCaptureRuleOutcomeUnknown;
            }

            LOGE("CaptureDevice: failed to remove iptables %s rule for %s (%s); %u capture ranges remain pending or "
                 "outcome-unknown",
                 notrack ? "NOTRACK" : "NFQUEUE",
                 cdev->capture_cidrs[index],
                 capturedeviceCommandStatusName(status),
                 capturedevicePendingRangeCount(cdev));
            return false;
        }

        *state = kCaptureRuleAbsent;
    }

    return true;
}

bool capturedeviceRemoveInstalledRules(capture_device_t *cdev)
{
    // Restore tracking first. Still retire the queue rules if NOTRACK cleanup
    // fails; each kind retains its own state for the next bounded cleanup pass.
    const bool notrack_ok = capturedeviceRemoveRuleKind(cdev, true);
    const bool queue_ok   = capturedeviceRemoveRuleKind(cdev, false);
    return notrack_ok && queue_ok;
}

char *capturedeviceFormatCidrString(const ipmask_t *range)
{
    char cidr[24];
    capturedeviceFormatCidr(range, cidr, sizeof(cidr));
    return stringDuplicate(cidr);
}

void capturedeviceFreeCidrs(char **cidrs, uint32_t count)
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

bool capturedeviceInstallRuleKind(capture_device_t *cdev, bool notrack)
{
    for (uint32_t i = 0; i < cdev->capture_range_count; ++i)
    {
        if (! capturedeviceReaderOperational(cdev))
        {
            LOGE("CaptureDevice: reader failed before %s rule %u could be installed",
                 notrack ? "NOTRACK" : "NFQUEUE",
                 i);
            return false;
        }

        capture_rule_state_t *state = capturedeviceRuleState(cdev, i, notrack);
        assert(*state == kCaptureRuleAbsent);
        char comment[kCaptureRuleCommentSize];
        capturedeviceFormatRuleComment(cdev, i, notrack, comment, sizeof(comment));
        const capturedevice_command_status_t status =
            notrack ? capturedeviceRunIptablesNotrackRule("-I", cdev->capture_cidrs[i], comment, cdev->protocol_filter)
                    : capturedeviceRunIptablesQueueRule(
                          "-I", cdev->capture_cidrs[i], cdev->queue_number, comment, cdev->protocol_filter);
        if (status != kCapturedeviceCommandOk)
        {
            if (capturedeviceCommandOutcomeMayBeUnknown(status))
            {
                *state = kCaptureRuleOutcomeUnknown;
            }
            LOGE("CaptureDevice: failed to install iptables %s rule for %s (%s)",
                 notrack ? "NOTRACK" : "NFQUEUE",
                 cdev->capture_cidrs[i],
                 capturedeviceCommandStatusName(status));
            return false;
        }

        *state = kCaptureRuleInstalled;
        if (! capturedeviceReaderOperational(cdev))
        {
            LOGE("CaptureDevice: reader failed after %s rule %u was installed", notrack ? "NOTRACK" : "NFQUEUE", i);
            return false;
        }
    }
    return true;
}

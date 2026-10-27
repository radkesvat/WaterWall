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
#include "capture_linux_reader.h"
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
static capturedevice_command_status_t capturedeviceRunCommandCapture(capture_device_t *cdev, const char *command_name,
                                                                     const char *const argv[], size_t max_output_bytes,
                                                                     char **captured_output)
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
                                            .max_output_bytes   = max_output_bytes,
                                            .progress           = cdev != NULL ? captureReaderService : NULL,
                                            .progress_context   = cdev};

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

static capturedevice_command_status_t capturedeviceRunCommand(capture_device_t *cdev, const char *command_name,
                                                              const char *const argv[])
{
    return capturedeviceRunCommandCapture(cdev, command_name, argv, kCaptureMutationMaxOutputBytes, NULL);
}

static capturedevice_command_status_t capturedeviceSetSysctl(const capturedevice_sysctl_setting_t *setting)
{
    const char *const argv[] = {"sysctl", "-w", setting->argv_setting, NULL};
    return capturedeviceRunCommand(NULL, "sysctl", argv);
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

/* Callers reserve four extra argv entries per filter plus the NULL terminator. */
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

static capturedevice_command_status_t capturedeviceRunIptablesQueueRuleWithContext(
    capture_device_t *cdev, const char *operation, const char *cidr, uint32_t queue_number, const char *rule_comment,
    const char *protocol_filter, const char *steering_filter, unsigned remaining_queues)
{
    char queue_number_arg[16];
    stringNPrintf(queue_number_arg, sizeof(queue_number_arg), "%u", queue_number);

    char lock_wait_arg[16];
    stringNPrintf(lock_wait_arg, sizeof(lock_wait_arg), "%d", kCaptureIptablesLockWaitSeconds);

    /* Sixteen base arguments, two four-argument BPF matches, six statistic
     * arguments and the terminating NULL. */
    const char *argv[31] = {"iptables",
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
    capturedeviceAppendProtocolFilter(argv, steering_filter);
    char probability_arg[16];
    if (remaining_queues > 1)
    {
        /* Integer fixed point keeps the decimal separator independent of the
         * process locale. Twelve places exceed xt_statistic's precision. */
        const uint64_t probability = UINT64_C(1000000000000) / remaining_queues;
        stringNPrintf(probability_arg, sizeof(probability_arg), "0.%012llu", (unsigned long long) probability);
        size_t count = 0;
        while (argv[count] != NULL)
            ++count;
        argv[count++] = "-m";
        argv[count++] = "statistic";
        argv[count++] = "--mode";
        argv[count++] = "random";
        argv[count++] = "--probability";
        argv[count++] = probability_arg;
        argv[count]   = NULL;
    }
    return capturedeviceRunCommand(cdev, "iptables", argv);
}

capturedevice_command_status_t capturedeviceRunIptablesQueueRule(const char *operation, const char *cidr,
                                                                 uint32_t queue_number, const char *rule_comment,
                                                                 const char *protocol_filter)
{
    return capturedeviceRunIptablesQueueRuleWithContext(
        NULL, operation, cidr, queue_number, rule_comment, protocol_filter, "", 0);
}

static capturedevice_command_status_t capturedeviceRunIptablesNotrackRuleWithContext(capture_device_t *cdev,
                                                                                     const char       *operation,
                                                                                     const char       *cidr,
                                                                                     const char       *rule_comment,
                                                                                     const char       *protocol_filter)
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
    return capturedeviceRunCommand(cdev, "iptables", argv);
}

capturedevice_command_status_t capturedeviceRunIptablesNotrackRule(const char *operation, const char *cidr,
                                                                   const char *rule_comment,
                                                                   const char *protocol_filter)
{
    return capturedeviceRunIptablesNotrackRuleWithContext(NULL, operation, cidr, rule_comment, protocol_filter);
}

static capturedevice_command_status_t capturedeviceReadIptablesRules(capture_device_t *cdev, bool notrack, char **rules)
{
    char lock_wait_arg[16];
    stringNPrintf(lock_wait_arg, sizeof(lock_wait_arg), "%d", kCaptureIptablesLockWaitSeconds);

    const char *const input_argv[]   = {"iptables", "-w", lock_wait_arg, "-S", "INPUT", NULL};
    const char *const notrack_argv[] = {"iptables", "-w", lock_wait_arg, "-t", "raw", "-S", "PREROUTING", NULL};
    const capturedevice_command_status_t status = capturedeviceRunCommandCapture(
        cdev, "iptables", notrack ? notrack_argv : input_argv, kCaptureInspectionMaxOutputBytes, rules);

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
    return capturedeviceReadIptablesRules(NULL, false, input_rules);
}

capturedevice_command_status_t capturedeviceReadIptablesNotrackRules(char **notrack_rules)
{
    return capturedeviceReadIptablesRules(NULL, true, notrack_rules);
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

bool capturedeviceSelectUnusedQueueRange(const char *input_rules, uint16_t start, uint16_t count, uint16_t *selected)
{
    assert(input_rules != NULL && selected != NULL && count > 0);

    bool *used = memoryAllocateZero(((size_t) UINT16_MAX + 1U) * sizeof(*used));
    capturedeviceMarkQueueOption(input_rules, "--queue-num", false, used);
    capturedeviceMarkQueueOption(input_rules, "--queue-balance", true, used);

    for (uint32_t offset = 0; offset <= UINT16_MAX; ++offset)
    {
        const uint16_t candidate = (uint16_t) ((uint32_t) start + offset);
        if ((uint32_t) candidate + count > (uint32_t) UINT16_MAX + 1U)
        {
            /* A range cannot wrap, but the search for its first number can. */
            offset += UINT16_MAX - candidate;
            continue;
        }
        bool available = true;
        for (uint32_t lane = 0; lane < count; ++lane)
        {
            if (used[(uint32_t) candidate + lane])
            {
                /* Every skipped start also overlaps this occupied number. */
                offset += lane;
                available = false;
                break;
            }
        }
        if (available)
        {
            *selected = candidate;
            memoryFree(used);
            return true;
        }
    }

    memoryFree(used);
    return false;
}

bool capturedeviceSelectUnusedQueueNumber(const char *input_rules, uint16_t start, uint16_t *selected)
{
    return capturedeviceSelectUnusedQueueRange(input_rules, start, 1, selected);
}

bool capturedeviceChooseQueueRange(uint16_t count, uint16_t *selected)
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
        capturedeviceSelectUnusedQueueRange(input_rules, GSTATE.capturedevice_queue_start_number, count, selected);
    memoryFree(input_rules);
    if (! found)
    {
        LOGE("CaptureDevice: no contiguous range of %u unreferenced NFQUEUE numbers is available",
             (unsigned int) count);
        return false;
    }

    return true;
}

bool capturedeviceChooseQueueNumber(uint16_t *selected)
{
    return capturedeviceChooseQueueRange(1, selected);
}

enum
{
    kCaptureRuleCommentSize = 48
};

typedef enum capture_owned_rule_kind_e
{
    kCaptureOwnedFlow,
    kCaptureOwnedNotrack,
    kCaptureOwnedOpaque
} capture_owned_rule_kind_t;

static void capturedeviceFormatRuleComment(const capture_device_t *cdev, size_t index, capture_owned_rule_kind_t kind,
                                           char *comment, size_t comment_size)
{
    stringNPrintf(comment,
                  comment_size,
                  "%s_%016llX_%016zX",
                  kind == kCaptureOwnedNotrack  ? "WWCAP_NOTRACK"
                  : kind == kCaptureOwnedOpaque ? "WWCAP_OPAQUE"
                                                : "WWCAP",
                  (unsigned long long) cdev->rule_token,
                  index);
}

uint32_t capturedevicePendingRangeCount(const capture_device_t *cdev)
{
    if (cdev->queue_count == 0)
    {
        return 0;
    }
    uint32_t pending = 0;
    for (uint32_t i = 0; i < cdev->capture_range_count; ++i)
    {
        const size_t first         = (size_t) i * cdev->queue_count;
        bool         range_pending = cdev->rule_states[first].notrack != kCaptureRuleAbsent;
        for (uint16_t lane = 0; lane < cdev->queue_count && ! range_pending; ++lane)
        {
            range_pending = cdev->rule_states[first + lane].queue != kCaptureRuleAbsent ||
                            cdev->rule_states[first + lane].opaque != kCaptureRuleAbsent;
        }
        if (range_pending)
        {
            ++pending;
        }
    }
    return pending;
}

static size_t capturedeviceRuleCount(const capture_device_t *cdev, capture_owned_rule_kind_t kind)
{
    if (cdev->queue_count == 0 || (kind == kCaptureOwnedOpaque && cdev->queue_count == 1))
    {
        return 0;
    }
    return kind == kCaptureOwnedNotrack ? cdev->capture_range_count
                                        : (size_t) cdev->capture_range_count * cdev->queue_count;
}

static capture_rule_state_t *capturedeviceRuleState(capture_device_t *cdev, size_t index,
                                                    capture_owned_rule_kind_t kind)
{
    if (kind == kCaptureOwnedNotrack)
        return &cdev->rule_states[index * cdev->queue_count].notrack;
    return kind == kCaptureOwnedOpaque ? &cdev->rule_states[index].opaque : &cdev->rule_states[index].queue;
}

static const char *capturedeviceRuleCidr(const capture_device_t *cdev, size_t index, capture_owned_rule_kind_t kind)
{
    return cdev->capture_cidrs[kind == kCaptureOwnedNotrack ? index : index / cdev->queue_count];
}

static capturedevice_command_status_t capturedeviceRunOwnedRule(capture_device_t *cdev, size_t index,
                                                                capture_owned_rule_kind_t kind, const char *operation,
                                                                const char *comment)
{
    const char *cidr = capturedeviceRuleCidr(cdev, index, kind);
    if (kind == kCaptureOwnedNotrack)
    {
        return capturedeviceRunIptablesNotrackRuleWithContext(cdev, operation, cidr, comment, cdev->protocol_filter);
    }
    const struct capture_linux_queue_s *queue = &cdev->queues[index % cdev->queue_count];
    char                                opaque_filter[kCaptureLinuxSteeringFilterSize];
    if (kind == kCaptureOwnedOpaque)
        captureLinuxBuildOpaqueFilter(cdev->ported.protocols, cdev->ported.count, opaque_filter);
    /* INSERT reverses ascending lane order. Conditional probabilities 1/N,
     * 1/(N-1), ... give each opaque queue the same expected share, with lane
     * zero's unconditional tail ensuring every eligible packet is selected. */
    return capturedeviceRunIptablesQueueRuleWithContext(
        cdev,
        operation,
        cidr,
        queue->number,
        comment,
        cdev->protocol_filter,
        kind == kCaptureOwnedOpaque ? opaque_filter : queue->steering_filter,
        kind == kCaptureOwnedOpaque ? (unsigned) (index % cdev->queue_count) + 1 : 0);
}

static bool capturedeviceReconcileUnknownRules(capture_device_t *cdev, capture_owned_rule_kind_t kind)
{
    bool         has_unknown = false;
    const size_t count       = capturedeviceRuleCount(cdev, kind);
    for (size_t i = 0; i < count; ++i)
    {
        has_unknown = has_unknown || *capturedeviceRuleState(cdev, i, kind) == kCaptureRuleOutcomeUnknown;
    }
    if (! has_unknown)
    {
        return true;
    }

    char                          *rules  = NULL;
    capturedevice_command_status_t status = capturedeviceReadIptablesRules(cdev, kind == kCaptureOwnedNotrack, &rules);
    if (status != kCapturedeviceCommandOk)
    {
        LOGE("CaptureDevice: could not reconcile outcome-unknown %s rules (%s)",
             kind == kCaptureOwnedNotrack ? "NOTRACK" : "NFQUEUE",
             capturedeviceCommandStatusName(status));
        return false;
    }

    for (size_t i = 0; i < count; ++i)
    {
        capture_rule_state_t *state = capturedeviceRuleState(cdev, i, kind);
        if (*state != kCaptureRuleOutcomeUnknown)
        {
            continue;
        }

        char comment[kCaptureRuleCommentSize];
        capturedeviceFormatRuleComment(cdev, i, kind, comment, sizeof(comment));
        *state = strstr(rules, comment) != NULL ? kCaptureRuleInstalled : kCaptureRuleAbsent;
    }

    memoryFree(rules);
    return true;
}

static bool capturedeviceRemoveRuleKind(capture_device_t *cdev, capture_owned_rule_kind_t kind)
{
    if (! capturedeviceReconcileUnknownRules(cdev, kind))
    {
        return false;
    }

    for (size_t i = capturedeviceRuleCount(cdev, kind); i > 0; --i)
    {
        const size_t          index = i - 1;
        capture_rule_state_t *state = capturedeviceRuleState(cdev, index, kind);
        if (*state == kCaptureRuleAbsent)
        {
            continue;
        }

        assert(*state == kCaptureRuleInstalled);
        char comment[kCaptureRuleCommentSize];
        capturedeviceFormatRuleComment(cdev, index, kind, comment, sizeof(comment));
        const capturedevice_command_status_t status = capturedeviceRunOwnedRule(cdev, index, kind, "-D", comment);
        if (status != kCapturedeviceCommandOk)
        {
            if (capturedeviceCommandOutcomeMayBeUnknown(status))
            {
                *state = kCaptureRuleOutcomeUnknown;
            }

            LOGE("CaptureDevice: failed to remove iptables %s rule for %s (%s); %u capture ranges remain pending or "
                 "outcome-unknown",
                 kind == kCaptureOwnedNotrack ? "NOTRACK" : "NFQUEUE",
                 capturedeviceRuleCidr(cdev, index, kind),
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
    const bool notrack_ok = capturedeviceRemoveRuleKind(cdev, kCaptureOwnedNotrack);
    const bool opaque_ok  = capturedeviceRemoveRuleKind(cdev, kCaptureOwnedOpaque);
    const bool queue_ok   = capturedeviceRemoveRuleKind(cdev, kCaptureOwnedFlow);
    return notrack_ok && opaque_ok && queue_ok;
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
        memoryFree(cidrs[i]);
    }

    memoryFree(cidrs);
}

static bool capturedeviceInstallOwnedRuleKind(capture_device_t *cdev, capture_owned_rule_kind_t kind)
{
    const size_t count = capturedeviceRuleCount(cdev, kind);
    for (size_t i = 0; i < count; ++i)
    {
        if (! capturedeviceReaderOperational(cdev))
        {
            LOGE("CaptureDevice: reader failed before %s rule %zu could be installed",
                 kind == kCaptureOwnedNotrack ? "NOTRACK" : "NFQUEUE",
                 i);
            return false;
        }

        capture_rule_state_t *state = capturedeviceRuleState(cdev, i, kind);
        assert(*state == kCaptureRuleAbsent);
        char comment[kCaptureRuleCommentSize];
        capturedeviceFormatRuleComment(cdev, i, kind, comment, sizeof(comment));
        const capturedevice_command_status_t status = capturedeviceRunOwnedRule(cdev, i, kind, "-I", comment);
        if (status != kCapturedeviceCommandOk)
        {
            if (capturedeviceCommandOutcomeMayBeUnknown(status))
            {
                *state = kCaptureRuleOutcomeUnknown;
            }
            LOGE("CaptureDevice: failed to install iptables %s rule for %s (%s)",
                 kind == kCaptureOwnedNotrack ? "NOTRACK" : "NFQUEUE",
                 capturedeviceRuleCidr(cdev, i, kind),
                 capturedeviceCommandStatusName(status));
            return false;
        }

        *state = kCaptureRuleInstalled;
        if (! capturedeviceReaderOperational(cdev))
        {
            LOGE("CaptureDevice: reader failed after %s rule %zu was installed",
                 kind == kCaptureOwnedNotrack ? "NOTRACK" : "NFQUEUE",
                 i);
            return false;
        }
    }
    return true;
}

bool capturedeviceInstallRuleKind(capture_device_t *cdev, bool notrack)
{
    if (notrack)
        return capturedeviceInstallOwnedRuleKind(cdev, kCaptureOwnedNotrack);
    return capturedeviceInstallOwnedRuleKind(cdev, kCaptureOwnedFlow) &&
           capturedeviceInstallOwnedRuleKind(cdev, kCaptureOwnedOpaque);
}

#include "raw_linux_internal.h"

#include "loggers/internal_logger.h"
#include "wproc.h"

#include <ctype.h>
#include <sys/socket.h>

enum
{
    kRawNotrackCommandTimeoutMs = 7000,
    kRawNotrackTerminateGraceMs = 250,
    kRawNotrackInspectionBytes  = 1024 * 1024,
    kRawNotrackMutationBytes    = 64 * 1024,
    kRawNotrackMarkAttempts     = 256
};

/* iptables-save quotes comments; do not interpret mark-like text inside them. */
static const char *rawLinuxNextRuleToken(const char **cursor, size_t *length)
{
    while (isspace((unsigned char) **cursor))
    {
        ++*cursor;
    }
    const char *begin  = *cursor;
    bool        quoted = false;
    while (**cursor != '\0' && (quoted || ! isspace((unsigned char) **cursor)))
    {
        if (**cursor == '\\' && (*cursor)[1] != '\0')
        {
            *cursor += 2;
            continue;
        }
        if (**cursor == '"')
        {
            quoted = ! quoted;
        }
        ++*cursor;
    }
    *length = (size_t) (*cursor - begin);
    return begin;
}

static bool rawLinuxRuleTokenIs(const char *token, size_t length, const char *expected)
{
    return length == strlen(expected) && memcmp(token, expected, length) == 0;
}

static bool rawLinuxParseMark(const char *token, size_t length, uint32_t *value, uint32_t *mask)
{
    if (length == 0 || ! isdigit((unsigned char) *token))
    {
        return false;
    }
    char *end;
    errno                = 0;
    unsigned long parsed = strtoul(token, &end, 0);
    if (errno != 0 || parsed > UINT32_MAX || end == token)
    {
        return false;
    }
    *value = (uint32_t) parsed;
    *mask  = UINT32_MAX;
    if (*end == '/')
    {
        const char *mask_begin = end + 1;
        if (! isdigit((unsigned char) *mask_begin))
        {
            return false;
        }
        errno  = 0;
        parsed = strtoul(mask_begin, &end, 0);
        if (errno != 0 || parsed > UINT32_MAX || end == mask_begin)
        {
            return false;
        }
        *mask = (uint32_t) parsed;
    }
    return end == token + length;
}

static bool rawLinuxScanMarks(const char *rules, bool routing, uint32_t candidate, uint32_t *zero_bits, bool *conflict)
{
    const char *cursor = rules;
    size_t      length;
    const char *token;
    while (*(token = rawLinuxNextRuleToken(&cursor, &length)) != '\0')
    {
        /* Comments can also be unquoted when they contain just one word. */
        if (! routing && rawLinuxRuleTokenIs(token, length, "--comment"))
        {
            discard rawLinuxNextRuleToken(&cursor, &length);
            continue;
        }
        const bool comparison = rawLinuxRuleTokenIs(token, length, routing ? "fwmark" : "--mark");
        const bool assignment = ! routing && (rawLinuxRuleTokenIs(token, length, "--set-mark") ||
                                              rawLinuxRuleTokenIs(token, length, "--set-xmark") ||
                                              rawLinuxRuleTokenIs(token, length, "--tproxy-mark"));
        if (! comparison && ! assignment)
        {
            continue;
        }

        token = rawLinuxNextRuleToken(&cursor, &length);
        uint32_t value, mask;
        if (! rawLinuxParseMark(token, length, &value, &mask))
        {
            return false;
        }
        if (routing)
        {
            /* fib rules mask both the configured value and the packet mark;
             * xt_mark instead compares the masked packet with the full value. */
            value &= mask;
        }
        if (comparison)
        {
            /* Preserve the match result of mark zero, including inverted rules.
             * SO_MARK participates in the initial route lookup before OUTPUT. */
            if (value == 0)
            {
                *zero_bits |= mask;
            }
            if (((candidate & mask) == value) != (value == 0))
            {
                *conflict = true;
            }
        }
        else if ((candidate & mask) == (value & mask))
        {
            *conflict = true;
        }
    }
    return true;
}

bool rawLinuxSelectNotrackMark(const char *iptables_rules, const char *routing_rules, uint32_t *selected)
{
    uint32_t zero_bits = 0;
    bool     conflict  = false;
    if (! rawLinuxScanMarks(iptables_rules, false, 0, &zero_bits, &conflict) ||
        ! rawLinuxScanMarks(routing_rules, true, 0, &zero_bits, &conflict))
    {
        LOGE("RawDevice: unable to parse existing firewall or routing marks");
        return false;
    }

    /* No Linux-wide mark registry exists. Prefer the high half of the 32-bit
     * space, away from small conventional values, while respecting zero-mask
     * matches. Fresh random draws also reduce cross-process/future collisions. */
    for (unsigned int attempt = 0; attempt < kRawNotrackMarkAttempts; ++attempt)
    {
        uint32_t candidate = fastRand32();
        if (attempt < kRawNotrackMarkAttempts / 2)
        {
            candidate |= UINT32_C(0x80000000);
        }
        candidate &= ~zero_bits;
        if (candidate < UINT32_C(0x00010000))
        {
            continue;
        }
        conflict = false;
        if (! rawLinuxScanMarks(iptables_rules, false, candidate, &zero_bits, &conflict) ||
            ! rawLinuxScanMarks(routing_rules, true, candidate, &zero_bits, &conflict))
        {
            return false;
        }
        if (! conflict)
        {
            *selected = candidate;
            return true;
        }
    }
    LOGE("RawDevice: no suitable automatic mark found; disable bypass-conntrack to use explicit mark/routing policy");
    return false;
}

static bool rawLinuxNotrackCommand(const char *const argv[], char **output)
{
    const proc_command_options_t options = {.timeout_ms         = kRawNotrackCommandTimeoutMs,
                                            .terminate_grace_ms = kRawNotrackTerminateGraceMs,
                                            .max_output_bytes =
                                                output != NULL ? kRawNotrackInspectionBytes : kRawNotrackMutationBytes};
    proc_command_result_t        result;
    const bool                   ok = procRunArgvWithDeadline(argv[0], argv, &options, &result);
    if (! ok)
    {
        LOGE("RawDevice: %s failed (exit=%d, timeout=%d, output-limit=%d, execution-error=%d)",
             argv[0],
             result.exit_code,
             result.timed_out,
             result.output_too_large,
             result.spawn_failed);
    }
    if (ok && output != NULL)
    {
        *output       = result.output;
        result.output = NULL;
    }
    procCommandResultDrop(&result);
    return ok;
}

static bool rawLinuxNotrackRule(raw_device_t *rdev, const char *operation)
{
    char mark[32];
    stringNPrintf(mark, sizeof(mark), "0x%08x/0xffffffff", rdev->mark);
    const char *const argv[] = {"iptables",
                                "-w",
                                "5",
                                "-t",
                                "raw",
                                operation,
                                "OUTPUT",
                                "-m",
                                "mark",
                                "--mark",
                                mark,
                                "-m",
                                "comment",
                                "--comment",
                                rdev->notrack_comment,
                                "-j",
                                "CT",
                                "--notrack",
                                NULL};
    return rawLinuxNotrackCommand(argv, NULL);
}

bool rawLinuxNotrackInstall(raw_device_t *rdev)
{
    if (! rdev->bypass_conntrack)
    {
        return true;
    }
    assert(! rdev->notrack_rule_pending);

    const char *const firewall_argv[] = {"iptables-save", NULL};
    const char *const routing_argv[]  = {"ip", "-4", "rule", "show", NULL};
    char             *firewall        = NULL;
    char             *routing         = NULL;
    uint32_t          mark;
    const bool        selected =
        rawLinuxNotrackCommand(firewall_argv, &firewall) && rawLinuxNotrackCommand(routing_argv, &routing) &&
        rawLinuxSelectNotrackMark(firewall != NULL ? firewall : "", routing != NULL ? routing : "", &mark);
    memoryFree(firewall);
    memoryFree(routing);
    if (! selected)
    {
        return false;
    }
    if (setsockopt(rdev->socket, SOL_SOCKET, SO_MARK, &mark, sizeof(mark)) != 0)
    {
        LOGE("RawDevice: unable to set automatic socket mark: %s", strerror(errno));
        return false;
    }

    rdev->mark = mark;
    stringNPrintf(rdev->notrack_comment, sizeof(rdev->notrack_comment), "WWRAW_NOTRACK_%016llx", LLU(fastRand64()));
    /* Even a timeout/nonzero result may have committed the rule. Keep its exact
     * identity until deletion or a successful inspection proves it absent. */
    rdev->notrack_rule_pending = true;
    if (! rawLinuxNotrackRule(rdev, "-I"))
    {
        return false;
    }
    LOGI("RawDevice: device %s bypasses output conntrack with mark 0x%08x (%s)",
         rdev->name,
         rdev->mark,
         rdev->notrack_comment);
    return true;
}

bool rawLinuxNotrackRemove(raw_device_t *rdev)
{
    if (! rdev->notrack_rule_pending)
    {
        return true;
    }
    if (rawLinuxNotrackRule(rdev, "-D"))
    {
        rdev->notrack_rule_pending = false;
        return true;
    }

    const char *const argv[] = {"iptables", "-w", "5", "-t", "raw", "-S", "OUTPUT", NULL};
    char             *rules  = NULL;
    if (rawLinuxNotrackCommand(argv, &rules) && rules != NULL && strstr(rules, "-P OUTPUT ") != NULL &&
        strstr(rules, rdev->notrack_comment) == NULL)
    {
        rdev->notrack_rule_pending = false;
    }
    memoryFree(rules);
    if (rdev->notrack_rule_pending)
    {
        LOGE("RawDevice: output NOTRACK cleanup pending for mark 0x%08x, comment %s; remove this rule from raw "
             "OUTPUT if automatic cleanup cannot complete",
             rdev->mark,
             rdev->notrack_comment);
    }
    return ! rdev->notrack_rule_pending;
}

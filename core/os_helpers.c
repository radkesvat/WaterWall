#include "os_helpers.h"
#include "wplatform.h"
#include "loggers/core_logger.h"
#include "wproc.h"

#ifdef OS_UNIX
#include <sys/resource.h>
void increaseFileLimit(void)
{

    struct rlimit rlim;
    // Get the current limit
    if (getrlimit(RLIMIT_NOFILE, &rlim) == -1)
    {
        LOGF("Core: getrlimit failed");
        exit(EXIT_FAILURE);
    }
    if ((unsigned long) rlim.rlim_max < 8192)
    {
        LOGW(
            "Core: Maximum open file limit is %lu, which is below 8192. If you are running as a vpn server with many customers, "
            "you might experience timeouts if this limit is reached, depending on how many clients are "
            "connected simultaneously",
            (unsigned long) rlim.rlim_max);
    }
    else
    {
        LOGD("Core: File limit %lu -> %lu", (unsigned long) rlim.rlim_cur, (unsigned long) rlim.rlim_max);
    }
    // Set the soft limit to the maximum allowed value
    rlim.rlim_cur = rlim.rlim_max;
    // Apply the new limit
    if (setrlimit(RLIMIT_NOFILE, &rlim) == -1)
    {
        LOGF("Core: setrlimit failed");
        exit(EXIT_FAILURE);
    }
}

#else


void increaseFileLimit(void)
{
    discard (0);
}

#endif

#ifdef OS_LINUX

#include <dirent.h>

#if ! defined(OS_ANDROID) && ! defined(OS_CYGWIN)
#include <sys/sysinfo.h>
#endif

static bool sysctlOutputHasToken(const char *output, const char *token)
{
    size_t token_len = stringLength(token);
    const char *p    = output;

    while (*p != '\0')
    {
        while (*p != '\0' && isspace((unsigned char) *p))
        {
            ++p;
        }

        const char *start = p;
        while (*p != '\0' && ! isspace((unsigned char) *p))
        {
            ++p;
        }

        if ((size_t) (p - start) == token_len && memoryCompare(start, token, token_len) == 0)
        {
            return true;
        }
    }

    return false;
}

static const char *commandResultDiagnostic(cmd_result_t *result)
{
    char *start = result->output;
    while (*start != '\0' && isspace((unsigned char) *start))
    {
        ++start;
    }

    char *end = start + stringLength(start);
    while (end > start && isspace((unsigned char) end[-1]))
    {
        --end;
    }
    *end = '\0';

    for (char *p = start; *p != '\0'; ++p)
    {
        if (isspace((unsigned char) *p))
        {
            *p = ' ';
        }
    }

    return *start != '\0' ? start : "no diagnostic output";
}

#if WW_HAVE_SPLICE
static bool readPipeLimitValue(const char **cursor, unsigned long *value)
{
    while (isspace((unsigned char) **cursor))
    {
        ++*cursor;
    }
    if (! isdigit((unsigned char) **cursor))
    {
        return false;
    }
    char *end;
    errno  = 0;
    *value = strtoul(*cursor, &end, 10);
    if (errno == ERANGE || (*end != '\0' && ! isspace((unsigned char) *end)))
    {
        return false;
    }
    *cursor = end;
    return true;
}
#endif

#if ! defined(OS_ANDROID) && ! defined(OS_CYGWIN)
static bool parseTcpMemoryLimits(const char *output, unsigned long limits[3])
{
    const char *cursor = output;
    for (size_t i = 0; i < 3; ++i)
    {
        while (isspace((unsigned char) *cursor))
        {
            ++cursor;
        }
        if (! isdigit((unsigned char) *cursor))
        {
            return false;
        }
        char *end;
        errno     = 0;
        limits[i] = strtoul(cursor, &end, 10);
        if (errno == ERANGE || limits[i] > LONG_MAX || (*end != '\0' && ! isspace((unsigned char) *end)))
        {
            return false;
        }
        cursor = end;
    }
    while (isspace((unsigned char) *cursor))
    {
        ++cursor;
    }
    return *cursor == '\0' && limits[0] <= limits[1] && limits[1] <= limits[2];
}

static void tryIncreaseTcpMemory(void)
{
    cmd_result_t current = execCmd("sysctl -n net.ipv4.tcp_mem 2>&1");
    if (current.exit_code != 0)
    {
        LOGW("Core: Could not read TCP memory limits (exit %d: %s); keeping current limits",
             current.exit_code,
             commandResultDiagnostic(&current));
        return;
    }
    unsigned long original[3];
    if (! parseTcpMemoryLimits(current.output, original))
    {
        LOGW("Core: Invalid TCP memory limits; keeping current limits");
        return;
    }

    struct sysinfo memory;
    if (sysinfo(&memory) != 0)
    {
        LOGW("Core: Could not determine host RAM for TCP memory tuning: %s; keeping current limits", strerror(errno));
        return;
    }
    if (memory.mem_unit == 0 || memory.totalram == 0 ||
        (uint64_t) memory.totalram > UINT64_MAX / (uint64_t) memory.mem_unit)
    {
        LOGW("Core: Invalid host RAM for TCP memory tuning; keeping current limits");
        return;
    }
    const long page_size = sysconf(_SC_PAGESIZE);
    if (page_size <= 0)
    {
        LOGW("Core: Could not determine page size for TCP memory tuning; keeping current limits");
        return;
    }
    const uint64_t total_bytes = (uint64_t) memory.totalram * (uint64_t) memory.mem_unit;
    const uint64_t unit        = (total_bytes / (uint64_t) page_size) / 16;
    // tcp_mem stores signed native longs, although its sysctl handler accepts unsigned values.
    if (unit == 0 || unit > (uint64_t) LONG_MAX / 6)
    {
        LOGW("Core: Host RAM exceeds the usable TCP memory tuning range; keeping current limits");
        return;
    }
    const unsigned long target[3] = {
        (unsigned long) (3 * unit), (unsigned long) (4 * unit), (unsigned long) (6 * unit)};
    for (size_t i = 0; i < 3; ++i)
    {
        if (target[i] < original[i])
        {
            LOGI("Core: Keeping TCP memory limits %lu %lu %lu pages; target %lu %lu %lu would lower a threshold",
                 original[0],
                 original[1],
                 original[2],
                 target[0],
                 target[1],
                 target[2]);
            return;
        }
    }
    if (memoryCompare(original, target, sizeof(original)) == 0)
    {
        LOGI("Core: TCP memory limits already equal %lu %lu %lu pages", original[0], original[1], original[2]);
        return;
    }

    char command[160];
    snprintf(
        command, sizeof(command), "sysctl -w net.ipv4.tcp_mem=\"%lu %lu %lu\" 2>&1", target[0], target[1], target[2]);
    cmd_result_t result = execCmd(command);
    if (result.exit_code != 0)
    {
        LOGW("Core: Could not raise TCP memory limits from %lu %lu %lu to %lu %lu %lu pages (exit %d: %s)",
             original[0],
             original[1],
             original[2],
             target[0],
             target[1],
             target[2],
             result.exit_code,
             commandResultDiagnostic(&result));
        return;
    }
    current = execCmd("sysctl -n net.ipv4.tcp_mem 2>&1");
    if (current.exit_code != 0)
    {
        LOGW("Core: Could not verify TCP memory limits after tuning (exit %d: %s)",
             current.exit_code,
             commandResultDiagnostic(&current));
        return;
    }
    unsigned long confirmed[3];
    if (! parseTcpMemoryLimits(current.output, confirmed))
    {
        LOGW("Core: Invalid TCP memory limits after tuning; could not verify the applied limits");
        return;
    }
    if (memoryCompare(confirmed, target, sizeof(confirmed)) != 0)
    {
        LOGW("Core: TCP memory tuning requested %lu %lu %lu pages; original %lu %lu %lu, confirmed %lu %lu %lu",
             target[0],
             target[1],
             target[2],
             original[0],
             original[1],
             original[2],
             confirmed[0],
             confirmed[1],
             confirmed[2]);
        return;
    }
    LOGI("Core: TCP memory limits raised from %lu %lu %lu to %lu %lu %lu pages",
         original[0],
         original[1],
         original[2],
         confirmed[0],
         confirmed[1],
         confirmed[2]);
}
#endif

void tryTuneTcp(bool splice_enabled)
{
#if ! defined(OS_ANDROID) && ! defined(OS_CYGWIN)
    if (splice_enabled)
    {
        tryIncreaseTcpMemory();
    }
    const char *commands[] = {
        "sysctl -w net.core.rmem_max=134217728 2>&1",
        "sysctl -w net.core.wmem_max=134217728 2>&1",
        "sysctl -w net.ipv4.tcp_rmem=\"4096 87380 134217728\" 2>&1",
        "sysctl -w net.ipv4.tcp_wmem=\"4096 87380 134217728\" 2>&1",
    };

    size_t applied = 0;
    for (size_t i = 0; i < ARRAY_SIZE(commands); ++i)
    {
        const char  *command = commands[i];
        cmd_result_t result  = execCmd(command);
        if (result.exit_code != 0)
        {
            LOGW("Core: TCP tuning command failed: %s (exit %d: %s)",
                 command,
                 result.exit_code,
                 commandResultDiagnostic(&result));
            continue;
        }
        ++applied;
    }
    LOGI("Core: TCP socket-buffer tuning applied %zu/%zu settings", applied, ARRAY_SIZE(commands));
#else
    discard(splice_enabled);
#endif
}

void tryIncreasePipeLimit(void)
{
#if WW_HAVE_SPLICE
    cmd_result_t limits = execCmd("sysctl -n fs.pipe-user-pages-soft fs.pipe-user-pages-hard 2>&1");
    if (limits.exit_code != 0)
    {
        LOGW("Core: Could not read pipe page limits (exit %d: %s); keeping current limits",
             limits.exit_code,
             commandResultDiagnostic(&limits));
        return;
    }

    const char   *cursor = limits.output;
    unsigned long soft, hard;
    if (! readPipeLimitValue(&cursor, &soft) || ! readPipeLimitValue(&cursor, &hard))
    {
        LOGW("Core: Invalid pipe page limits; keeping current limits");
        return;
    }
    while (isspace((unsigned char) *cursor))
    {
        ++cursor;
    }
    if (*cursor != '\0')
    {
        LOGW("Core: Invalid pipe page limits; keeping current limits");
        return;
    }
    // Zero means unlimited. Never replace an unlimited soft limit with a finite one.
    if (soft == 0)
    {
        return;
    }
    const long page_size = sysconf(_SC_PAGESIZE);
    if (page_size <= 0)
    {
        LOGW("Core: Could not determine page size for the pipe soft limit; keeping current limits");
        return;
    }
    const unsigned long target_bytes = SPLICE_TOTAL_SIZE_LIMIT;
    unsigned long target = target_bytes / (unsigned long) page_size + (target_bytes % (unsigned long) page_size != 0);
    if (hard != 0 && hard < target)
    {
        target = hard;
    }
    if (soft >= target)
    {
        return;
    }

    char command[128];
    snprintf(command, sizeof(command), "sysctl -w fs.pipe-user-pages-soft=%lu 2>&1", target);
    cmd_result_t result = execCmd(command);
    if (result.exit_code != 0)
    {
        LOGW("Core: Could not raise the system-wide pipe soft limit to %lu pages (exit %d: %s)",
             target,
             result.exit_code,
             commandResultDiagnostic(&result));
        return;
    }
    LOGI("Core: System-wide pipe soft limit raised from %lu to %lu pages", soft, target);
#endif
}

uint32_t splicePipeCountLimit(void)
{
#if WW_HAVE_SPLICE
    struct rlimit limit;
    if (getrlimit(RLIMIT_NOFILE, &limit) != 0)
    {
        LOGW("Core: Could not read the descriptor limit; splice inventory will be empty");
        return 0;
    }

    DIR *descriptors = opendir("/proc/self/fd");
    if (descriptors == NULL)
    {
        LOGW("Core: Could not inspect open descriptors; splice inventory will be empty");
        return 0;
    }
    rlim_t         open_count = 0;
    struct dirent *entry;
    errno = 0;
    while ((entry = readdir(descriptors)) != NULL)
    {
        /* Include the directory descriptor conservatively. Saturating at the
         * allowance also handles unexpectedly many inherited descriptors. */
        if (isdigit((unsigned char) entry->d_name[0]) && open_count < limit.rlim_cur)
            ++open_count;
    }
    const bool scan_succeeded  = errno == 0;
    const bool close_succeeded = closedir(descriptors) == 0;
    if (! scan_succeeded || ! close_succeeded)
    {
        LOGW("Core: Could not finish inspecting open descriptors; splice inventory will be empty");
        return 0;
    }

    const uint32_t target_count     = SPLICE_TOTAL_SIZE_LIMIT / SPLICE_PAYLOAD_LIMIT;
    const rlim_t   descriptor_count = (limit.rlim_cur - open_count) / 8;
    return descriptor_count < target_count ? (uint32_t) descriptor_count : target_count;
#else
    return 0;
#endif
}

static void tryEnableFq(void)
{
    cmd_result_t current = execCmd("sysctl -n net.core.default_qdisc 2>&1");
    if (current.exit_code == 0 && sysctlOutputHasToken(current.output, "fq"))
    {
        return;
    }
    if (current.exit_code != 0)
    {
        LOGW("Core: Could not check net.core.default_qdisc (exit %d: %s); trying to set fq",
             current.exit_code,
             commandResultDiagnostic(&current));
    }

    cmd_result_t qdisc = execCmd("sysctl -w net.core.default_qdisc=fq 2>&1");
    if (qdisc.exit_code != 0)
    {
        LOGW("Core: Failed to set net.core.default_qdisc=fq (exit %d: %s)",
             qdisc.exit_code,
             commandResultDiagnostic(&qdisc));
        return;
    }

    current = execCmd("sysctl -n net.core.default_qdisc 2>&1");
    if (current.exit_code == 0 && sysctlOutputHasToken(current.output, "fq"))
    {
        LOGI("Core: fq is now the default queueing discipline");
    }
    else if (current.exit_code != 0)
    {
        LOGW("Core: Could not verify net.core.default_qdisc after setting fq (exit %d: %s)",
             current.exit_code,
             commandResultDiagnostic(&current));
    }
    else
    {
        LOGW("Core: fq enable command completed, but the default queueing discipline is %s",
             commandResultDiagnostic(&current));
    }
}

void tryEnableBbr(void)
{
    cmd_result_t current = execCmd("sysctl -n net.ipv4.tcp_congestion_control 2>&1");
    bool         enabled = current.exit_code == 0 && sysctlOutputHasToken(current.output, "bbr");
    if (current.exit_code != 0)
    {
        LOGW("Core: Could not check the current TCP congestion control (exit %d: %s); trying BBR anyway",
             current.exit_code,
             commandResultDiagnostic(&current));
    }

    if (enabled)
    {
        tryEnableFq();
        LOGI("Core: TCP BBR is already enabled");
        return;
    }

    LOGI("Core: Trying to enable TCP BBR");

    cmd_result_t bbr = execCmd("sysctl -w net.ipv4.tcp_congestion_control=bbr 2>&1");
    if (bbr.exit_code != 0)
    {
        LOGW("Core: Failed to set net.ipv4.tcp_congestion_control=bbr (exit %d: %s)",
             bbr.exit_code,
             commandResultDiagnostic(&bbr));
        return;
    }

    current = execCmd("sysctl -n net.ipv4.tcp_congestion_control 2>&1");
    if (current.exit_code == 0 && sysctlOutputHasToken(current.output, "bbr"))
    {
        tryEnableFq();
        LOGI("Core: TCP BBR enabled");
    }
    else if (current.exit_code != 0)
    {
        LOGW("Core: Could not verify TCP BBR after enabling it (exit %d: %s)",
             current.exit_code,
             commandResultDiagnostic(&current));
    }
    else
    {
        LOGW("Core: TCP BBR enable command completed, but the active congestion control is %s",
             commandResultDiagnostic(&current));
    }
}

#else

void tryTuneTcp(bool splice_enabled)
{
    discard(splice_enabled);
}

void tryIncreasePipeLimit(void)
{
    discard(0);
}

uint32_t splicePipeCountLimit(void)
{
    return 0;
}

void tryEnableBbr(void)
{
    discard (0);
}

#endif

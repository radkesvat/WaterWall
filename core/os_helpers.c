#include "os_helpers.h"
#include "wplatform.h"
#include "loggers/core_logger.h"
#include "wproc.h"

#include <ctype.h>

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

void tryEnableBbr(void)
{
    discard (0);
}

#endif

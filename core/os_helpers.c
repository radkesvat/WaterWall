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

void tryEnableBbr(void)
{
    cmd_result_t current = execCmd("sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null");
    if (current.exit_code == 0 && sysctlOutputHasToken(current.output, "bbr"))
    {
        LOGI("Core: TCP BBR is already enabled");
        return;
    }

    cmd_result_t available = execCmd("sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null");
    if (available.exit_code != 0)
    {
        LOGW("Core: Could not check available TCP congestion controls; skipping BBR enable attempt");
        return;
    }

    if (! sysctlOutputHasToken(available.output, "bbr"))
    {
        LOGI("Core: TCP BBR is not available on this Linux kernel; skipping");
        return;
    }

    LOGI("Core: TCP BBR is available; trying to enable fq queueing and BBR");

    cmd_result_t qdisc = execCmd("sysctl -w net.core.default_qdisc=fq >/dev/null 2>&1");
    if (qdisc.exit_code != 0)
    {
        LOGW("Core: Failed to set net.core.default_qdisc=fq");
    }

    cmd_result_t bbr = execCmd("sysctl -w net.ipv4.tcp_congestion_control=bbr >/dev/null 2>&1");
    if (bbr.exit_code != 0)
    {
        LOGW("Core: Failed to set net.ipv4.tcp_congestion_control=bbr");
        return;
    }

    current = execCmd("sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null");
    if (current.exit_code == 0 && sysctlOutputHasToken(current.output, "bbr"))
    {
        LOGI("Core: TCP BBR enabled");
    }
    else
    {
        LOGW("Core: TCP BBR enable command completed, but BBR is not active");
    }
}

#else

void tryEnableBbr(void)
{
    discard (0);
}

#endif

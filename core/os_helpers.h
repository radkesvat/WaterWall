#pragma once

#include "loggers/core_logger.h"

#ifdef OS_UNIX
#include <sys/resource.h>
static void increaseFileLimit()
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
            "Core: Maximum allowed open files limit is %lu which is below 8192 !\n if you are running as a server then \
        you might experince time-outs if this limits gets reached, depends on how many clients are connected to the server simultaneously\
        ",
            (unsigned long) rlim.rlim_max);
    }
    else
    {
        LOGD("Core: File limit  %lu -> %lu", (unsigned long) rlim.rlim_cur, (unsigned long) rlim.rlim_max);
    }
    // Set the hard limit to the maximum allowed value
    rlim.rlim_cur = rlim.rlim_max;
    // Apply the new limit
    if (setrlimit(RLIMIT_NOFILE, &rlim) == -1)
    {
        LOGF("Core: setrlimit failed");
        exit(EXIT_FAILURE);
    }
}
#else
static void increaseFileLimit()
{
    (void) (0);
}
#endif
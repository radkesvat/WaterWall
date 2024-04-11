#pragma once

#define i_type vec_config_path_t
#define i_key char *
#include "stc/vec.h"

struct core_settings_s
{

    char *log_path;

    char *core_log_level;
    char *core_log_file;
    bool core_log_console;

    char *network_log_level;
    char *network_log_file;
    bool network_log_console;

    char *dns_log_level;
    char *dns_log_file;
    bool dns_log_console;

    int threads;
    char *libs_path;

    vec_config_path_t config_paths;
};

void parseCoreSettings(char *data_json);
struct core_settings_s *getCoreSettings();
void initCoreSettings();

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
    if ((unsigned long)rlim.rlim_max < 8192)
    {
        LOGW("Core: Maximum allowed open files limit is %lu which is below 8192 !\n if you are running as a server then \
        you might experince time-outs if this limits gets reached, depends on how many clients are connected to the server simultaneously\
        ", (unsigned long)rlim.rlim_max);
    }
    else
        LOGD("Core: File limit  %lu -> %lu", (unsigned long)rlim.rlim_cur, (unsigned long)rlim.rlim_max);
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
static void increaseFileLimit() { (void)(0); }
#endif
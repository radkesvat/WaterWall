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

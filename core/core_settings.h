#pragma once

#include "wlibc.h"

#define i_type vec_config_path_t // NOLINT
#define i_key  char *            // NOLINT
#include "stc/vec.h"

struct core_settings_s
{

    char *log_path;

    char *internal_log_file;
    char *internal_log_level;
    bool  internal_log_console;
    char *internal_log_file_fullpath;

    char *core_log_file;
    char *core_log_level;
    bool  core_log_console;
    char *core_log_file_fullpath;

    char *network_log_file;
    char *network_log_level;
    bool  network_log_console;
    char *network_log_file_fullpath;

    char *dns_log_file;
    char *dns_log_level;
    bool  dns_log_console;
    char *dns_log_file_fullpath;

    unsigned int workers_count;
    unsigned int ram_profile;
    char        *libs_path;

    vec_config_path_t config_paths;
};

void                    parseCoreSettings(const char *data_json);
struct core_settings_s *getCoreSettings(void);

void destroyCoreSettings(void);

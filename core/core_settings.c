#include "core_settings.h"
#include "cJSON.h"
#include "hsysinfo.h"
#include "utils/jsonutils.h"
#include "utils/stringutils.h"
#include "ww.h"
#include <assert.h> // for assert
#include <stdio.h>
#include <string.h>

#define DEFAULT_CORE_LOG_LEVEL         "INFO"
#define DEFAULT_CORE_LOG_FILE          "core.json"
#define DEFAULT_CORE_ENABLE_CONSOLE    true
#define DEFAULT_NETWORK_LOG_LEVEL      "INFO"
#define DEFAULT_NETWORK_LOG_FILE       "network.json"
#define DEFAULT_NETWORK_ENABLE_CONSOLE true
#define DEFAULT_DNS_LOG_LEVEL          "INFO"
#define DEFAULT_DNS_LOG_FILE           "dns.json"
#define DEFAULT_DNS_ENABLE_CONSOLE     true
#define DEFAULT_RAM_PROFILE            kRamProfileServer

enum settings_ram_profiles
{
    kRamProfileServer        = kRamProfileL2Memory,
    kRamProfileClientGeneric = kRamProfileS2Memory,
    kRamProfileClientLarger  = kRamProfileM2Memory,
    kRamProfileMinimal       = kRamProfileS1Memory,
};

#define DEFAULT_LIBS_PATH "libs/"
#define DEFAULT_LOG_PATH  "log/"

static struct core_settings_s *settings = NULL;

static void initCoreSettings(void)
{
    assert(settings == NULL);

    settings = wwmGlobalMalloc(sizeof(struct core_settings_s));
    memset(settings, 0, sizeof(struct core_settings_s));

    settings->config_paths = vec_config_path_t_with_capacity(2);
}

static void parseLogPartOfJsonNoCheck(const cJSON *log_obj)
{
    getStringFromJsonObjectOrDefault(&(settings->log_path), log_obj, "path", DEFAULT_LOG_PATH);

    {
        const cJSON *core_obj = cJSON_GetObjectItemCaseSensitive(log_obj, "core");
        if (cJSON_IsObject(core_obj) && (core_obj->child != NULL))
        {

            getStringFromJsonObjectOrDefault(&(settings->core_log_level), core_obj, "loglevel", DEFAULT_CORE_LOG_LEVEL);
            getStringFromJsonObjectOrDefault(&(settings->core_log_file), core_obj, "file", DEFAULT_CORE_LOG_FILE);
            getBoolFromJsonObjectOrDefault(&(settings->core_log_console), core_obj, "console",
                                           DEFAULT_CORE_ENABLE_CONSOLE);
        }
        else
        {
            settings->core_log_level = wwmGlobalMalloc(strlen(DEFAULT_CORE_LOG_LEVEL) + 1);
            settings->core_log_file  = wwmGlobalMalloc(strlen(DEFAULT_CORE_LOG_FILE) + 1);

#if defined(OS_UNIX)
            strcpy(settings->core_log_level, DEFAULT_CORE_LOG_LEVEL);
            strcpy(settings->core_log_file, DEFAULT_CORE_LOG_FILE);
#else
            strcpy_s(settings->core_log_level, strlen(DEFAULT_CORE_LOG_LEVEL) + 1, DEFAULT_CORE_LOG_LEVEL);
            strcpy_s(settings->core_log_file, strlen(DEFAULT_CORE_LOG_FILE) + 1, DEFAULT_CORE_LOG_FILE);
#endif

            settings->core_log_console = DEFAULT_CORE_ENABLE_CONSOLE;
        }
    }

    {
        const cJSON *network_obj = cJSON_GetObjectItemCaseSensitive(log_obj, "network");
        if (cJSON_IsObject(network_obj) && (network_obj->child != NULL))
        {

            getStringFromJsonObjectOrDefault(&(settings->network_log_level), network_obj, "loglevel",
                                             DEFAULT_NETWORK_LOG_LEVEL);
            getStringFromJsonObjectOrDefault(&(settings->network_log_file), network_obj, "file",
                                             DEFAULT_NETWORK_LOG_FILE);
            getBoolFromJsonObjectOrDefault(&(settings->network_log_console), network_obj, "console",
                                           DEFAULT_NETWORK_ENABLE_CONSOLE);
        }
        else
        {
            settings->network_log_level = wwmGlobalMalloc(strlen(DEFAULT_NETWORK_LOG_LEVEL) + 1);
            settings->network_log_file  = wwmGlobalMalloc(strlen(DEFAULT_NETWORK_LOG_FILE) + 1);
#if defined(OS_UNIX)
            strcpy(settings->network_log_level, DEFAULT_NETWORK_LOG_LEVEL);
            strcpy(settings->network_log_file, DEFAULT_NETWORK_LOG_FILE);
#else
            strcpy_s(settings->network_log_level, strlen(DEFAULT_NETWORK_LOG_LEVEL) + 1, DEFAULT_NETWORK_LOG_LEVEL);
            strcpy_s(settings->network_log_file, strlen(DEFAULT_NETWORK_LOG_FILE) + 1, DEFAULT_NETWORK_LOG_FILE);
#endif

            settings->network_log_console = DEFAULT_NETWORK_ENABLE_CONSOLE;
        }
    }

    {
        const cJSON *dns_obj = cJSON_GetObjectItemCaseSensitive(log_obj, "dns");
        if (cJSON_IsObject(dns_obj) && (dns_obj->child != NULL))
        {
            getStringFromJsonObjectOrDefault(&(settings->dns_log_level), dns_obj, "loglevel", DEFAULT_DNS_LOG_LEVEL);
            getStringFromJsonObjectOrDefault(&(settings->dns_log_file), dns_obj, "file", DEFAULT_DNS_LOG_FILE);
            getBoolFromJsonObjectOrDefault(&(settings->dns_log_console), dns_obj, "console",
                                           DEFAULT_DNS_ENABLE_CONSOLE);
        }
        else
        {
            settings->dns_log_level = wwmGlobalMalloc(strlen(DEFAULT_DNS_LOG_LEVEL) + 1);
            settings->dns_log_file  = wwmGlobalMalloc(strlen(DEFAULT_DNS_LOG_FILE) + 1);

#if defined(OS_UNIX)
            strcpy(settings->dns_log_level, DEFAULT_DNS_LOG_LEVEL);
            strcpy(settings->dns_log_file, DEFAULT_DNS_LOG_FILE);
#else
            strcpy_s(settings->dns_log_level, strlen(DEFAULT_DNS_LOG_LEVEL) + 1, DEFAULT_DNS_LOG_LEVEL);
            strcpy_s(settings->dns_log_file, strlen(DEFAULT_DNS_LOG_FILE) + 1, DEFAULT_DNS_LOG_FILE);
#endif
            settings->dns_log_console = DEFAULT_DNS_ENABLE_CONSOLE;
        }
    }
}

static void parseLogPartOfJson(cJSON *log_obj)
{
    if (cJSON_IsObject(log_obj) && (log_obj->child != NULL))
    {
        parseLogPartOfJsonNoCheck(log_obj);
    }
    else
    {

        settings->log_path          = wwmGlobalMalloc(strlen(DEFAULT_LOG_PATH) + 1);
        settings->core_log_file     = wwmGlobalMalloc(strlen(DEFAULT_CORE_LOG_FILE) + 1);
        settings->core_log_level    = wwmGlobalMalloc(strlen(DEFAULT_CORE_LOG_LEVEL) + 1);
        settings->network_log_file  = wwmGlobalMalloc(strlen(DEFAULT_NETWORK_LOG_FILE) + 1);
        settings->network_log_level = wwmGlobalMalloc(strlen(DEFAULT_NETWORK_LOG_LEVEL) + 1);
        settings->dns_log_file      = wwmGlobalMalloc(strlen(DEFAULT_DNS_LOG_FILE) + 1);
        settings->dns_log_level     = wwmGlobalMalloc(strlen(DEFAULT_DNS_LOG_LEVEL) + 1);

#if defined(OS_UNIX)
        strcpy(settings->log_path, DEFAULT_LOG_PATH);
        strcpy(settings->core_log_file, DEFAULT_CORE_LOG_FILE);
        strcpy(settings->core_log_level, DEFAULT_CORE_LOG_LEVEL);
        strcpy(settings->network_log_file, DEFAULT_NETWORK_LOG_FILE);
        strcpy(settings->network_log_level, DEFAULT_NETWORK_LOG_LEVEL);
        strcpy(settings->dns_log_file, DEFAULT_DNS_LOG_FILE);
        strcpy(settings->log_path, DEFAULT_DNS_LOG_LEVEL);

#else
        strcpy_s(settings->log_path, strlen(DEFAULT_LOG_PATH) + 1, DEFAULT_LOG_PATH);
        strcpy_s(settings->core_log_file, strlen(DEFAULT_CORE_LOG_FILE) + 1, DEFAULT_CORE_LOG_FILE);
        strcpy_s(settings->core_log_level, strlen(DEFAULT_CORE_LOG_LEVEL) + 1, DEFAULT_CORE_LOG_LEVEL);
        strcpy_s(settings->network_log_file, strlen(DEFAULT_NETWORK_LOG_FILE) + 1, DEFAULT_NETWORK_LOG_FILE);
        strcpy_s(settings->network_log_level, strlen(DEFAULT_NETWORK_LOG_LEVEL) + 1, DEFAULT_NETWORK_LOG_LEVEL);
        strcpy_s(settings->dns_log_file, strlen(DEFAULT_DNS_LOG_FILE) + 1, DEFAULT_DNS_LOG_FILE);
        strcpy_s(settings->log_path, strlen(DEFAULT_DNS_LOG_LEVEL) + 1, DEFAULT_DNS_LOG_LEVEL);

#endif

        settings->core_log_console    = DEFAULT_CORE_ENABLE_CONSOLE;
        settings->network_log_console = DEFAULT_NETWORK_ENABLE_CONSOLE;
        settings->dns_log_console     = DEFAULT_DNS_ENABLE_CONSOLE;
    }
    settings->core_log_file_fullpath    = concat(settings->log_path, settings->core_log_file);
    settings->network_log_file_fullpath = concat(settings->log_path, settings->network_log_file);
    settings->dns_log_file_fullpath     = concat(settings->log_path, settings->dns_log_file);
}

static void parseConfigPartOfJson(const cJSON *config_array)
{
    if (! cJSON_IsArray(config_array) || (config_array->child == NULL))
    {
        fprintf(stderr, "Error: \"configs\" array in core json is empty or invalid \n");
        exit(1);
    }
    const cJSON *path      = NULL;
    bool         had_child = false;
    cJSON_ArrayForEach(path, config_array)
    {
        if (cJSON_IsString(path) && path->valuestring != NULL)
        {
            had_child          = true;
            unsigned long size = strlen(path->valuestring) + 1;
            char         *buf  = wwmGlobalMalloc(size);
#if defined(OS_UNIX)
            strcpy(buf, path->valuestring);
#else
            strcpy_s(buf, size, path->valuestring);
#endif
            vec_config_path_t_push(&settings->config_paths, buf);
        }
    }

    if (! had_child)
    {
        fprintf(stderr, "Error: \"configs\" array in core json is empty or invalid \n");
        exit(1);
    }
}

static void parseMiscPartOfJson(cJSON *misc_obj)
{

    if (cJSON_IsObject(misc_obj) && (misc_obj->child != NULL))
    {
        getStringFromJsonObjectOrDefault(&(settings->libs_path), misc_obj, "libs-path", DEFAULT_LIBS_PATH);
        if (! getIntFromJsonObjectOrDefault(&(settings->workers_count), misc_obj, "workers", get_ncpu()))
        {
            printf("workers unspecified in json (misc), fallback to cpu cores: %d\n", settings->workers_count);
        }
        // user could just enter 0 as value
        if (settings->workers_count <= 0)
        {
            settings->workers_count = get_ncpu();
        }

        const cJSON *json_ram_profile = cJSON_GetObjectItemCaseSensitive(misc_obj, "ram-profile");
        if (cJSON_IsNumber(json_ram_profile))
        {
            int profile = json_ram_profile->valueint;

            switch (profile)
            {
            case 0:
            case 1:
                settings->ram_profile = kRamProfileS1Memory;
                break;
            case 2:
                settings->ram_profile = kRamProfileS2Memory;
                break;
            case 3:
                settings->ram_profile = kRamProfileM1Memory;
                break;
            case 4:
                settings->ram_profile = kRamProfileM2Memory;
                break;
            case 5:
                settings->ram_profile = kRamProfileL1Memory;
                break;
            case 6:
                settings->ram_profile = kRamProfileL2Memory;
                break;
            default:
                fprintf(stderr, "CoreSettings: ram-profile must be in range [1 - 5]\n");
                exit(1);
                break;
            }
        }
        else if (cJSON_IsString(json_ram_profile))
        {
            char *string_ram_profile = NULL;
            getStringFromJsonObject(&string_ram_profile, misc_obj, "ram-profile");
            toLowerCase(string_ram_profile);

            if (0 == strcmp(string_ram_profile, "server"))
            {
                settings->ram_profile = kRamProfileServer;
            }
            else if (0 == strcmp(string_ram_profile, "client"))
            {
                settings->ram_profile = kRamProfileClientGeneric;
            }
            else if (0 == strcmp(string_ram_profile, "client-larger"))
            {
                settings->ram_profile = kRamProfileClientLarger;
            }
            else if (0 == strcmp(string_ram_profile, "ultralow") || 0 == strcmp(string_ram_profile, "minimal"))
            {
                settings->ram_profile = kRamProfileMinimal;
            }

            if (settings->ram_profile <= 0)
            {
                fprintf(stderr, "CoreSettings: ram-profile can hold \"server\" or \"client\" "
                                "or \"client-larger\" or \"minimal\" or \"ultralow\" \n");

                exit(1);
            }
            wwmGlobalFree(string_ram_profile);
        }
        else
        {
            settings->ram_profile = DEFAULT_RAM_PROFILE;
        }
    }
    else
    {
        unsigned long size  = strlen(DEFAULT_LIBS_PATH) + 1;
        settings->libs_path = wwmGlobalMalloc(size);
#if defined(OS_UNIX)
        strcpy(settings->libs_path, DEFAULT_LIBS_PATH);
#else
        strcpy_s(settings->libs_path, size, DEFAULT_LIBS_PATH);
#endif
        settings->workers_count = get_ncpu();
        printf("misc block unspecified in json, using defaults. cpu cores: %d\n", settings->workers_count);
    }
}
void parseCoreSettings(const char *data_json)
{
    if (settings == NULL)
    {
        initCoreSettings();
    }

    cJSON *json = cJSON_Parse(data_json);
    if (json == NULL)
    {
        const char *error_ptr = cJSON_GetErrorPtr();
        if (error_ptr != NULL)
        {
            fprintf(stderr, "JSON Error before: %s\n", error_ptr);
        }
        exit(1);
    }

    parseLogPartOfJson(cJSON_GetObjectItemCaseSensitive(json, "log"));
    parseConfigPartOfJson(cJSON_GetObjectItemCaseSensitive(json, "configs"));
    parseMiscPartOfJson(cJSON_GetObjectItemCaseSensitive(json, "misc"));

    if (settings->workers_count <= 0)
    {
        fprintf(stderr, "CoreSettings: the workers count is invalid");
        exit(1);
    }
    if (settings->workers_count > 254)
    {
        fprintf(stderr, "CoreSettings: workers count is shrinked to maximum supported value -> 254");
        settings->workers_count = 254;
    }

    cJSON_Delete(json);

    // TODO (DNS) Implement dns settings and backend
}

struct core_settings_s *getCoreSettings(void)
{
    return settings;
}

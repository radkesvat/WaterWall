#include "core_settings.h"
#include "wwapi.h"

// Default logging configurations
#define DEFAULT_INTERNAL_LOG_LEVEL      "INFO"
#define DEFAULT_INTERNAL_LOG_FILE       "internal.log"
#define DEFAULT_INTERNAL_ENABLE_CONSOLE true
#define DEFAULT_CORE_LOG_LEVEL          "INFO"
#define DEFAULT_CORE_LOG_FILE           "core.log"
#define DEFAULT_CORE_ENABLE_CONSOLE     true
#define DEFAULT_NETWORK_LOG_LEVEL       "INFO"
#define DEFAULT_NETWORK_LOG_FILE        "network.log"
#define DEFAULT_NETWORK_ENABLE_CONSOLE  true
#define DEFAULT_DNS_LOG_LEVEL           "INFO"
#define DEFAULT_DNS_LOG_FILE            "dns.log"
#define DEFAULT_DNS_ENABLE_CONSOLE      true
#define DEFAULT_RAM_PROFILE             kRamProfileServer

#define DEFAULT_MTU_PROFILE             1500

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

    settings = memoryAllocate(sizeof(struct core_settings_s));
    memorySet(settings, 0, sizeof(struct core_settings_s));

    settings->config_paths = vec_config_path_t_with_capacity(2);
}

static void parseLogPartOfJsonNoCheck(const cJSON *log_obj)
{
    getStringFromJsonObjectOrDefault(&(settings->log_path), log_obj, "path", DEFAULT_LOG_PATH);

    const cJSON *internal_obj = cJSON_GetObjectItemCaseSensitive(log_obj, "internal");
    if (cJSON_IsObject(internal_obj) && (internal_obj->child != NULL))
    {
        getStringFromJsonObjectOrDefault(&(settings->internal_log_level), internal_obj, "loglevel",
                                         DEFAULT_INTERNAL_LOG_LEVEL);
        getStringFromJsonObjectOrDefault(&(settings->internal_log_file), internal_obj, "file",
                                         DEFAULT_INTERNAL_LOG_FILE);
        getBoolFromJsonObjectOrDefault(&(settings->internal_log_console), internal_obj, "console",
                                       DEFAULT_INTERNAL_ENABLE_CONSOLE);
    }
    else
    {
        settings->internal_log_level   = stringDuplicate(DEFAULT_INTERNAL_LOG_LEVEL);
        settings->internal_log_file    = stringDuplicate(DEFAULT_INTERNAL_LOG_FILE);
        settings->internal_log_console = DEFAULT_INTERNAL_ENABLE_CONSOLE;
    }

    const cJSON *core_obj = cJSON_GetObjectItemCaseSensitive(log_obj, "core");
    if (cJSON_IsObject(core_obj) && (core_obj->child != NULL))
    {
        getStringFromJsonObjectOrDefault(&(settings->core_log_level), core_obj, "loglevel", DEFAULT_CORE_LOG_LEVEL);
        getStringFromJsonObjectOrDefault(&(settings->core_log_file), core_obj, "file", DEFAULT_CORE_LOG_FILE);
        getBoolFromJsonObjectOrDefault(&(settings->core_log_console), core_obj, "console", DEFAULT_CORE_ENABLE_CONSOLE);
    }
    else
    {
        settings->core_log_level   = stringDuplicate(DEFAULT_CORE_LOG_LEVEL);
        settings->core_log_file    = stringDuplicate(DEFAULT_CORE_LOG_FILE);
        settings->core_log_console = DEFAULT_CORE_ENABLE_CONSOLE;
    }

    const cJSON *network_obj = cJSON_GetObjectItemCaseSensitive(log_obj, "network");
    if (cJSON_IsObject(network_obj) && (network_obj->child != NULL))
    {
        getStringFromJsonObjectOrDefault(&(settings->network_log_level), network_obj, "loglevel",
                                         DEFAULT_NETWORK_LOG_LEVEL);
        getStringFromJsonObjectOrDefault(&(settings->network_log_file), network_obj, "file", DEFAULT_NETWORK_LOG_FILE);
        getBoolFromJsonObjectOrDefault(&(settings->network_log_console), network_obj, "console",
                                       DEFAULT_NETWORK_ENABLE_CONSOLE);
    }
    else
    {
        settings->network_log_level   = stringDuplicate(DEFAULT_NETWORK_LOG_LEVEL);
        settings->network_log_file    = stringDuplicate(DEFAULT_NETWORK_LOG_FILE);
        settings->network_log_console = DEFAULT_NETWORK_ENABLE_CONSOLE;
    }

    const cJSON *dns_obj = cJSON_GetObjectItemCaseSensitive(log_obj, "dns");
    if (cJSON_IsObject(dns_obj) && (dns_obj->child != NULL))
    {
        getStringFromJsonObjectOrDefault(&(settings->dns_log_level), dns_obj, "loglevel", DEFAULT_DNS_LOG_LEVEL);
        getStringFromJsonObjectOrDefault(&(settings->dns_log_file), dns_obj, "file", DEFAULT_DNS_LOG_FILE);
        getBoolFromJsonObjectOrDefault(&(settings->dns_log_console), dns_obj, "console", DEFAULT_DNS_ENABLE_CONSOLE);
    }
    else
    {
        settings->dns_log_level   = stringDuplicate(DEFAULT_DNS_LOG_LEVEL);
        settings->dns_log_file    = stringDuplicate(DEFAULT_DNS_LOG_FILE);
        settings->dns_log_console = DEFAULT_DNS_ENABLE_CONSOLE;
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
        // Set default values when log object is invalid
        settings->log_path           = stringDuplicate(DEFAULT_LOG_PATH);
        settings->core_log_file      = stringDuplicate(DEFAULT_CORE_LOG_FILE);
        settings->core_log_level     = stringDuplicate(DEFAULT_CORE_LOG_LEVEL);
        settings->network_log_file   = stringDuplicate(DEFAULT_NETWORK_LOG_FILE);
        settings->network_log_level  = stringDuplicate(DEFAULT_NETWORK_LOG_LEVEL);
        settings->dns_log_file       = stringDuplicate(DEFAULT_DNS_LOG_FILE);
        settings->dns_log_level      = stringDuplicate(DEFAULT_DNS_LOG_LEVEL);
        settings->internal_log_file  = stringDuplicate(DEFAULT_INTERNAL_LOG_FILE);
        settings->internal_log_level = stringDuplicate(DEFAULT_INTERNAL_LOG_LEVEL);

        settings->core_log_console     = DEFAULT_CORE_ENABLE_CONSOLE;
        settings->network_log_console  = DEFAULT_NETWORK_ENABLE_CONSOLE;
        settings->dns_log_console      = DEFAULT_DNS_ENABLE_CONSOLE;
        settings->internal_log_console = DEFAULT_INTERNAL_ENABLE_CONSOLE;
    }

    // Construct full paths
    settings->core_log_file_fullpath     = stringConcat(settings->log_path, settings->core_log_file);
    settings->network_log_file_fullpath  = stringConcat(settings->log_path, settings->network_log_file);
    settings->dns_log_file_fullpath      = stringConcat(settings->log_path, settings->dns_log_file);
    settings->internal_log_file_fullpath = stringConcat(settings->log_path, settings->internal_log_file);
}

static void parseConfigPartOfJson(const cJSON *config_array)
{
    if (! cJSON_IsArray(config_array) || (config_array->child == NULL))
    {
        printError("Error: \"configs\" array in core json is empty or invalid \n");
        terminateProgram(1);
    }
    const cJSON *path      = NULL;
    bool         had_child = false;
    cJSON_ArrayForEach(path, config_array)
    {
        if (cJSON_IsString(path) && path->valuestring != NULL)
        {
            had_child          = true;
            unsigned long size = stringLength(path->valuestring) + 1;
            char         *buf  = memoryAllocate(size);
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
        printError("Error: \"configs\" array in core json is empty or invalid \n");
        terminateProgram(1);
    }
}

static void parseMiscPartOfJson(cJSON *misc_obj)
{
    if (cJSON_IsObject(misc_obj) && (misc_obj->child != NULL))
    {
        int mtu_size = DEFAULT_MTU_PROFILE;
        getIntFromJsonObjectOrDefault(&mtu_size, misc_obj, "mtu-size", DEFAULT_MTU_PROFILE);
        if (mtu_size <= 0)
        {
            printError("CoreSettings: mtu-size must be greater than 0, using default value %d\n", DEFAULT_MTU_PROFILE);
            mtu_size = DEFAULT_MTU_PROFILE;
        }
        settings->mtu_size = (uint16_t) mtu_size;
        
        getStringFromJsonObjectOrDefault(&(settings->libs_path), misc_obj, "libs-path", DEFAULT_LIBS_PATH);
        if (! getIntFromJsonObjectOrDefault((int *) &(settings->workers_count), misc_obj, "workers", getNCPU()))
        {
            printf("workers unspecified in json (misc), fallback to cpu cores: %d\n", settings->workers_count);
        }
        // user could just enter 0 as value
        if (settings->workers_count <= 0)
        {
            settings->workers_count = (unsigned int) getNCPU();
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
                printError("CoreSettings: ram-profile must be in range [1 - 5]\n");
                terminateProgram(1);
                break;
            }
        }
        else if (cJSON_IsString(json_ram_profile))
        {
            char *string_ram_profile = NULL;
            getStringFromJsonObject(&string_ram_profile, misc_obj, "ram-profile");
            stringLowerCase(string_ram_profile);

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
                printError("CoreSettings: ram-profile can hold \"server\" or \"client\" "
                           "or \"client-larger\" or \"minimal\" or \"ultralow\" \n");

                terminateProgram(1);
            }
            memoryFree(string_ram_profile);
        }
        else
        {
            settings->ram_profile = DEFAULT_RAM_PROFILE;
        }
    }
    else
    {
        settings->libs_path     = stringDuplicate(DEFAULT_LIBS_PATH);
        settings->workers_count = (unsigned int) getNCPU();
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
            printError("JSON Error before: %s\n", error_ptr);
        }
        terminateProgram(1);
    }

    parseLogPartOfJson(cJSON_GetObjectItemCaseSensitive(json, "log"));
    parseConfigPartOfJson(cJSON_GetObjectItemCaseSensitive(json, "configs"));
    parseMiscPartOfJson(cJSON_GetObjectItemCaseSensitive(json, "misc"));

    if (settings->workers_count <= 0)
    {
        printError("CoreSettings: the workers count is invalid");
        terminateProgram(1);
    }
    if (settings->workers_count > 254)
    {
        printError("CoreSettings: workers count is shrinked to maximum supported value -> 254");
        settings->workers_count = 254;
    }

    cJSON_Delete(json);

    // TODO (DNS) Implement dns settings and backend
}

struct core_settings_s *getCoreSettings(void)
{
    return settings;
}

void destroyCoreSettings(void)
{
    if (settings == NULL)
    {
        return;
    }
    c_foreach(k, vec_config_path_t, settings->config_paths){
        memoryFree(*k.ref);
    }

    // Free all strings
    memoryFree(settings->log_path);
    memoryFree(settings->internal_log_file);
    memoryFree(settings->internal_log_level);
    memoryFree(settings->core_log_file);
    memoryFree(settings->core_log_level);
    memoryFree(settings->network_log_file);
    memoryFree(settings->network_log_level);
    memoryFree(settings->dns_log_file);
    memoryFree(settings->dns_log_level);
    memoryFree(settings->libs_path);

    // Free full paths
    memoryFree(settings->internal_log_file_fullpath);
    memoryFree(settings->core_log_file_fullpath);
    memoryFree(settings->network_log_file_fullpath);
    memoryFree(settings->dns_log_file_fullpath);

    vec_config_path_t_drop(&settings->config_paths);

    // Free the settings structure itself
    memoryFree(settings);
    settings = NULL;
}

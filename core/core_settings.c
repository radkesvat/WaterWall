#include "core_settings.h"
#include "hv/hsysinfo.h"
#include "utils/jsonutils.h"
#include "utils/stringutils.h"
#include <assert.h> // for assert
#include <stdio.h>
#include <string.h>

#define DEFAULT_CORE_LOG_LEVEL      "INFO"
#define DEFAULT_CORE_LOG_FILE       "core.json"
#define DEFAULT_CORE_ENABLE_CONSOLE true

#define DEFAULT_NETWORK_LOG_LEVEL      "INFO"
#define DEFAULT_NETWORK_LOG_FILE       "network.json"
#define DEFAULT_NETWORK_ENABLE_CONSOLE true

#define DEFAULT_DNS_LOG_LEVEL      "INFO"
#define DEFAULT_DNS_LOG_FILE       "dns.json"
#define DEFAULT_DNS_ENABLE_CONSOLE true

#define DEFAULT_LIBS_PATH "libs/"
#define DEFAULT_LOG_PATH  "log/"

static struct core_settings_s *settings = NULL;

#ifdef OS_UNIX
#include <sys/resource.h>
void increaseFileLimit()
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
void increaseFileLimit()
{
    (void) (0);
}
#endif

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
            settings->core_log_level = malloc(strlen(DEFAULT_CORE_LOG_LEVEL) + 1);
            strcpy(settings->core_log_level, DEFAULT_CORE_LOG_LEVEL);
            settings->core_log_file = malloc(strlen(DEFAULT_CORE_LOG_FILE) + 1);
            strcpy(settings->core_log_file, DEFAULT_CORE_LOG_FILE);
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
            settings->network_log_level = malloc(strlen(DEFAULT_NETWORK_LOG_LEVEL) + 1);
            strcpy(settings->network_log_level, DEFAULT_NETWORK_LOG_LEVEL);
            settings->network_log_file = malloc(strlen(DEFAULT_NETWORK_LOG_FILE) + 1);
            strcpy(settings->network_log_file, DEFAULT_NETWORK_LOG_FILE);
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
            settings->dns_log_level = malloc(strlen(DEFAULT_DNS_LOG_LEVEL) + 1);
            strcpy(settings->dns_log_level, DEFAULT_DNS_LOG_LEVEL);
            settings->dns_log_file = malloc(strlen(DEFAULT_DNS_LOG_FILE) + 1);
            strcpy(settings->dns_log_file, DEFAULT_DNS_LOG_FILE);
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
        settings->log_path = malloc(strlen(DEFAULT_LOG_PATH) + 1);
        strcpy(settings->log_path, DEFAULT_LOG_PATH);
        settings->core_log_file = malloc(strlen(DEFAULT_CORE_LOG_FILE) + 1);
        strcpy(settings->core_log_file, DEFAULT_CORE_LOG_FILE);
        settings->core_log_level = malloc(strlen(DEFAULT_CORE_LOG_LEVEL) + 1);
        strcpy(settings->core_log_level, DEFAULT_CORE_LOG_LEVEL);
        settings->core_log_console = DEFAULT_CORE_ENABLE_CONSOLE;
        settings->network_log_file = malloc(strlen(DEFAULT_NETWORK_LOG_FILE) + 1);
        strcpy(settings->network_log_file, DEFAULT_NETWORK_LOG_FILE);
        settings->network_log_level = malloc(strlen(DEFAULT_NETWORK_LOG_LEVEL) + 1);
        strcpy(settings->network_log_level, DEFAULT_NETWORK_LOG_LEVEL);
        settings->network_log_console = DEFAULT_NETWORK_ENABLE_CONSOLE;
        settings->dns_log_file        = malloc(strlen(DEFAULT_DNS_LOG_FILE) + 1);
        strcpy(settings->dns_log_file, DEFAULT_DNS_LOG_FILE);
        settings->dns_log_level = malloc(strlen(DEFAULT_DNS_LOG_LEVEL) + 1);
        strcpy(settings->log_path, DEFAULT_DNS_LOG_LEVEL);
        settings->dns_log_console = DEFAULT_DNS_ENABLE_CONSOLE;
    }
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
            had_child = true;

            char *buf = malloc(strlen(path->valuestring) + 1);
            strcpy(buf, path->valuestring);
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
        if (! getIntFromJsonObject(&(settings->workers_count), misc_obj, "workers"))
        {
            settings->workers_count = 0;
            printf("workers_count unspecified in json (misc), fallback to cpu cores: %d\n", settings->workers_count);
        }
        if (settings->workers_count <= 0)
        {
            settings->workers_count = get_ncpu();
        }
    }
    else
    {
        settings->libs_path = malloc(strlen(DEFAULT_LIBS_PATH) + 1);
        strcpy(settings->libs_path, DEFAULT_LIBS_PATH);
        settings->workers_count = get_ncpu();
        printf("workers_count unspecified in json (misc), fallback to cpu cores: %d\n", settings->workers_count);
    }
}
void parseCoreSettings(char *data_json)
{
    assert(settings != NULL);

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

    if ((settings->workers_count < 0) || (settings->workers_count > 200))
    {
        LOGF("CoreSettings: the workers count is invalid");
        exit(1);
    }
    cJSON_Delete(json);
    // TODO (DNS) Implement dns settings and backend
}

char *getCoreLoggerFullPath()
{
    return concat(settings->log_path, settings->core_log_file);
}
char *getNetworkLoggerFullPath()
{
    return concat(settings->log_path, settings->network_log_file);
}
char *getDnsLoggerFullPath()
{
    return concat(settings->log_path, settings->dns_log_file);
}

struct core_settings_s *getCoreSettings()
{
    return settings;
}

void initCoreSettings()
{
    assert(settings == NULL); // we can't use logs here, so just assert

    settings = malloc(sizeof(struct core_settings_s));
    memset(settings, 0, sizeof(struct core_settings_s));

    settings->config_paths = vec_config_path_t_with_capacity(10);
}

#include "core_settings.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <assert.h> // for assert

#include "cJSON.h"

#define DEFAULT_CORE_LOG_LEVEL "debug"
#define DEFAULT_CORE_LOG_FILE "core.json"
#define DEFAULT_NETWORK_LOG_LEVEL "debug"
#define DEFAULT_NETWORK_LOG_FILE "network.json"
#define DEFAULT_DNS_LOG_LEVEL "debug"
#define DEFAULT_DNS_LOG_FILE "dns.json"

#define DEFAULT_LOG_PATH "log/"

static struct core_settings_s *settings = NULL;

static void parseLogSection(const cJSON *log_obj)
{
    const cJSON *path = cJSON_GetObjectItemCaseSensitive(log_obj, "path");
    if (cJSON_IsString(path) && (path->valuestring != NULL))
    {
        settings->log_path = malloc(strlen(path->valuestring) + 1);
        strcpy(settings->log_path, path->valuestring);
    }
    else
    {
        settings->log_path = malloc(strlen(DEFAULT_LOG_PATH) + 1);
        strcpy(settings->log_path, DEFAULT_LOG_PATH);
    }

    {
        const cJSON *core_obj = cJSON_GetObjectItemCaseSensitive(log_obj, "core");
        if (cJSON_IsObject(core_obj) && (core_obj->child != NULL))
        {
            const cJSON *loglevel = cJSON_GetObjectItemCaseSensitive(core_obj, "loglevel");
            if (cJSON_IsString(loglevel) && (loglevel->valuestring != NULL))
            {
                settings->core_log_level = malloc(strlen(loglevel->valuestring) + 1);
                strcpy(settings->core_log_level, loglevel->valuestring);
            }
            else
            {
                settings->core_log_level = malloc(strlen(DEFAULT_CORE_LOG_LEVEL) + 1);
                strcpy(settings->core_log_level, DEFAULT_CORE_LOG_LEVEL);
            }

            const cJSON *file = cJSON_GetObjectItemCaseSensitive(core_obj, "file");
            if (cJSON_IsString(file) && (file->valuestring != NULL))
            {
                settings->core_log_file = malloc(strlen(file->valuestring) + 1);
                strcpy(settings->core_log_file, file->valuestring);
            }
            else
            {
                settings->core_log_file = malloc(strlen(DEFAULT_CORE_LOG_FILE) + 1);
                strcpy(settings->core_log_file, DEFAULT_CORE_LOG_FILE);
            }
        }
        else
        {
            settings->core_log_level = malloc(strlen(DEFAULT_CORE_LOG_LEVEL) + 1);
            strcpy(settings->core_log_level, DEFAULT_CORE_LOG_LEVEL);
            settings->core_log_file = malloc(strlen(DEFAULT_CORE_LOG_FILE) + 1);
            strcpy(settings->core_log_file, DEFAULT_CORE_LOG_FILE);
        }
    }

    {
        const cJSON *network_obj = cJSON_GetObjectItemCaseSensitive(log_obj, "network");
        if (cJSON_IsObject(network_obj) && (network_obj->child != NULL))
        {
            const cJSON *loglevel = cJSON_GetObjectItemCaseSensitive(network_obj, "loglevel");
            if (cJSON_IsString(loglevel) && (loglevel->valuestring != NULL))
            {
                settings->network_log_level = malloc(strlen(loglevel->valuestring) + 1);
                strcpy(settings->network_log_level, loglevel->valuestring);
            }
            else
            {
                settings->network_log_level = malloc(strlen(DEFAULT_NETWORK_LOG_LEVEL) + 1);
                strcpy(settings->network_log_level, DEFAULT_NETWORK_LOG_LEVEL);
            }

            const cJSON *file = cJSON_GetObjectItemCaseSensitive(network_obj, "file");
            if (cJSON_IsString(file) && (file->valuestring != NULL))
            {
                settings->network_log_file = malloc(strlen(file->valuestring) + 1);
                strcpy(settings->network_log_file, file->valuestring);
            }
            else
            {
                settings->network_log_file = malloc(strlen(DEFAULT_NETWORK_LOG_FILE) + 1);
                strcpy(settings->network_log_file, DEFAULT_NETWORK_LOG_FILE);
            }
        }
        else
        {
            settings->network_log_level = malloc(strlen(DEFAULT_NETWORK_LOG_LEVEL) + 1);
            strcpy(settings->network_log_level, DEFAULT_NETWORK_LOG_LEVEL);
            settings->network_log_file = malloc(strlen(DEFAULT_NETWORK_LOG_FILE) + 1);
            strcpy(settings->network_log_file, DEFAULT_NETWORK_LOG_FILE);
        }
    }

    {
        const cJSON *dns_obj = cJSON_GetObjectItemCaseSensitive(log_obj, "dns");
        if (cJSON_IsObject(dns_obj) && (dns_obj->child != NULL))
        {
            const cJSON *loglevel = cJSON_GetObjectItemCaseSensitive(dns_obj, "loglevel");
            if (cJSON_IsString(loglevel) && (loglevel->valuestring != NULL))
            {
                settings->dns_log_level = malloc(strlen(loglevel->valuestring) + 1);
                strcpy(settings->dns_log_level, loglevel->valuestring);
            }
            else
            {
                settings->dns_log_level = malloc(strlen(DEFAULT_DNS_LOG_LEVEL) + 1);
                strcpy(settings->dns_log_level, DEFAULT_DNS_LOG_LEVEL);
            }

            const cJSON *file = cJSON_GetObjectItemCaseSensitive(dns_obj, "file");
            if (cJSON_IsString(file) && (file->valuestring != NULL))
            {
                settings->dns_log_file = malloc(strlen(file->valuestring) + 1);
                strcpy(settings->dns_log_file, file->valuestring);
            }
            else
            {
                settings->dns_log_file = malloc(strlen(DEFAULT_DNS_LOG_FILE) + 1);
                strcpy(settings->dns_log_file, DEFAULT_DNS_LOG_FILE);
            }
        }
        else
        {
            settings->dns_log_level = malloc(strlen(DEFAULT_DNS_LOG_LEVEL) + 1);
            strcpy(settings->dns_log_level, DEFAULT_DNS_LOG_LEVEL);
            settings->dns_log_file = malloc(strlen(DEFAULT_DNS_LOG_FILE) + 1);
            strcpy(settings->dns_log_file, DEFAULT_DNS_LOG_FILE);
        }
    }
}

static void parseIncludeSection(const cJSON *inc_array)
{
    const cJSON *path = NULL;

    cJSON_ArrayForEach(path, inc_array)
    {
        if (cJSON_IsString(path) && path->valuestring != NULL)
        {
            char *buf = malloc(strlen(path->valuestring) + 1);
            strcpy(buf, path->valuestring);
            vec_config_path_t_push(&settings->config_paths, buf);
        }
    }

    if (path == NULL)
    {
        fprintf(stderr, "Error: \"include\" array in core json is empty or invalid \n");
        exit(1);
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

    const cJSON *log_obj = cJSON_GetObjectItemCaseSensitive(json, "log");
    if (cJSON_IsObject(log_obj) && (log_obj->child != NULL))
    {
        parseLogSection(log_obj);
    }
    else
    {
        settings->log_path = malloc(strlen(DEFAULT_LOG_PATH) + 1);
        strcpy(settings->log_path, DEFAULT_LOG_PATH);

        settings->core_log_file = malloc(strlen(DEFAULT_CORE_LOG_FILE) + 1);
        strcpy(settings->core_log_file, DEFAULT_CORE_LOG_FILE);

        settings->core_log_level = malloc(strlen(DEFAULT_CORE_LOG_LEVEL) + 1);
        strcpy(settings->core_log_level, DEFAULT_CORE_LOG_LEVEL);

        settings->network_log_file = malloc(strlen(DEFAULT_NETWORK_LOG_FILE) + 1);
        strcpy(settings->network_log_file, DEFAULT_NETWORK_LOG_FILE);

        settings->network_log_level = malloc(strlen(DEFAULT_NETWORK_LOG_LEVEL) + 1);
        strcpy(settings->network_log_level, DEFAULT_NETWORK_LOG_LEVEL);

        settings->dns_log_file = malloc(strlen(DEFAULT_DNS_LOG_FILE) + 1);
        strcpy(settings->log_path, DEFAULT_DNS_LOG_FILE);

        settings->dns_log_level = malloc(strlen(DEFAULT_DNS_LOG_LEVEL) + 1);
        strcpy(settings->log_path, DEFAULT_DNS_LOG_LEVEL);
    }

    const cJSON *inc_array = cJSON_GetObjectItemCaseSensitive(json, "include");
    if (cJSON_IsArray(inc_array) && (inc_array->child != NULL))
    {
        parseIncludeSection(inc_array);
    }
    else
    {
        fprintf(stderr, "Error: \"include\" array in core json is empty or invalid \n");
        exit(1);
    }

    // TODO: DNS / API
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

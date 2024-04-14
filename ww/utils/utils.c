#include "basic_types.h"
#include "stringutils.h"
#include "jsonutils.h"
#include "fileutils.h"
#include "sockutils.h"
#include "userutils.h"
#include "hashutils.h"
#include "procutils.h"
#include <stdio.h>
#define NOMINMAX
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

char *readFile(const char *const path)
{
    FILE *f = fopen(path, "rb");

    if (!f)
        return NULL;

    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET); /* same as rewind(f); */

    char *string = malloc(fsize + 1);
    size_t count = fread(string, fsize, 1, f);
    if (count == 0)
    {
        free(string);
        return NULL;
    }
    fclose(f);

    string[fsize] = 0;
    return string;
}

bool writeFile(const char *const path, const char *data, size_t len)
{
    FILE *f = fopen(path, "wb");

    if (!f)
        return false;

    fseek(f, 0, SEEK_SET);

    if (fwrite(data, len, 1, f) != len)
    {
        fclose(f);
        return false;
    }
    fclose(f);
    return true;
}

char *concat(const char *s1, const char *s2)
{
    char *result = malloc(strlen(s1) + strlen(s2) + 1); // +1 for the null-terminator
    strcpy(result, s1);
    strcat(result, s2);
    return result;
}

bool getBoolFromJsonObject(bool *dest, const cJSON *json_obj, const char *key)
{

    assert(dest != NULL);
    const cJSON *jbool = cJSON_GetObjectItemCaseSensitive(json_obj, key);
    if (cJSON_IsBool(jbool))
    {
        *dest = cJSON_IsTrue(jbool);
        return true;
    }
    else
    {
        return false;
    }
}

bool getBoolFromJsonObjectOrDefault(bool *dest, const cJSON *json_obj, const char *key, bool def)
{
    assert(dest != NULL);
    const cJSON *jbool = cJSON_GetObjectItemCaseSensitive(json_obj, key);
    if (cJSON_IsBool(jbool))
    {
        *dest = cJSON_IsTrue(jbool);
        return true;
    }
    else
    {
        *dest = def;
        return false;
    }
}

bool getIntFromJsonObject(int *dest, const cJSON *json_obj, const char *key)
{
    assert(dest != NULL);
    const cJSON *jnumber = cJSON_GetObjectItemCaseSensitive(json_obj, key);
    if (cJSON_IsNumber(jnumber))
    {
        *dest = jnumber->valueint;
        return true;
    }
    else
    {
        return false;
    }
}

bool getIntFromJsonObjectOrDefault(int *dest, const cJSON *json_obj, const char *key, int def)
{
    assert(dest != NULL);
    const cJSON *jnumber = cJSON_GetObjectItemCaseSensitive(json_obj, key);
    if (cJSON_IsNumber(jnumber))
    {
        *dest = jnumber->valueint;
        return true;
    }
    else
    {
        *dest = def;
        return false;
    }
}

bool getStringFromJson(char **dest, const cJSON *json_str_node)
{
    assert(*dest == NULL);
    if (cJSON_IsString(json_str_node) && (json_str_node->valuestring != NULL))
    {

        *dest = malloc(strlen(json_str_node->valuestring) + 1);
        strcpy(*dest, json_str_node->valuestring);
        return true;
    }
    else
    {
        return false;
    }
}
bool getStringFromJsonObject(char **dest, const cJSON *json_obj, const char *key)
{

    assert(*dest == NULL);
    const cJSON *jstr = cJSON_GetObjectItemCaseSensitive(json_obj, key);
    if (cJSON_IsString(jstr) && (jstr->valuestring != NULL))
    {

        *dest = malloc(strlen(jstr->valuestring) + 1);
        strcpy(*dest, jstr->valuestring);
        return true;
    }
    else
    {
        return false;
    }
}

bool getStringFromJsonObjectOrDefault(char **dest, const cJSON *json_obj, const char *key, const char *def)
{
    assert(def != NULL);
    if (!getStringFromJsonObject(dest, json_obj, key))
    {
        *dest = malloc(strlen(def) + 1);
        strcpy(*dest, def);
        return false;
    }
    return true;
}

// memory behind these pointers are not being mutated, but i prefere using restrict
// when 2 arguments are same pointer types, if it dose not make the code invalid
extern bool socket_cmp_ipv4(sockaddr_u *restrict addr1, sockaddr_u *restrict addr2);
extern bool socket_cmp_ipv6(sockaddr_u *restrict addr1, sockaddr_u *restrict addr2);
bool socket_cmp_ip(sockaddr_u *restrict addr1, sockaddr_u *restrict addr2)
{

    if (addr1->sa.sa_family != addr2->sa.sa_family)
        return false;

    if (addr1->sa.sa_family == AF_INET)
    {
        return socket_cmp_ipv4(addr1, addr2);
    }
    else if (addr1->sa.sa_family == AF_INET6)
    {
        return socket_cmp_ipv6(addr1, addr2);
    }

    assert(!"unknown sa_family");

    return false;
}

void copySocketContextAddr(socket_context_t *dest, socket_context_t **source)
{
    dest->acmd = (*source)->acmd;
    dest->atype = (*source)->atype;

    switch (dest->atype)
    {
    case SAT_IPV4:
        dest->addr.sa.sa_family = AF_INET;
        dest->addr.sin.sin_addr = (*source)->addr.sin.sin_addr;

        break;

    case SAT_DOMAINNAME:
        dest->addr.sa.sa_family = AF_INET;
        if ((*source)->domain != NULL)
        {
            dest->domain = (*source)->domain;
            // (*source)->domain = NULL; // this copies the pointer and the caller is awair
        }

        break;

    case SAT_IPV6:
        dest->addr.sa.sa_family = AF_INET6;
        memcpy(&(dest->addr.sin6.sin6_addr), &((*source)->addr.sin6.sin6_addr), sizeof(struct in6_addr));

        break;
    }
}

enum socket_address_type getHostAddrType(char *host)
{
    if (is_ipv4(host))
        return SAT_IPV4;
    if (is_ipv6(host))
        return SAT_IPV6;
    return SAT_DOMAINNAME;
}

void copySocketContextPort(socket_context_t *dest, socket_context_t *source)
{

    switch (dest->atype)
    {
    case SAT_IPV4:
        dest->addr.sin.sin_port = source->addr.sin.sin_port;
        break;

    case SAT_DOMAINNAME:
        dest->addr.sin.sin_port = source->addr.sin.sin_port;
        break;

    case SAT_IPV6:
        dest->addr.sin6.sin6_port = source->addr.sin6.sin6_port;
        break;
    default:
        dest->addr.sin.sin_port = source->addr.sin.sin_port;
        break;
    }
}

struct user_s *parseUserFromJsonObject(const cJSON *user_json)
{
    if (!cJSON_IsObject(user_json) || user_json->child == NULL)
        return NULL;

    user_t *user = malloc(sizeof(user_t));
    memset(user, 0, sizeof(user_t));

    getStringFromJsonObjectOrDefault(&(user->name), user_json, "name", "EMPTY_NAME");
    getStringFromJsonObjectOrDefault(&(user->email), user_json, "email", "EMPTY_EMAIL");
    getStringFromJsonObjectOrDefault(&(user->notes), user_json, "notes", "EMTPY_NOTES");

    if (!getStringFromJsonObject(&(user->uid), user_json, "uid"))
    {
        free(user);
        return NULL;
    }
    user->hash_uid = calcHashLen(user->uid, strlen(user->uid));

    bool enable;
    if (!getBoolFromJsonObject(&(enable), user_json, "enable"))
    {
        free(user);
        return NULL;
    }
    user->enable = enable;
    // TODO
    return user;
}

dynamic_value_t parseDynamicStrValueFromJsonObject(const cJSON *json_obj, const char *key, size_t matchers, ...)
{

    dynamic_value_t result = {0};
    result.status = dvs_empty;

    if (!cJSON_IsObject(json_obj) || json_obj->child == NULL)
        return result;

    const cJSON *jstr = cJSON_GetObjectItemCaseSensitive(json_obj, key);
    if (cJSON_IsString(jstr) && (jstr->valuestring != NULL))
    {

        va_list argp;
        va_start(argp, matchers);
        for (size_t mi = dvs_constant + 1; mi < matchers + dvs_constant + 1; mi++)
        {
            char *matcher = va_arg(argp, char *);
            if (strcmp(matcher, jstr->valuestring) == 0)
            {
                va_end(argp);
                result.status = mi;
                return result;
            }
        }

        va_end(argp);
        result.status = dvs_constant;
        result.value_ptr = malloc(strlen(jstr->valuestring) + 1);
        strcpy(result.value_ptr, jstr->valuestring);
    }
    return result;
}
dynamic_value_t parseDynamicNumericValueFromJsonObject(const cJSON *json_obj, const char *key, size_t matchers, ...)
{

    dynamic_value_t result = {0};
    result.status = dvs_empty;

    if (!cJSON_IsObject(json_obj) || json_obj->child == NULL)
        return result;

    const cJSON *jstr = cJSON_GetObjectItemCaseSensitive(json_obj, key);
    if (cJSON_IsString(jstr) && (jstr->valuestring != NULL))
    {

        va_list argp;
        va_start(argp, matchers);
        for (size_t mi = dvs_constant + 1; mi < matchers + dvs_constant + 1; mi++)
        {
            char *matcher = va_arg(argp, char *);
            if (strcmp(matcher, jstr->valuestring) == 0)
            {
                va_end(argp);
                result.status = mi;
                return result;
            }
        }

        va_end(argp);
        result.status = dvs_empty;
    }
    else if (cJSON_IsNumber(jstr))
    {
        result.status = dvs_constant;
        result.value = (size_t)jstr->valueint;
    }
    return result;
}

// blocking io
cmdresult_t execCmd(const char *str)
{
    FILE *fp;
    cmdresult_t result = (cmdresult_t){{0}, -1};
    char *buf = &(result.output[0]);
    int i = 0;
    /* Open the command for reading. */
    fp = popen(str, "r");
    if (fp == NULL)
    {
        printf("Failed to run command \"%s\"\n", str);
        return (cmdresult_t){{0}, -1};
    }

    int read = fscanf(fp, "%2047s", buf);
    result.exit_code = pclose(fp);

    return result;
    /* close */
    // return 0 == pclose(fp);
}
bool check_installed(const char *app)
{
    char b[300];
    sprintf(b, "command -v %s", app);
    cmdresult_t result = execCmd(b);
    return (result.exit_code == 0 && strlen(result.output) > 0);
}

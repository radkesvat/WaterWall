#include "basic_types.h"
#include "stringutils.h"
#include "jsonutils.h"
#include "fileutils.h"
#include "sockutils.h"
#include "userutils.h"
#include "hashutils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char *readFile(const char *const path)
{
    FILE *f = fopen(path, "rb");

    if (!f)
        return NULL;

    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET); /* same as rewind(f); */

    char *string = malloc(fsize + 1);
    fread(string, fsize, 1, f);
    fclose(f);

    string[fsize] = 0;
    return string;
}

bool writeFile(const char *const path, char *data, size_t len)
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

extern bool socket_cmp_ipv4(sockaddr_u *addr1, sockaddr_u *addr2);
extern bool socket_cmp_ipv6(sockaddr_u *addr1, sockaddr_u *addr2);
bool socket_cmp_ip(sockaddr_u *addr1, sockaddr_u *addr2)
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

bool parseUserFromJsonObject(struct user_s *dest, const cJSON *user_json)
{
    if (!cJSON_IsObject(user_json) || user_json->child == NULL)
        return NULL;

    user_t *user = malloc(sizeof(user_t));
    memset(user, 0, sizeof(user_t));

    getStringFromJsonObjectOrDefault(&(user->name), user_json, "name", "EMPTY_NAME");
    getStringFromJsonObjectOrDefault(&(user->email), user_json, "email", "EMPTY_EMAIL");
    getStringFromJsonObjectOrDefault(&(user->name), user_json, "notes", "EMTPY_NOTES");

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
    //TODO
    return user;
}

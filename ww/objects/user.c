#include "objects/user.h"

struct user_s *parseUserFromJsonObject(const cJSON *user_json)
{
    if (! cJSON_IsObject(user_json) || user_json->child == NULL)
    {
        return NULL;
    }
    user_t *user = memoryAllocate(sizeof(user_t));
    memorySet(user, 0, sizeof(user_t));

    getStringFromJsonObjectOrDefault(&(user->name), user_json, "name", "EMPTY_NAME");
    getStringFromJsonObjectOrDefault(&(user->email), user_json, "email", "EMPTY_EMAIL");
    getStringFromJsonObjectOrDefault(&(user->notes), user_json, "notes", "EMTPY_NOTES");

    if (! getStringFromJsonObject(&(user->uid), user_json, "uid"))
    {
        memoryFree(user);
        return NULL;
    }
    user->hash_uid = calcHashBytes(user->uid, strlen(user->uid));

    bool enable;
    if (! getBoolFromJsonObject(&(enable), user_json, "enable"))
    {
        memoryFree(user);
        return NULL;
    }
    user->enable = enable;
    // TODO (parse user) parse more fields from user like limits/dates/etc..
    return user;
}


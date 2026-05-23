#pragma once

/*
 * User model types and JSON parsing entrypoint.
 */

#include "wlibc.h"

#include "uuid.h"
#include "cJSON.h"


typedef struct ud_s
{
    uint64_t u;
    uint64_t d;
} ud_t;

typedef union {
    ud_t     max;
    uint64_t max_total;
} traffic_limit_t;

typedef struct user_limit_s
{
    traffic_limit_t traffic;
    ud_t            bandwidth;
    uint64_t        ip;
    uint64_t        devices;
    uint64_t        cons_in;
    uint64_t        cons_out;
} user_limit_t;

typedef struct user_time_info_s
{
    datetime_t create_date;
    datetime_t first_usage_date;
    datetime_t expire_date;
    bool       since_first_use;
} user_time_info_t;

typedef struct user_stat_s
{

    uint64_t ips;
    uint64_t devices;
    uint64_t cons_in;
    uint64_t cons_out;
    ud_t     speed;
    ud_t     traffic;
} user_stat_t;

typedef struct user_s
{
    struct cJSON *json;
    //-----------------
    wrwlock_t        lock; // protects all fields below, except stats which is updated atomically without locking
    char            *name;
    char            *email;
    char            *notes;
    char            *uid; // unique id
    int              gid; // group id
    hash_t           hash_uid;
    bool             enable;
    user_limit_t     limit;
    user_time_info_t timeinfo;
    //-----------------
    user_stat_t stats;

} user_t;

struct user_s;

/**
 * @brief Parse a user object from JSON.
 *
 * @param user_json JSON object containing user fields.
 * @return struct user_s* Allocated user object, or NULL on parse failure.
 */
struct user_s *parseUserFromJsonObject(const cJSON *user_json);

#pragma once
#include "basic_types.h"
#include "wtime.h"
#include <stdatomic.h>

typedef struct ud_s
{
    atomic_ullong u;
    atomic_ullong d;
} ud_t;

typedef union {
    ud_t          max;
    atomic_ullong max_total;
} traffic_limit_t;

typedef struct user_limit_s
{
    traffic_limit_t traffic;
    ud_t            bandwidth;
    atomic_ullong   ip;
    atomic_ullong   devices;
    atomic_ullong   cons_in;
    atomic_ullong   cons_out;
} user_limit_t;

typedef struct user_time_info_s
{
    datetime_t  create_date;
    datetime_t  first_usage_date;
    datetime_t  expire_date;
    atomic_bool since_first_use;
} user_time_info_t;

typedef struct user_stat_s
{

    atomic_ullong ips;
    atomic_ullong devices;
    atomic_ullong cons_in;
    atomic_ullong cons_out;
    ud_t          speed;
    ud_t          traffic;
} user_stat_t;

typedef struct user_s
{
    struct cJSON   *json;
    //-----------------
    char            *name;
    char            *email;
    char            *notes;
    char            *uid; // unique id
    int              gid; // group id
    hash_t           hash_uid;
    atomic_bool      enable;
    user_limit_t     limit;
    user_time_info_t timeinfo;
    user_stat_t      stats;

} user_t;

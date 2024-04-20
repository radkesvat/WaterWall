#pragma once

#include "hv/hatomic.h"
#include "hv/hmutex.h"
#include "hv/hplatform.h"
#include "hv/hsocket.h"
#include "hv/htime.h"

typedef uint64_t hash_t;

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
    ud_t          speed;
    ud_t          traffic;
    atomic_ullong ips;
    atomic_ullong devices;
    atomic_ullong cons_in;
    atomic_ullong cons_out;

} user_stat_t;

typedef struct user_s
{
    struct cJSON *json;
    hmutex_t *    fsync_lock;
    //-----------------
    char * name;
    char * email;
    char * notes;
    char * uid; // unique id
    int    gid; // group id
    hash_t hash_uid;

    atomic_bool      enable;
    user_limit_t     limit;
    user_time_info_t timeinfo;
    user_stat_t      stats;

} user_t;

typedef struct api_result_s
{
    char * result;
    size_t result_len;
} api_result_t;

enum domain_strategy
{
    kDsInvalid,
    kDsPreferIpV4,
    kDsPreferIpV6,
    kDsOnlyIpV4,
    kDsOnlyIpV6

};
enum dynamic_value_status
{
    kDvsEmpty = 0x0,
    kDvsConstant,
};
typedef struct dynamic_value_s
{
    enum dynamic_value_status status;
    size_t                    value;
    void *                    value_ptr;
} dynamic_value_t;

enum socket_address_type
{
    kSatIPV4       = 0X1,
    kSatDomainName = 0X3,
    kSatIPV6       = 0X4,
};

enum socket_address_protocol
{
    kSapTcp = 0X1,
    kSapUdp = 0X3,
};

// all data we need to connect to somewhere
typedef struct socket_context_s
{
    enum socket_address_protocol aproto;
    enum socket_address_type     atype;
    char *                       domain;
    unsigned int                 domain_len;
    bool                         resolved;
    sockaddr_u                   addr;

} socket_context_t;

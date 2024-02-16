#pragma once

#include "hv/hplatform.h"
#include "hv/hsocket.h"
#include "hv/htime.h"

// typedef enum 
// {
//     tcp,
//     udp,
//     socks,
//     vmess,
//     vless,
//     trojan,
//     shadowsockes,
//     dokodemo_door,
//     http,
//     wireguard,
//     usw, // und so weiter :)
// } protocol_type;

typedef uint64_t hash_t;

typedef struct ud_s
{
    uint64_t u;
    uint64_t d;
} ud_t;

typedef union
{
    ud_t max;
    uint64_t max_total;
} traffic_limit_t;

typedef struct user_limit_s
{
    traffic_limit_t traffic;
    ud_t bandwidth;
    uint64_t ip;
    uint64_t cons_in;
    uint64_t cons_out;
} user_limit_t;

typedef struct user_time_info_s
{
    datetime_t create_date;
    datetime_t first_usage_date;
    datetime_t expire_date;
    bool since_first_use;
} user_time_info_t;

typedef struct user_s
{
    char *name;
    char *email;
    char *notes;
    char uid[40]; // unique id
    uint64_t gid; // group id
    hash_t hash;  // represents uid

    bool enable;
    user_limit_t limit;
    user_time_info_t timeinfo;
} user_t;

// typedef struct proxy_protocol_s
// {
//     char *name;
//     protocol_type type;
//     void *settings;
// } proxy_protocol_t;

// typedef struct bound_s
// {
//     char *name;
//     char *tag;
//     hash_t hash; // represents tag
//     sockaddr_u addr;
//     proxy_protocol_t protocol;
//     bool mux;
// } bound_t;


// typedef struct 
// {
//     bound_t* buf;
//     size_t len;
// } bounds;



typedef enum
{
    IPv4Addr = 1,
    FqdnAddr = 3,
    IPv6Addr = 4,
} addr_type_e;

// all data we need to connect to somewhere
typedef struct socket_context_s
{
    uint8_t protocol; //IPPROTO_X
    char *domain;
    bool resolved;
    addr_type_e addr_type;
    sockaddr_u addr;
} socket_context_t;

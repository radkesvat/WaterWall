#pragma once

#include "hv/hplatform.h"
#include "hv/hsocket.h"
#include "hv/htime.h"
#include "hv/hatomic.h"

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
    _Atomic uint64_t u;
    _Atomic uint64_t d;
} ud_t;

typedef union
{
    ud_t max;
    _Atomic uint64_t max_total;
} traffic_limit_t;

typedef struct user_limit_s
{
    traffic_limit_t traffic;
    ud_t bandwidth;
    _Atomic uint64_t ip;
    _Atomic uint64_t devices;
    _Atomic uint64_t cons_in;
    _Atomic uint64_t cons_out;
} user_limit_t;

typedef struct user_time_info_s
{
    datetime_t create_date;
    datetime_t first_usage_date;
    datetime_t expire_date;
    _Atomic bool since_first_use;
} user_time_info_t;

typedef struct user_stat_s
{
    ud_t speed;
    ud_t traffic;
    _Atomic uint64_t ips;
    _Atomic uint64_t devices;
    _Atomic uint64_t cons_in;
    _Atomic uint64_t cons_out;

} user_stat_t;

typedef struct user_s
{
    struct cJSON *json;
    //-----------------
    char *name;
    char *email;
    char *notes;
    char *uid;   // unique id
    int gid;     // group id
    hash_t hash; // represents uid

    _Atomic bool enable;
    user_limit_t limit;
    user_time_info_t timeinfo;
    user_stat_t stats;

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

// all data we need to connect to somewhere
typedef struct socket_context_s
{
    uint8_t protocol; // IPPROTO_X
    char *domain;
    bool resolved;
    sockaddr_u addr;
} socket_context_t;

typedef struct node_instance_context_s
{
    struct cJSON *node_json;
    struct cJSON *node_settings_json; // node_json -> settings
    uint32_t threads;
    struct hloop_s **loops;                            // thread local
    struct buffer_dispatcher_storage_s **buffer_disps; // thread local
    struct socket_dispatcher_state_s *socket_disp_state;
    struct node_dispatcher_state_s *node_disp_state;
    struct node_t *self_node_handle;
    struct config_file_s *self_file_handle;
} node_instance_context_t;

typedef struct node_s
{
    char *name;
    hash_t hash_name;
    char *type_name;
    hash_t hash_type_name;
    char *next_name;
    hash_t hash_next_naem;
    size_t refrenced;
    size_t version;
    //------------ evaluated:
    unsigned listener : 1;
    unsigned sender : 1;
    struct tunnel_s *(*creation_proc)(node_instance_context_t *instance_info);
    void (*api_proc)(struct tunnel_s *instance, char *msg);
    struct tunnel_s *(*destroy_proc)(struct tunnel_s *instance);
    node_instance_context_t instance_context;
    struct tunnel_s *instance;

} node_t;

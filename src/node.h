#pragma once

#include "common_types.h"
#include "tunnel.h"
#include "cJSON.h"
#include "hv/hv.h"

typedef struct node_instance_context_s
{
    cJSON *node_settings_json;

    hloop_t **loops;                            // thread local
    buffer_dispatcher_storage_t **buffer_disps; // thread local
    uint32_t threads;
    struct socket_dispatcher_state_s *socket_disp_state;
    struct node_dispatcher_state_s *node_disp_state;
    struct node_t *self_node_handle;
    struct nodes_file_s *self_file_handle;
} node_instance_context_t;

typedef struct node_s
{
    char *name;
    hash_t ident;
    char *type_name;
    hash_t type_ident;
    char *next_name;
    hash_t next_ident;
    cJSON *node_json;
    cJSON *node_settings_json;
    size_t refrenced;
    size_t version;
    //------------ evaluated:
    unsigned listener : 1;
    unsigned sender : 1;
    tunnel_t *(*creation_proc)(node_instance_context_t *instance_info);
    void (*api_proc)(tunnel_t *instance, char *msg);
    tunnel_t *(*destroy_proc)(tunnel_t *instance);

    tunnel_t *instance;

} node_t;

#define i_type map_node_t
#define i_key hash_t
#define i_val node_t *

#include "stc/hmap.h"

// a file containing array of nodes also describes path(up)
typedef struct nodes_file_s
{
    char *name;
    char *author;
    size_t minimum_version;
    bool encrypted;
    cJSON *nodes;

    //------------ evaluated:
    map_node_t nmap;
} nodes_file_t;

#define i_type vec_nodes_file_t
#define i_key nodes_file_t
#include "stc/vec.h"
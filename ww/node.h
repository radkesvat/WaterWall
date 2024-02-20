#pragma once

#include "basic_types.h"

typedef struct node_instance_context_s
{
    struct cJSON *node_json;
    struct cJSON *node_settings_json; // node_json -> settings

    // uint32_t threads;
    // struct hloop_s **loops;
    // struct buffer_pool_s **buffer_disps;
    // struct socket_manager_s *socket_disp_state;
    // struct node_manager_s *node_disp_state;

    struct node_t *self_node_handle;
    struct config_file_s *self_file_handle;

} node_instance_context_t;

typedef struct node_s
{
    char *name;
    hash_t hash_name;
    char *type;
    hash_t hash_type;
    char *next;
    hash_t hash_next;
    size_t refrenced;
    size_t version;
    //------------ evaluated:
    unsigned listener : 1;
    unsigned sender : 1;
    struct tunnel_lib_s *lib;
    node_instance_context_t instance_context;
    struct tunnel_s *instance;

} node_t;

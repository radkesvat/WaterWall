#pragma once

#include "basic_types.h"

typedef struct node_instance_context_s
{
    struct cJSON *node_json;
    struct cJSON *node_settings_json; // node_json -> settings
    struct node_s *self_node_handle;
    struct config_file_s *self_file_handle;
    size_t chain_index;
} node_instance_context_t;

typedef struct tunnel_metadata_s
{
    int32_t version;
    int32_t flags;
} tunnel_metadata_t;

#define TFLAG_ROUTE_STARTER (1 << 0)

typedef struct node_s
{
    char *name;
    hash_t hash_name;
    char *type;
    hash_t hash_type;
    char *next;
    hash_t hash_next;
    size_t version;
    //------------ evaluated:
    size_t refrenced;
    bool route_starter;

    tunnel_metadata_t metadata;
    struct tunnel_lib_s *lib;
    node_instance_context_t instance_context;
    struct tunnel_s *instance;

} node_t;


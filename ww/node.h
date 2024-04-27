#pragma once

#include "basic_types.h"

typedef struct node_instance_context_s
{
    struct cJSON         *node_json;
    struct cJSON         *node_settings_json; // node_json -> settings
    struct config_file_s *node_file_handle;
    struct node_s        *node;
    size_t                chain_index;
} node_instance_context_t;

enum node_flags
{
    kNodeFlagNone = (1 << 0),
    // this node can be a chain head (begin of the chain)
    kNodeFlagChainHead = (1 << 1)
};
typedef struct tunnel_metadata_s
{
    int32_t         version;
    enum node_flags flags;
} tunnel_metadata_t;

typedef struct node_s
{
    char    *name;
    hash_t   hash_name;
    char    *type;
    hash_t   hash_type;
    char    *next;
    hash_t   hash_next;
    uint32_t version;
    //------------ evaluated:
    uint32_t refrenced;
    bool     route_starter;

    tunnel_metadata_t       metadata;
    struct tunnel_lib_s    *lib;
    node_instance_context_t instance_context;
    struct tunnel_s        *instance;

} node_t;

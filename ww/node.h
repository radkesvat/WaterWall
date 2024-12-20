#pragma once

#include "basic_types.h"
#include <stddef.h>
#include <stdint.h>

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
    uint16_t        required_padding_left;
    uint16_t        required_padding_right;
} tunnel_metadata_t;

typedef struct node_s
{
    char    *name;
    char    *type;
    char    *next;
    hash_t   hash_name;
    hash_t   hash_type;
    hash_t   hash_next;
    uint32_t version;

    // evaluated:

    struct tunnel_lib_s *lib;

    struct cJSON                 *node_json;
    struct cJSON                 *node_settings_json; // node_json -> settings
    struct node_manager_config_s *node_manager_config;

    struct tunnel_s  *instance;
    tunnel_metadata_t metadata;
    uint32_t          refrenced;
    bool flag_route_starter;

} node_t;

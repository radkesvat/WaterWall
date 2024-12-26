#pragma once

#include "tunnel.h"
#include <stddef.h>
#include <stdint.h>

typedef struct api_result_s
{
    char  *result;
    size_t result_len;
} api_result_t;

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

typedef struct node_s node_t;

struct node_s
{
    char    *name;
    char    *type;
    char    *next;
    hash_t   hash_name;
    hash_t   hash_type;
    hash_t   hash_next;
    uint32_t version;

    tunnel_t *(*createHandle)(node_t *instance_info);
    void (*destroyHandle)(node_t node, tunnel_t *instance);
    api_result_t (*apiHandle)(tunnel_t *instance, const char *msg);
    tunnel_metadata_t (*getMetadataHandle)(void);

    struct cJSON                 *node_json;
    struct cJSON                 *node_settings_json; // node_json -> settings
    struct node_manager_config_s *node_manager_config;

    tunnel_t         *instance;
    tunnel_metadata_t metadata;
    uint32_t          refrenced;
};

node_t loadNodeLibrary(const char *name);
node_t loadNodeLibraryByHash(hash_t hname);
void   registerStaticNodeLib(node_t lib);

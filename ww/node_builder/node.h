#pragma once

#include "shiftbuffer.h"
#include "tunnel.h"
#include "wlibc.h"

enum api_result_e
{
    kApiResultOk    = 0,
    kApiResultError = 1
};

typedef struct api_result_s
{
    enum api_result_e result_code;
    sbuf_t           *buffer;

} api_result_t;

enum node_flags
{
    // no flags (default)
    kNodeFlagNone = (1 << 0),
    // this node can be a chain head (begin of the chain)
    kNodeFlagChainHead = (1 << 1),
    // this node can be a chain end (end of the chain)
    kNodeFlagChainEnd = (1 << 2),
    // this node dose not need to be in a chain to work (maybe a database node for user auth?)
    kNodeFlagNoChain = (1 << 3)
};

enum node_layer_group
{
    kNodeLayerNone     = (1 << 0),
    kNodeLayerAnything = (1 << 1),
    kNodeLayer3        = (1 << 2),
    kNodeLayer4        = (1 << 3)
};

typedef struct node_s node_t;

typedef tunnel_t *(*TunnelCreateHandle)(node_t *node);

struct node_s
{
    char           *name;
    char           *type;
    char           *next;
    hash_t          hash_name;
    hash_t          hash_type;
    hash_t          hash_next;
    uint32_t        version;
    enum node_flags flags;
    uint16_t        required_padding_left;

    TunnelCreateHandle  createHandle;


    struct cJSON                 *node_json;
    struct cJSON                 *node_settings_json; // node_json -> settings
    struct node_manager_config_s *node_manager_config;

    enum node_layer_group layer_group;
    enum node_layer_group layer_group_next_node;
    enum node_layer_group layer_group_prev_node;
    bool                  can_have_next;
    bool                  can_have_prev;
    bool                  is_adapter;

    tunnel_t *instance;
};

node_t nodelibraryLoadByTypeName(const char *name);
node_t nodelibraryLoadByTypeHash(hash_t htype);

void nodelibraryRegister(node_t lib);
bool nodeHasFlagChainHead(node_t *node);

void nodelibraryCleanup(void);


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
    kNodeFlagChainHead = (1 << 1)
};

typedef struct node_s node_t;

typedef tunnel_t *(*TunnelCreateHandle)(node_t *node);
typedef void (*TunnelDestroyHandle)(tunnel_t *instance);
typedef api_result_t (*TunnelApiHandle)(tunnel_t *instance, sbuf_t *message);

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
    TunnelDestroyHandle destroyHandle;
    TunnelApiHandle     apiHandle;

    struct cJSON                 *node_json;
    struct cJSON                 *node_settings_json; // node_json -> settings
    struct node_manager_config_s *node_manager_config;

    tunnel_t *instance;
};

node_t nodelibraryLoadByTypeName(const char *name);
node_t nodelibraryLoadByTypeHash(hash_t htype);

void nodelibraryRegister(node_t lib);
bool nodeHasFlagChainHead(node_t *node);

#pragma once

/*
 * Core node definition shared by node loading, chaining, and tunnel creation.
 */

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
    kNodeFlagNoChain = (1 << 3),
    // this node should only have one instance in the whole chain config (singleton pattern)
    kNodeFlagSingleton = (1 << 4)

};

enum node_layer_group
{
    kNodeLayerNone     = (1 << 0),
    kNodeLayer3        = (1 << 2),
    kNodeLayer4        = (1 << 3),
    kNodeLayerAnything = kNodeLayer3 | kNodeLayer4

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

    TunnelCreateHandle createHandle;

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

/**
 * @brief Check if node is implemented as an adapter endpoint.
 *
 * @param node Node definition.
 * @return true Node is an adapter.
 * @return false Node is not an adapter.
 */
static inline bool nodeIsAdapter(node_t *node)
{
    return node->is_adapter;
}

/**
 * @brief Check whether node has no configured next node.
 *
 * @param node Node definition.
 * @return true Node is terminal in chain config.
 * @return false Node points to a next node.
 */
static inline bool nodeIsLastInChain(node_t *node)
{
    return node->next == NULL;
}

/**
 * @brief Check whether node has a configured next node.
 *
 * @param node Node definition.
 * @return true Node has next node.
 * @return false Node has no next node.
 */
static inline bool nodeHasNext(node_t *node)
{
    return node->next != NULL;
}

typedef enum node_child_link_mode_e
{
    kNodeChildLinkNone = 0,
    kNodeChildLinkOwnerNext,
    kNodeChildLinkOwnerSelf
} node_child_link_mode_t;

static inline char *nodeMakeChildName(const node_t *node, const char *suffix)
{
    assert(node != NULL);
    assert(suffix != NULL);

    const char *base = node->name != NULL ? node->name : node->type;
    if (base == NULL)
    {
        base = "Node";
    }

    return stringConcat(base, suffix);
}

static inline bool nodeConfigureChild(node_t *child, node_t template_node, const node_t *owner, const char *suffix,
                                      node_child_link_mode_t link_mode, struct cJSON *settings)
{
    assert(child != NULL);
    assert(owner != NULL);

    *child = template_node;

    child->name = nodeMakeChildName(owner, suffix);
    if (child->name == NULL)
    {
        return false;
    }

    child->hash_name = calcHashBytes(child->name, stringLength(child->name));

    switch (link_mode)
    {
    case kNodeChildLinkOwnerNext:
        child->next      = owner->next != NULL ? stringDuplicate(owner->next) : NULL;
        child->hash_next = owner->hash_next;
        break;
    case kNodeChildLinkOwnerSelf:
        child->next      = owner->name != NULL ? stringDuplicate(owner->name) : NULL;
        child->hash_next = owner->hash_name;
        break;
    case kNodeChildLinkNone:
    default:
        child->next      = NULL;
        child->hash_next = 0;
        break;
    }

    if ((link_mode == kNodeChildLinkOwnerNext && owner->next != NULL && child->next == NULL) ||
        (link_mode == kNodeChildLinkOwnerSelf && owner->name != NULL && child->next == NULL))
    {
        memoryFree(child->name);
        child->name = NULL;
        return false;
    }

    child->version             = owner->version;
    child->node_json           = owner->node_json;
    child->node_settings_json  = settings;
    child->node_manager_config = owner->node_manager_config;
    child->instance            = NULL;
    return true;
}

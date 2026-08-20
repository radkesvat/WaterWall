#pragma once

/*
 * Core node definition shared by node loading, chaining, and tunnel creation.
 */

#include "global_state.h"
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

/*
 * ---------------------------------------------------------------------------
 * Tunnel-API dispatch contract
 * ---------------------------------------------------------------------------
 *
 * An ordinary `<node>TunnelApi()` entry point runs on an event worker. The
 * caller hands over a request buffer taken from *that worker's* pool and the
 * callee owns it: it either recycles it into the same pool or destroys it.
 *
 * A node whose API needs a different rule (TlsClient returns a generated buffer
 * and must keep the originating pool through every error path) documents that
 * on its own entry point. Everything else uses the helpers below, so no node
 * repeats `bufferpoolReuseBuffer(getWorkerBufferPool(getWID()), message)` and
 * silently borrows worker 0's pool when the current thread has no worker slot.
 */

/*!
 * @brief Releases a tunnel-API input buffer according to the contract above.
 *
 * @param message API input buffer; may be NULL.
 * @return true when the buffer went back to its owning worker pool, false when
 *         the caller is not an ordinary event worker and it was destroyed.
 */
static inline bool tunnelapiReleaseMessage(sbuf_t *message)
{
    if (UNLIKELY(! currentThreadIsEventWorker()))
    {
        /*
         * An unregistered thread or the lwIP pseudo-worker owns no worker-local
         * pool, and the buffer's real owner is not knowable from here, so free
         * it rather than pushing it into a pool this thread does not own.
         */
        if (message != NULL)
        {
            sbufDestroy(message);
        }
        return false;
    }

    if (message != NULL)
    {
        bufferpoolReuseBuffer(getCurrentEventWorkerBufferPool(), message);
    }
    return true;
}

/*!
 * @brief Consumes an API message a node does not act on, reporting success.
 *
 * @param message API input buffer; may be NULL.
 * @return kApiResultOk, or kApiResultError when the caller was not an event worker.
 */
static inline api_result_t tunnelapiRecycleMessage(sbuf_t *message)
{
    if (UNLIKELY(! tunnelapiReleaseMessage(message)))
    {
        return (api_result_t) {.result_code = kApiResultError};
    }
    return (api_result_t) {.result_code = kApiResultOk};
}

/*!
 * @brief Consumes an API message for a node that exposes no API, reporting failure.
 *
 * @param message API input buffer; may be NULL.
 * @return kApiResultError.
 */
static inline api_result_t tunnelapiUnsupportedMessage(sbuf_t *message)
{
    discard tunnelapiReleaseMessage(message);
    return (api_result_t) {.result_code = kApiResultError};
}

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
    kNodeLayerNone         = (1 << 0),
    kNodeLayer3            = (1 << 2),
    kNodeLayer4            = (1 << 3),
    kNodeLayerAnything     = kNodeLayer3 | kNodeLayer4,
    kNodeLayerSameAsNext   = (1 << 4),
    kNodeLayerSameAsPrev   = (1 << 5),
    kNodeLayerOppositeNext = (1 << 6), // must be ORed with a base layer (3, 4, or Anything) to constrain this side and require opposite layer on next side
    kNodeLayerOppositePrev = (1 << 7)  // must be ORed with a base layer (3, 4, or Anything) to constrain this side and require opposite layer on prev side
};

static inline const char *nodeLayerGroupToString(enum node_layer_group layer)
{
    switch ((int)layer)
    {
    case kNodeLayerNone:
        return "kNodeLayerNone";
    case kNodeLayer3:
        return "kNodeLayer3";
    case kNodeLayer4:
        return "kNodeLayer4";
    case kNodeLayerAnything:
        return "kNodeLayerAnything";
    case kNodeLayerSameAsNext:
        return "kNodeLayerSameAsNext";
    case kNodeLayerSameAsPrev:
        return "kNodeLayerSameAsPrev";
    case kNodeLayer3 | kNodeLayerOppositePrev:
        return "kNodeLayer3|kNodeLayerOppositePrev";
    case kNodeLayer4 | kNodeLayerOppositePrev:
        return "kNodeLayer4|kNodeLayerOppositePrev";
    case kNodeLayerAnything | kNodeLayerOppositePrev:
        return "kNodeLayerAnything|kNodeLayerOppositePrev";
    case kNodeLayer3 | kNodeLayerOppositeNext:
        return "kNodeLayer3|kNodeLayerOppositeNext";
    case kNodeLayer4 | kNodeLayerOppositeNext:
        return "kNodeLayer4|kNodeLayerOppositeNext";
    case kNodeLayerAnything | kNodeLayerOppositeNext:
        return "kNodeLayerAnything|kNodeLayerOppositeNext";
    case kNodeLayerOppositeNext:
        return "kNodeLayerOppositeNext";
    case kNodeLayerOppositePrev:
        return "kNodeLayerOppositePrev";
    default:
        break;
    }

    if ((layer & kNodeLayerAnything) == kNodeLayerAnything)
    {
        return "kNodeLayerAnything";
    }
    if (layer & kNodeLayer3)
    {
        return "kNodeLayer3";
    }
    if (layer & kNodeLayer4)
    {
        return "kNodeLayer4";
    }
    if (layer & kNodeLayerOppositeNext)
    {
        return "kNodeLayerOppositeNext";
    }
    if (layer & kNodeLayerOppositePrev)
    {
        return "kNodeLayerOppositePrev";
    }
    if (layer & kNodeLayerSameAsNext)
    {
        return "kNodeLayerSameAsNext";
    }
    if (layer & kNodeLayerSameAsPrev)
    {
        return "kNodeLayerSameAsPrev";
    }
    return "unknown";
}

typedef struct node_s node_t;

typedef tunnel_t *(*TunnelCreateHandle)(node_t *node);

/*
 * node_t is part of the external-node ABI. Dynamically loaded node libraries
 * receive this structure from the core and may read its public metadata. Do not
 * change its layout without an explicit ABI compatibility plan.
 */
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

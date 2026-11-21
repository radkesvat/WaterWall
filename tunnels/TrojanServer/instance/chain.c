#include "internal.h"

#include "loggers/network_logger.h"

static hash_t trojanserverUserControllerTypeHash(void)
{
    const char *type_name = "UserController";
    return calcHashBytes(type_name, stringLength(type_name));
}

static void trojanserverBindFallback(tunnel_t *t, tunnel_chain_t *chain)
{
    trojanserver_tstate_t *ts = tunnelGetState(t);

    if (ts->fallback_node == NULL)
    {
        return;
    }

    tunnel_t *target = ts->fallback_node->instance;
    if (target == NULL)
    {
        LOGF("TrojanServer: fallback tunnel \"%s\" is not available", ts->fallback_node->name);
        startupFailureRecord(1);
        return;
    }

    if (target == t || target == ts->user_controller_tunnel)
    {
        LOGF("TrojanServer: fallback target must be different from TrojanServer and its internal UserController");
        startupFailureRecord(1);
        return;
    }

    if (target->chain == chain &&
        (target == t->next || target->prev == t ||
         (ts->user_controller_tunnel == NULL && target->node->hash_name == t->node->hash_next)))
    {
        ts->fallback_tunnel = tunnelGetBranchEntry(t, target);
        if (ts->fallback_tunnel != NULL)
            return;
    }

    if (target->prev != NULL && target->prev != t)
    {
        LOGF("TrojanServer: fallback target node \"%s\" is already bound to previous node \"%s\"",
             target->node->name,
             target->prev->node->name);
        startupFailureRecord(1);
        return;
    }

    if (target->chain == chain)
    {
        LOGF("TrojanServer: fallback target node \"%s\" is already in the TrojanServer chain", target->node->name);
        startupFailureRecord(1);
        return;
    }

    if (target->prev == NULL)
    {
        tunnelBindDown(t, target);
    }

    if (target->chain != NULL)
    {
        tunnelchainCombine(chain, target->chain);
    }
    else
    {
        target->onChain(target, chain);
    }

    if (startupFailurePending())
        return;

    // The fallback target may insert internal tunnels in front of itself while
    // chaining (e.g. a connector's domain setup + DomainResolver); call the branch
    // entry bound directly below us, not the raw instance.
    ts->fallback_tunnel = tunnelGetBranchEntry(t, target);
    if (ts->fallback_tunnel == NULL)
    {
        LOGF("TrojanServer: fallback target node \"%s\" is not reachable from TrojanServer", target->node->name);
        startupFailureRecord(1);
        return;
    }
}

static void trojanserverBindFallbackTarget(tunnel_t *t, tunnel_chain_t *chain)
{
    if (startupFailurePending())
        return;
    trojanserverBindFallback(t, chain);
    trojanserver_tstate_t *ts = tunnelGetState(t);
    if (! startupFailurePending() && ts->fallback_tunnel != NULL && ts->fallback_tunnel != t->next)
        discard tunnelchainRegisterLayerRelation(tunnelGetChain(t),
                                                 t,
                                                 kTunnelLayerSidePrev,
                                                 ts->fallback_tunnel,
                                                 kTunnelLayerSidePrev,
                                                 kTunnelLayerRelationSame);
}

void trojanserverTunnelOnChain(tunnel_t *t, tunnel_chain_t *chain)
{
    trojanserver_tstate_t *ts   = tunnelGetState(t);
    node_t                *node = tunnelGetNode(t);

    tunnel_t *controller = ts->user_controller_tunnel;
    if (controller == NULL)
    {
        tunnelDefaultOnChain(t, chain);
        chain = tunnelGetChain(t);
        trojanserverBindFallbackTarget(t, chain);
        return;
    }

    if (node->hash_next == 0)
    {
        LOGF("TrojanServer: a next node is required");
        startupFailureRecord(1);
        return;
    }

    node_t *next_node = nodemanagerGetConfigNodeByHash(node->node_manager_config, node->hash_next);
    if (next_node == NULL)
    {
        LOGF("Node Map Failure: node (\"%s\")->next (\"%s\") not found", node->name, node->next);
        startupFailureRecord(1);
        return;
    }

    if (next_node->hash_type == trojanserverUserControllerTypeHash())
    {
        LOGF("TrojanServer: authenticated mode creates an internal UserController; remove the manual next "
             "UserController node \"%s\" and point TrojanServer to the real outbound node",
             next_node->name);
        startupFailureRecord(1);
        return;
    }

    if (controller->prev != NULL && controller->prev != t)
    {
        LOGF("TrojanServer: internal UserController is already bound downstream by %s", controller->prev->node->name);
        startupFailureRecord(1);
        return;
    }

    if (t->next != NULL && t->next != controller)
    {
        LOGF("TrojanServer: node \"%s\" is already bound upstream by %s", node->name, t->next->node->name);
        startupFailureRecord(1);
        return;
    }

    tunnelBind(t, controller);

    tunnelchainInsert(chain, t);
    controller->onChain(controller, chain);
    chain = tunnelGetChain(t);

    trojanserverBindFallbackTarget(t, chain);
}

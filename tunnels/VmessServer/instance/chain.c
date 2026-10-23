#include "internal.h"

#include "loggers/network_logger.h"

static hash_t vmessserverUserControllerTypeHash(void)
{
    const char *type_name = "UserController";
    return calcHashBytes(type_name, stringLength(type_name));
}

static void vmessserverBindFallbackTarget(tunnel_t *t, tunnel_chain_t *chain)
{
    vmessserver_tstate_t *ts = tunnelGetState(t);

    if (ts->fallback_node == NULL)
    {
        return;
    }

    tunnel_t *target = ts->fallback_node->instance;
    if (target == NULL)
    {
        LOGF("VmessServer: fallback tunnel \"%s\" is not available", ts->fallback_node->name);
        startupFailureRecord(1);
        return;
    }

    if (target == t || target == ts->user_controller_tunnel)
    {
        LOGF("VmessServer: fallback target must be different from VmessServer and its internal UserController");
        startupFailureRecord(1);
        return;
    }

    ts->fallback_tunnel = target;

    if (target == t->next)
    {
        return;
    }

    if (target->prev != NULL && target->prev != t)
    {
        LOGF("VmessServer: fallback target node \"%s\" is already bound to previous node \"%s\"",
             target->node->name,
             target->prev->node->name);
        startupFailureRecord(1);
        return;
    }

    if (target->chain == chain)
    {
        if (target->prev == t)
        {
            return;
        }

        LOGF("VmessServer: fallback target node \"%s\" is already in the VmessServer chain", target->node->name);
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

    // The fallback target may insert internal tunnels in front of itself while
    // chaining (e.g. a connector's domain setup + DomainResolver); call the branch
    // entry bound directly below us, not the raw instance.
    ts->fallback_tunnel = tunnelGetBranchEntry(t, target);
    if (ts->fallback_tunnel == NULL)
    {
        LOGF("VmessServer: fallback target node \"%s\" is not reachable from VmessServer", target->node->name);
        startupFailureRecord(1);
        return;
    }
}

void vmessserverTunnelOnChain(tunnel_t *t, tunnel_chain_t *chain)
{
    vmessserver_tstate_t *ts   = tunnelGetState(t);
    node_t               *node = tunnelGetNode(t);

    tunnel_t *controller = ts->user_controller_tunnel;
    if (controller == NULL)
    {
        tunnelDefaultOnChain(t, chain);
        chain = tunnelGetChain(t);
        vmessserverBindFallbackTarget(t, chain);
        return;
    }

    if (node->hash_next == 0)
    {
        LOGF("VmessServer: a next node is required");
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

    if (next_node->hash_type == vmessserverUserControllerTypeHash())
    {
        LOGF("VmessServer: authenticated mode creates an internal UserController; remove the manual next "
             "UserController node \"%s\" and point VmessServer to the real outbound node",
             next_node->name);
        startupFailureRecord(1);
        return;
    }

    if (controller->prev != NULL && controller->prev != t)
    {
        LOGF("VmessServer: internal UserController is already bound downstream by %s", controller->prev->node->name);
        startupFailureRecord(1);
        return;
    }

    if (t->next != NULL && t->next != controller)
    {
        LOGF("VmessServer: node \"%s\" is already bound upstream by %s", node->name, t->next->node->name);
        startupFailureRecord(1);
        return;
    }

    tunnelBind(t, controller);

    tunnelchainInsert(chain, t);
    controller->onChain(controller, chain);
    chain = tunnelGetChain(t);

    vmessserverBindFallbackTarget(t, chain);
}

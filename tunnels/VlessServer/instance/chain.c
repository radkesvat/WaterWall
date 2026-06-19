#include "structure.h"

#include "loggers/network_logger.h"
#include "managers/node_manager.h"

static hash_t vlessserverUserControllerTypeHash(void)
{
    const char *type_name = "UserController";
    return calcHashBytes(type_name, stringLength(type_name));
}

static void vlessserverBindFallbackTarget(tunnel_t *t, tunnel_chain_t *chain)
{
    vlessserver_tstate_t *ts = tunnelGetState(t);

    if (ts->fallback_node == NULL)
    {
        return;
    }

    tunnel_t *target = ts->fallback_node->instance;
    if (target == NULL)
    {
        LOGF("VlessServer: fallback tunnel \"%s\" is not available", ts->fallback_node->name);
        terminateProgram(1);
    }

    if (target == t || target == ts->user_controller_tunnel)
    {
        LOGF("VlessServer: fallback target must be different from VlessServer and its internal UserController");
        terminateProgram(1);
    }

    ts->fallback_tunnel = target;

    if (target == t->next)
    {
        return;
    }

    if (target->prev != NULL && target->prev != t)
    {
        LOGF("VlessServer: fallback target node \"%s\" is already bound to previous node \"%s\"",
             target->node->name,
             target->prev->node->name);
        terminateProgram(1);
    }

    if (target->chain == chain)
    {
        if (target->prev == t)
        {
            return;
        }

        LOGF("VlessServer: fallback target node \"%s\" is already in the VlessServer chain", target->node->name);
        terminateProgram(1);
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
}

void vlessserverTunnelOnChain(tunnel_t *t, tunnel_chain_t *chain)
{
    vlessserver_tstate_t *ts   = tunnelGetState(t);
    node_t               *node = tunnelGetNode(t);

    tunnel_t *controller = ts->user_controller_tunnel;
    if (controller == NULL)
    {
        tunnelDefaultOnChain(t, chain);
        chain = tunnelGetChain(t);
        vlessserverBindFallbackTarget(t, chain);
        return;
    }

    if (node->hash_next == 0)
    {
        LOGF("VlessServer: a next node is required");
        terminateProgram(1);
    }

    node_t *next_node = nodemanagerGetConfigNodeByHash(node->node_manager_config, node->hash_next);
    if (next_node == NULL)
    {
        LOGF("Node Map Failure: node (\"%s\")->next (\"%s\") not found", node->name, node->next);
        terminateProgram(1);
    }

    if (next_node->hash_type == vlessserverUserControllerTypeHash())
    {
        LOGF("VlessServer: authenticated mode creates an internal UserController; remove the manual next "
             "UserController node \"%s\" and point VlessServer to the real outbound node",
             next_node->name);
        terminateProgram(1);
    }

    if (controller->prev != NULL && controller->prev != t)
    {
        LOGF("VlessServer: internal UserController is already bound downstream by %s", controller->prev->node->name);
        terminateProgram(1);
    }

    if (t->next != NULL && t->next != controller)
    {
        LOGF("VlessServer: node \"%s\" is already bound upstream by %s", node->name, t->next->node->name);
        terminateProgram(1);
    }

    tunnelBind(t, controller);

    tunnelchainInsert(chain, t);
    controller->onChain(controller, chain);
    chain = tunnelGetChain(t);

    vlessserverBindFallbackTarget(t, chain);
}

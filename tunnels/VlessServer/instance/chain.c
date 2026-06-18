#include "structure.h"

#include "loggers/network_logger.h"
#include "managers/node_manager.h"

static hash_t vlessserverUserControllerTypeHash(void)
{
    const char *type_name = "UserController";
    return calcHashBytes(type_name, stringLength(type_name));
}

void vlessserverTunnelOnChain(tunnel_t *t, tunnel_chain_t *chain)
{
    vlessserver_tstate_t *ts   = tunnelGetState(t);
    node_t               *node = tunnelGetNode(t);

    tunnel_t *controller = ts->user_controller_tunnel;
    if (controller == NULL)
    {
        LOGF("VlessServer: internal UserController is not available");
        terminateProgram(1);
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
}

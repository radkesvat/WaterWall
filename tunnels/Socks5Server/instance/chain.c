#include "structure.h"

#include "loggers/network_logger.h"
#include "managers/node_manager.h"

static hash_t socks5serverUserControllerTypeHashForChain(void)
{
    const char *type_name = "UserController";
    return calcHashBytes(type_name, stringLength(type_name));
}

void socks5serverTunnelOnChain(tunnel_t *t, tunnel_chain_t *chain)
{
    socks5server_tstate_t *ts   = tunnelGetState(t);
    node_t                *node = tunnelGetNode(t);

    if (ts->no_auth)
    {
        tunnelDefaultOnChain(t, chain);
        return;
    }

    tunnel_t *controller = ts->user_controller_tunnel;
    if (controller == NULL)
    {
        LOGF("Socks5Server: authenticated mode requires an internal UserController");
        terminateProgram(1);
    }

    if (node->hash_next == 0)
    {
        LOGF("Socks5Server: a next node is required");
        terminateProgram(1);
    }

    node_t *next_node = nodemanagerGetConfigNodeByHash(node->node_manager_config, node->hash_next);
    if (next_node == NULL)
    {
        LOGF("Node Map Failure: node (\"%s\")->next (\"%s\") not found", node->name, node->next);
        terminateProgram(1);
    }

    if (next_node->hash_type == socks5serverUserControllerTypeHashForChain())
    {
        LOGF("Socks5Server: authenticated mode creates an internal UserController; remove the manual next "
             "UserController node \"%s\" and point Socks5Server to the real outbound node",
             next_node->name);
        terminateProgram(1);
    }

    if (controller->prev != NULL && controller->prev != t)
    {
        LOGF("Socks5Server: internal UserController is already bound downstream by %s",
             controller->prev->node->name);
        terminateProgram(1);
    }

    if (t->next != NULL && t->next != controller)
    {
        LOGF("Socks5Server: node \"%s\" is already bound upstream by %s", node->name, t->next->node->name);
        terminateProgram(1);
    }

    tunnelBind(t, controller);

    tunnelchainInsert(chain, t);
    controller->onChain(controller, chain);
}

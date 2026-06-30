#include "structure.h"

#include "loggers/network_logger.h"
#include "managers/node_manager.h"

static hash_t wireguarddeviceUserControllerTypeHash(void)
{
    const char *type_name = "UserController";
    return calcHashBytes(type_name, stringLength(type_name));
}

static void wireguarddeviceSetInternalUserControllerNext(wgd_tstate_t *state, const char *next, hash_t hash_next)
{
    node_t *controller_node = &state->user_controller_node;

    memoryFree(controller_node->next);
    controller_node->next      = NULL;
    controller_node->hash_next = 0;

    if (next == NULL)
    {
        return;
    }

    controller_node->next = stringDuplicate(next);
    if (controller_node->next == NULL)
    {
        LOGF("WireGuardDevice: failed to set internal UserController next node");
        terminateProgram(1);
    }
    controller_node->hash_next = hash_next;
}

static node_t *wireguarddeviceGetNextNode(tunnel_t *t)
{
    node_t *node = tunnelGetNode(t);

    if (node->hash_next == 0)
    {
        LOGF("WireGuardDevice: a next node is required when its transport side is next");
        terminateProgram(1);
    }

    node_t *next_node = nodemanagerGetConfigNodeByHash(node->node_manager_config, node->hash_next);
    if (next_node == NULL)
    {
        LOGF("Node Map Failure: node (\"%s\")->next (\"%s\") not found", node->name, node->next);
        terminateProgram(1);
    }

    return next_node;
}

static void wireguarddeviceInsertUserControllerNext(tunnel_t *t, tunnel_chain_t *chain)
{
    wgd_tstate_t *state      = tunnelGetState(t);
    node_t       *node       = tunnelGetNode(t);
    tunnel_t     *controller = state->user_controller_tunnel;
    node_t       *next_node  = wireguarddeviceGetNextNode(t);

    if (next_node->hash_type == wireguarddeviceUserControllerTypeHash())
    {
        LOGF("WireGuardDevice: authenticated mode creates an internal UserController on the transport side; remove "
             "the manual next UserController node \"%s\" and point WireGuardDevice to the real transport node",
             next_node->name);
        terminateProgram(1);
    }

    if (controller->prev != NULL && controller->prev != t)
    {
        LOGF("WireGuardDevice: internal UserController is already bound downstream by %s",
             controller->prev->node->name);
        terminateProgram(1);
    }

    if (t->next != NULL && t->next != controller)
    {
        LOGF("WireGuardDevice: node \"%s\" is already bound upstream by %s", node->name, t->next->node->name);
        terminateProgram(1);
    }

    wireguarddeviceSetInternalUserControllerNext(state, node->next, node->hash_next);
    tunnelBind(t, controller);

    tunnelchainInsert(chain, t);
    controller->onChain(controller, chain);
}

static void wireguarddeviceInsertUserControllerPrev(tunnel_t *t, tunnel_chain_t *chain)
{
    wgd_tstate_t *state      = tunnelGetState(t);
    node_t       *node       = tunnelGetNode(t);
    tunnel_t     *controller = state->user_controller_tunnel;
    tunnel_t     *prev       = t->prev;

    if (prev == NULL)
    {
        LOGF("WireGuardDevice: cannot insert transport-side UserController before the previous tunnel is bound");
        terminateProgram(1);
    }

    if (prev->node != NULL && prev->node->hash_type == wireguarddeviceUserControllerTypeHash())
    {
        LOGF("WireGuardDevice: authenticated mode creates an internal UserController on the transport side; remove "
             "the manual previous UserController node \"%s\"",
             prev->node->name);
        terminateProgram(1);
    }

    if (controller->prev != NULL && controller->prev != prev)
    {
        LOGF("WireGuardDevice: internal UserController is already bound downstream by %s",
             controller->prev->node->name);
        terminateProgram(1);
    }

    if (controller->next != NULL && controller->next != t)
    {
        LOGF("WireGuardDevice: internal UserController is already bound upstream by %s",
             controller->next->node->name);
        terminateProgram(1);
    }

    if (prev->next != t && prev->next != controller)
    {
        LOGF("WireGuardDevice: previous tunnel \"%s\" is not bound directly to WireGuardDevice", prev->node->name);
        terminateProgram(1);
    }

    wireguarddeviceSetInternalUserControllerNext(state, node->name, node->hash_name);

    prev->next        = controller;
    controller->prev  = prev;
    controller->next  = t;
    t->prev           = controller;

    tunnelchainInsert(chain, controller);
    tunnelDefaultOnChain(t, chain);
}

void wireguarddeviceTunnelOnChain(tunnel_t *t, tunnel_chain_t *chain)
{
    wgd_tstate_t *state = tunnelGetState(t);

    if (state->user_controller_tunnel == NULL)
    {
        tunnelDefaultOnChain(t, chain);
        return;
    }

    if (t->prev == NULL)
    {
        if (chain->tunnels.len != 0)
        {
            LOGF("WireGuardDevice: cannot defer internal UserController insertion on a non-empty chain");
            terminateProgram(1);
        }
        tunnelchainDestroy(chain);
        return;
    }

    wireguarddeviceResolveTransportSide(t);
    if (wireguarddeviceTransportSideIsNext(state))
    {
        wireguarddeviceInsertUserControllerNext(t, chain);
        return;
    }

    wireguarddeviceInsertUserControllerPrev(t, chain);
}

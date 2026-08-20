#include "structure.h"

#include "loggers/network_logger.h"
#include "net/node_layer_solver.h"

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
        startupFailureRecord(1);
        return;
    }
    controller_node->hash_next = hash_next;
}

static bool wireguarddeviceFindChainIndex(const tunnel_chain_t *chain, const tunnel_t *t, uint16_t *index)
{
    for (uint16_t i = 0; i < chain->tunnels.len; ++i)
    {
        if (chain->tunnels.tuns[i] == t)
        {
            *index = i;
            return true;
        }
    }
    return false;
}

static bool wireguarddeviceInsertUserControllerNext(tunnel_t *t, tunnel_chain_t *chain, uint16_t index)
{
    wgd_tstate_t *state      = tunnelGetState(t);
    tunnel_t     *controller = state->user_controller_tunnel;
    tunnel_t     *next       = t->next;

    if (next == NULL)
    {
        LOGF("WireGuardDevice: solved next transport side has no adjacent tunnel");
        startupFailureRecord(1);
        return false;
    }
    if (next->node != NULL && next->node->hash_type == wireguarddeviceUserControllerTypeHash())
    {
        LOGF("WireGuardDevice: authenticated mode creates an internal UserController on the transport side; remove "
             "the manual next UserController node \"%s\"",
             next->node->name);
        startupFailureRecord(1);
        return false;
    }
    if (controller->chain != NULL || controller->prev != NULL || controller->next != NULL)
    {
        LOGF("WireGuardDevice: internal UserController is already attached to a chain");
        startupFailureRecord(1);
        return false;
    }

    wireguarddeviceSetInternalUserControllerNext(state, next->node->name, next->node->hash_name);
    if (UNLIKELY(startupFailurePending()))
    {
        return false;
    }

    tunnelchainInsertAt(chain, controller, (uint16_t) (index + 1U));
    if (UNLIKELY(startupFailurePending() || controller->chain != chain))
    {
        return false;
    }

    t->next          = controller;
    controller->prev = t;
    controller->next = next;
    next->prev       = controller;
    return true;
}

static bool wireguarddeviceInsertUserControllerPrev(tunnel_t *t, tunnel_chain_t *chain, uint16_t index)
{
    wgd_tstate_t *state      = tunnelGetState(t);
    tunnel_t     *controller = state->user_controller_tunnel;
    tunnel_t     *prev       = t->prev;

    if (prev == NULL)
    {
        LOGF("WireGuardDevice: solved previous transport side has no adjacent tunnel");
        startupFailureRecord(1);
        return false;
    }
    if (prev->node != NULL && prev->node->hash_type == wireguarddeviceUserControllerTypeHash())
    {
        LOGF("WireGuardDevice: authenticated mode creates an internal UserController on the transport side; remove "
             "the manual previous UserController node \"%s\"",
             prev->node->name);
        startupFailureRecord(1);
        return false;
    }
    if (controller->chain != NULL || controller->prev != NULL || controller->next != NULL)
    {
        LOGF("WireGuardDevice: internal UserController is already attached to a chain");
        startupFailureRecord(1);
        return false;
    }

    wireguarddeviceSetInternalUserControllerNext(state, t->node->name, t->node->hash_name);
    if (UNLIKELY(startupFailurePending()))
    {
        return false;
    }

    tunnelchainInsertAt(chain, controller, index);
    if (UNLIKELY(startupFailurePending() || controller->chain != chain))
    {
        return false;
    }

    prev->next       = controller;
    controller->prev = prev;
    controller->next = t;
    t->prev          = controller;
    return true;
}

/*
 * This must run before onIndex: choosing the transport side may insert the
 * private UserController, which invalidates the layer cache and requires a new
 * solve. onIndex only consumes the final solution over immutable topology.
 */
bool wireguarddeviceTunnelOnSolvedTopology(tunnel_t *t, tunnel_chain_t *chain)
{
    wgd_tstate_t *state = tunnelGetState(t);
    uint16_t      index;

    if (chain == NULL || ! chain->layer_solution_ready || ! wireguarddeviceFindChainIndex(chain, t, &index))
    {
        LOGF("WireGuardDevice: cannot resolve sides outside its solved chain");
        startupFailureRecord(1);
        return false;
    }

    const node_layer_domain_t prev_layer = (node_layer_domain_t) tunnelchainGetResolvedPrevLayer(chain, index);
    const node_layer_domain_t next_layer = (node_layer_domain_t) tunnelchainGetResolvedNextLayer(chain, index);

    if (prev_layer == kLayerDomainL3 && next_layer == kLayerDomainL4)
    {
        state->transport_side_is_next = true;
    }
    else if (prev_layer == kLayerDomainL4 && next_layer == kLayerDomainL3)
    {
        state->transport_side_is_next = false;
    }
    else
    {
        state->transport_side_resolved = false;
        LOGF("WireGuardDevice: chain layers must resolve exactly one L3 packet side and one L4 transport side "
             "(previous=%s, next=%s); use packet/stream bridge nodes to make the topology explicit",
             nodeLayerDomainToString(prev_layer),
             nodeLayerDomainToString(next_layer));
        startupFailureRecord(1);
        return false;
    }

    state->transport_side_resolved = true;
    if (state->user_controller_tunnel == NULL)
    {
        return false;
    }

    tunnel_t *controller = state->user_controller_tunnel;
    if (controller->chain != NULL)
    {
        const bool correctly_attached =
            controller->chain == chain &&
            (state->transport_side_is_next ? t->next == controller : t->prev == controller);
        if (! correctly_attached)
        {
            LOGF("WireGuardDevice: internal UserController is attached on the wrong side");
            startupFailureRecord(1);
        }
        return false;
    }

    if (state->transport_side_is_next)
    {
        return wireguarddeviceInsertUserControllerNext(t, chain, index);
    }
    return wireguarddeviceInsertUserControllerPrev(t, chain, index);
}

void wireguarddeviceTunnelOnChain(tunnel_t *t, tunnel_chain_t *chain)
{
    tunnelDefaultOnChain(t, chain);
}

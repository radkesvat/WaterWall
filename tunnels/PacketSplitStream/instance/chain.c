#include "structure.h"

#include "loggers/network_logger.h"

void packetsplitstreamTunnelOnChain(tunnel_t *t, tunnel_chain_t *chain)
{
    packetsplitstream_tstate_t *state = tunnelGetState(t);

    state->up_tunnel   = state->up_node->instance;
    state->down_tunnel = state->down_node->instance;

    if (state->up_tunnel == NULL || state->down_tunnel == NULL)
    {
        LOGF("PacketSplitStream: referenced up/down tunnel instances are not available");
        terminateProgram(1);
    }

    if (state->up_tunnel == state->down_tunnel)
    {
        LOGF("PacketSplitStream: up/down tunnel instances must be different");
        terminateProgram(1);
    }

    if ((state->up_tunnel->prev != NULL && state->up_tunnel->prev != t) ||
        (state->down_tunnel->prev != NULL && state->down_tunnel->prev != t))
    {
        LOGF("PacketSplitStream: configured up/down nodes are already bound to another previous tunnel");
        terminateProgram(1);
    }

    if (t->next != NULL && t->next != state->down_tunnel)
    {
        LOGF("PacketSplitStream: tunnel already has a different chained next tunnel");
        terminateProgram(1);
    }

    tunnelBindDown(t, state->up_tunnel);
    tunnelBind(t, state->down_tunnel);
    tunnelchainInsert(chain, t);

    if (state->down_tunnel->chain != NULL)
    {
        tunnelchainCombine(state->down_tunnel->chain, chain);
    }
    else
    {
        state->down_tunnel->onChain(state->down_tunnel, chain);
    }

    chain = tunnelGetChain(t);

    if (state->up_tunnel->chain != NULL)
    {
        if (state->up_tunnel->chain != chain)
        {
            tunnelchainCombine(chain, state->up_tunnel->chain);
        }
    }
    else
    {
        state->up_tunnel->onChain(state->up_tunnel, chain);
    }

    // Each branch may insert internal tunnels in front of itself while chaining;
    // drive the branch entries bound directly below us, not the raw instances.
    tunnel_t *up_entry   = tunnelGetBranchEntry(t, state->up_tunnel);
    tunnel_t *down_entry = tunnelGetBranchEntry(t, state->down_tunnel);
    if (up_entry == NULL || down_entry == NULL)
    {
        LOGF("PacketSplitStream: configured up/down node is not reachable from the split tunnel");
        terminateProgram(1);
    }
    state->up_tunnel   = up_entry;
    state->down_tunnel = down_entry;
}

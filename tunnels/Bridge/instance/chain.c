#include "structure.h"

#include "loggers/network_logger.h"

void bridgeTunnelOnChain(tunnel_t *t, tunnel_chain_t *chain)
{

    bridge_tstate_t *state = tunnelGetState(t);

    tunnelDefaultOnChain(t, chain);

    if (! state->pair_tun)
    {

        // we are first in pair, so we need to set pair_tunel
        state->pair_tun = state->pair_node->instance;

        bridge_tstate_t *pair_state = tunnelGetState(state->pair_tun);

        pair_state->pair_tun = t;

        state->pair_tun->onChain(state->pair_tun, chain);
    }
}

#include "structure.h"

#include "loggers/network_logger.h"

void bridgeTunnelOnChain(tunnel_t *t, tunnel_chain_t *chain)
{

    bridge_tstate_t *state      = tunnelGetState(t);
    bridge_tstate_t *pair_state = tunnelGetState(state->pair_tunel);

    tunnelDefaultOnChain(t, chain);

    if (! state->pair_tunel)
    {

        // we are first in pair, so we need to set pair_tunel
        state->pair_tunel      = state->pair_node->instance;
        pair_state->pair_tunel = t;

        state->pair_tunel->onChain(state->pair_tunel, chain);
    }
}

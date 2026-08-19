#include "structure.h"

#include "loggers/network_logger.h"

void bridgeTunnelOnChain(tunnel_t *t, tunnel_chain_t *chain)
{

    bridge_tstate_t *state = tunnelGetState(t);

    tunnelDefaultOnChain(t, chain);
    chain = tunnelGetChain(t);

    if (! state->pair_tun)
    {
        // we are first in pair, so we need to set pair_tunel
        assert(state->pair_node != NULL);
        state->pair_tun = state->pair_node->instance;
        assert(state->pair_tun != NULL);

        bridge_tstate_t *pair_state = tunnelGetState(state->pair_tun);

        pair_state->pair_tun = t;

        state->pair_tun->onChain(state->pair_tun, chain);
    }

    chain = tunnelGetChain(t);
    assert(state->pair_tun != NULL && chain != NULL);

    tunnelchainRegisterLayerRelation(
        chain, t, kTunnelLayerSidePrev, state->pair_tun, kTunnelLayerSidePrev, kTunnelLayerRelationSame);

    tunnelchainRegisterLayerRelation(
        chain, t, kTunnelLayerSideNext, state->pair_tun, kTunnelLayerSideNext, kTunnelLayerRelationSame);
}

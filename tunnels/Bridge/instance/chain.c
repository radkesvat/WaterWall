#include "structure.h"

#include "loggers/network_logger.h"

void bridgeTunnelOnChain(tunnel_t *t, tunnel_chain_t *chain)
{

    bridge_tstate_t *state = tunnelGetState(t);

    tunnelDefaultOnChain(t, chain);
    if (UNLIKELY(startupFailurePending()))
    {
        return;
    }

    chain = tunnelGetChain(t);

    if (! state->pair_tun)
    {
        // We are first in the pair, so publish the reciprocal link before
        // chaining the peer and thereby prevent recursive pair setup.
        if (UNLIKELY(state->pair_node == NULL || state->pair_node->instance == NULL))
        {
            LOGF("Bridge: pair for node \"%s\" has no created tunnel instance", t->node->name);
            startupFailureRecord(1);
            return;
        }

        tunnel_t *pair_tun = state->pair_node->instance;
        if (UNLIKELY(pair_tun == t || pair_tun->node == NULL || t->node->type == NULL || pair_tun->node->type == NULL ||
                     pair_tun->node->hash_type != t->node->hash_type ||
                     stringCompare(pair_tun->node->type, t->node->type) != 0))
        {
            LOGF("Bridge: pair for node \"%s\" is not a distinct Bridge tunnel", t->node->name);
            startupFailureRecord(1);
            return;
        }

        bridge_tstate_t *pair_state = tunnelGetState(pair_tun);
        if (UNLIKELY(pair_state->pair_node != t->node || (pair_state->pair_tun != NULL && pair_state->pair_tun != t)))
        {
            LOGF("Bridge: pair configuration for node \"%s\" is not reciprocal", t->node->name);
            startupFailureRecord(1);
            return;
        }

        state->pair_tun      = pair_tun;
        pair_state->pair_tun = t;

        pair_tun->onChain(pair_tun, chain);
        if (UNLIKELY(startupFailurePending()))
        {
            return;
        }
    }

    chain = tunnelGetChain(t);
    if (UNLIKELY(state->pair_tun == NULL || chain == NULL))
    {
        LOGF("Bridge: node \"%s\" lost its pair or chain during startup", t->node->name);
        startupFailureRecord(1);
        return;
    }

    if (! tunnelchainRegisterLayerRelation(
            chain, t, kTunnelLayerSidePrev, state->pair_tun, kTunnelLayerSidePrev, kTunnelLayerRelationSame))
    {
        return;
    }

    if (! tunnelchainRegisterLayerRelation(
            chain, t, kTunnelLayerSideNext, state->pair_tun, kTunnelLayerSideNext, kTunnelLayerRelationSame))
    {
        return;
    }
}

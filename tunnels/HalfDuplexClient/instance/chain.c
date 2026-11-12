#include "structure.h"

#include "loggers/network_logger.h"

static bool halfduplexclientPathConflictsWithChain(tunnel_t *t, node_t *target)
{
    // Named branches are not part of NodeManager's configured-next cycle walk.
    for (unsigned depth = 0; target != NULL && depth <= kMaxChainLen; ++depth)
    {
        if (target == t->node || (target->instance != NULL && target->instance->chain == tunnelGetChain(t)))
            return true;
        if (target->hash_next == 0)
            return false;
        target = nodemanagerGetConfigNodeByHash(t->node->node_manager_config, target->hash_next);
    }
    return true;
}

static tunnel_t *halfduplexclientAttachPath(tunnel_t *t, node_t *node, bool primary)
{
    tunnel_t       *target = node->instance;
    tunnel_chain_t *chain  = tunnelGetChain(t);
    if (target == NULL || target->prev != NULL || halfduplexclientPathConflictsWithChain(t, node))
    {
        LOGF("HalfDuplexClient: upload/download path is unavailable, already bound, or cyclic");
        startupFailureRecord(1);
        return NULL;
    }
    if (primary)
        tunnelBind(t, target);
    else
        tunnelBindDown(t, target);

    if (target->chain != NULL)
        tunnelchainCombine(chain, target->chain);
    else
        target->onChain(target, chain);
    if (startupFailurePending())
        return NULL;

    // Chaining may insert private predecessors and merge the original chain.
    tunnel_t *entry = tunnelGetBranchEntry(t, target);
    if (entry == NULL)
    {
        LOGF("HalfDuplexClient: upload/download path has no callable branch entry");
        startupFailureRecord(1);
    }
    return entry;
}

void halfduplexclientTunnelOnChain(tunnel_t *t, tunnel_chain_t *chain)
{
    halfduplexclient_tstate_t *ts = tunnelGetState(t);
    // Require the normal inlet before attaching branches, including when the
    // node manager happens to visit this middle node before its predecessor.
    if (t->prev == NULL)
    {
        assert(chain->tunnels.len == 0);
        tunnelchainDestroy(chain);
        return;
    }
    if (ts->upload_node == NULL)
    {
        tunnelDefaultOnChain(t, chain);
        if (! startupFailurePending())
        {
            ts->upload_tunnel   = t->next;
            ts->download_tunnel = t->next;
        }
        return;
    }

    tunnelchainInsert(chain, t);
    if (startupFailurePending())
        return;
    ts->download_tunnel = halfduplexclientAttachPath(t, ts->download_node, true);
    if (startupFailurePending())
        return;
    ts->upload_tunnel = ts->upload_node == ts->download_node ? ts->download_tunnel
                                                             : halfduplexclientAttachPath(t, ts->upload_node, false);
    if (! startupFailurePending() && ts->upload_tunnel != ts->download_tunnel)
    {
        // The extra branch has only a prev-link back to us. Couple its inlet
        // to our ordinary L4 next edge so the solver constrains both paths.
        discard tunnelchainRegisterLayerRelation(tunnelGetChain(t),
                                                 t,
                                                 kTunnelLayerSideNext,
                                                 ts->upload_tunnel,
                                                 kTunnelLayerSidePrev,
                                                 kTunnelLayerRelationSame);
    }
}

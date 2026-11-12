#include "structure.h"

#include "loggers/network_logger.h"

static bool halfduplexserverPairPathIsCyclic(tunnel_t *t, node_t *node)
{
    // Pair references are outside NodeManager's configured-next cycle walk.
    // Follow configuration edges: other wrappers may not be chained yet.
    for (unsigned depth = 0; node != NULL && depth <= kMaxChainLen; ++depth)
    {
        if (node == t->node)
            return true;
        if (node->hash_next != 0)
        {
            node = nodemanagerGetConfigNodeByHash(t->node->node_manager_config, node->hash_next);
            continue;
        }
        // A secondary continues through its primary. Other node types may
        // have unrelated settings named pair; those are not routing edges here.
        if (node->hash_type != t->node->hash_type || stringCompare(node->type, t->node->type) != 0)
            return false;
        const cJSON *pair = cJSON_GetObjectItemCaseSensitive(node->node_settings_json, "pair");
        if (pair == NULL)
            return false;
        // All constructors have validated their settings before chaining.
        assert(cJSON_IsString(pair) && pair->valuestring != NULL && pair->valuestring[0] != '\0');
        node = nodemanagerGetConfigNodeByName(t->node->node_manager_config, pair->valuestring);
    }
    return true;
}

void halfduplexserverTunnelOnChain(tunnel_t *t, tunnel_chain_t *chain)
{
    halfduplexserver_tstate_t *ts = tunnelGetState(t);
    if (ts->pair_node == NULL)
    {
        tunnelDefaultOnChain(t, chain);
        return;
    }

    tunnel_t *primary_wrapper = ts->pair_node->instance;
    if (primary_wrapper == NULL || halfduplexserverPairPathIsCyclic(t, ts->pair_node))
    {
        LOGF("HalfDuplexServer: pair is unavailable or its application path contains a next/pair cycle");
        startupFailureRecord(1);
        return;
    }

    tunnelchainInsert(chain, t);
    if (startupFailurePending())
        return;

    // Preserve both transport predecessors. Combining storage does not bind
    // this secondary's next to the primary or replace either ingress wrapper.
    if (primary_wrapper->chain == NULL)
        primary_wrapper->onChain(primary_wrapper, chain);
    else if (primary_wrapper->chain != chain)
        tunnelchainCombine(chain, primary_wrapper->chain);
    if (startupFailurePending())
        return;

    // PipeTunnel publishes its child as next during chaining. node.instance
    // names that wrapper, not the HalfDuplexServer state it owns.
    ts->owner = primary_wrapper->next;
    assert(ts->owner != NULL);
    assert(((halfduplexserver_tstate_t *) tunnelGetState(ts->owner))->owner == ts->owner);
    discard tunnelchainRegisterLayerRelation(
        tunnelGetChain(t), t, kTunnelLayerSidePrev, ts->owner, kTunnelLayerSidePrev, kTunnelLayerRelationSame);
}

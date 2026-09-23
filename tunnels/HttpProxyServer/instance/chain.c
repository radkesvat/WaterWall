#include "loggers/network_logger.h"
#include "structure.h"

static void bindFallback(tunnel_t *t)
{
    hps_tstate_t *ts = tunnelGetState(t);
    if (! ts->fallback_node || startupFailurePending())
        return;
    tunnel_t       *target = ts->fallback_node->instance;
    tunnel_chain_t *chain  = tunnelGetChain(t);
    if (! target || target == t || target == ts->controller || target->prev || target->chain == chain)
        goto invalid;
    /* Reject a configured forward path back into this owner before chaining it. */
    node_t *node = ts->fallback_node;
    for (unsigned count = 0; node; ++count)
    {
        if (node == tunnelGetNode(t) || node == &ts->controller_node || count >= kMaxChainLen)
            goto invalid;
        node = node->hash_next ? nodemanagerGetConfigNodeByHash(node->node_manager_config, node->hash_next) : NULL;
    }
    tunnelBindDown(t, target);
    if (target->chain)
        tunnelchainCombine(chain, target->chain);
    else
        target->onChain(target, chain);
    if (startupFailurePending())
        return;
    ts->fallback = tunnelGetBranchEntry(t, target);
    if (ts->fallback)
        return;
invalid:
    LOGF("HttpProxyServer: fallback requires a distinct, unbound L4 branch without a cycle");
    startupFailureRecord(1);
}

void httpproxyserverTunnelOnChain(tunnel_t *t, tunnel_chain_t *chain)
{
    hps_tstate_t *ts = tunnelGetState(t);
    if (ts->auth_mode != kHpsAuthTracked)
    {
        tunnelDefaultOnChain(t, chain);
        bindFallback(t);
        return;
    }
    node_t *node     = tunnelGetNode(t);
    node_t *outbound = nodemanagerGetConfigNodeByHash(node->node_manager_config, node->hash_next);
    if (! outbound || ! stringCompare(outbound->type, "UserController") || (t->next && t->next != ts->controller) ||
        (ts->controller->prev && ts->controller->prev != t))
    {
        LOGF("HttpProxyServer: authenticated mode requires an outbound node after its internal UserController");
        startupFailureRecord(1);
        return;
    }
    tunnelBind(t, ts->controller);
    tunnelchainInsert(chain, t);
    ts->controller->onChain(ts->controller, chain);
    bindFallback(t);
}

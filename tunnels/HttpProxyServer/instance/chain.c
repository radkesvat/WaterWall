#include "loggers/network_logger.h"
#include "structure.h"

void httpproxyserverTunnelOnChain(tunnel_t *t, tunnel_chain_t *chain)
{
    hps_tstate_t *ts = tunnelGetState(t);
    if (ts->auth_mode != kHpsAuthTracked)
    {
        tunnelDefaultOnChain(t, chain);
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
}

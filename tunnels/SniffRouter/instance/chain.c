#include "structure.h"

#include "loggers/network_logger.h"

void sniffrouterTunnelOnChain(tunnel_t *t, tunnel_chain_t *chain)
{
    sniffrouter_tstate_t *ts = tunnelGetState(t);

    tunnelDefaultOnChain(t, chain);
    chain = tunnelGetChain(t);

    tunnel_t *web = ts->web_node->instance;
    if (web == NULL)
    {
        LOGF("SniffRouter: referenced web tunnel instance is not available");
        terminateProgram(1);
    }

    if (web == t || web == t->next)
    {
        LOGF("SniffRouter: web node must be different from the router and its normal next node");
        terminateProgram(1);
    }

    if (web->prev != NULL && web->prev != t)
    {
        LOGF("SniffRouter: web node \"%s\" is already bound to previous node \"%s\"",
             web->node->name,
             web->prev->node->name);
        terminateProgram(1);
    }

    if (web->chain == chain)
    {
        LOGF("SniffRouter: web node \"%s\" is already in the router chain", web->node->name);
        terminateProgram(1);
    }

    ts->web_tunnel = web;
    tunnelBindDown(t, web);

    if (web->chain != NULL)
    {
        tunnelchainCombine(chain, web->chain);
    }
    else
    {
        web->onChain(web, chain);
    }
}

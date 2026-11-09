#include "structure.h"

void domainresolverTunnelDownStreamFinish(tunnel_t *t, line_t *l)
{
    domainresolver_lstate_t *ls = lineGetState(l, t);

    if (ls->chain_query != NULL)
    {
        // Detach before the owner settles the injected line; nothing goes back toward next.
        dnslineclient_query_t *query = ls->chain_query;
        domainresolverChainDetachLine(t, l);
        dnslineclientOnLineFinish(query, l);
        return;
    }

    domainresolverLinestateDestroy(t, l, ls);
    tunnelPrevDownStreamFinish(t, l);
}

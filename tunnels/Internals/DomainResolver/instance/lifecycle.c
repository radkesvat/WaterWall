#include "structure.h"

/* Every hook is a no-op in core mode: no client exists and the resolver keeps
 * the default lifecycle behaviour. */

void domainresolverTunnelOnPrepare(tunnel_t *t)
{
    domainresolver_tstate_t *ts = tunnelGetState(t);
    if (ts->mode != kDnsLineClientModeChain)
    {
        return;
    }

    assert(ts->chain_client == NULL && ts->inject != NULL && ts->inject_owner != NULL);
    ts->chain_client =
        dnslineclientCreate(&ts->chain_cfg, t, domainresolverChainOpenLine, domainresolverChainDetachLine);
}

void domainresolverTunnelOnWorkerQuiesce(tunnel_t *t, wid_t wid, const ww_lifecycle_context_t *context)
{
    discard                  context;
    domainresolver_tstate_t *ts = tunnelGetState(t);
    if (ts->chain_client != NULL)
    {
        dnslineclientWorkerQuiesce(ts->chain_client, wid);
    }
}

void domainresolverTunnelOnWorkerStop(tunnel_t *t, wid_t wid, const ww_lifecycle_context_t *context)
{
    discard                  context;
    domainresolver_tstate_t *ts = tunnelGetState(t);
    if (ts->chain_client != NULL)
    {
        dnslineclientWorkerStop(ts->chain_client, wid);
    }
}

void domainresolverTunnelOnDestroy(tunnel_t *t, const ww_lifecycle_context_t *context)
{
    discard                  context;
    domainresolver_tstate_t *ts = tunnelGetState(t);
    if (ts->chain_client != NULL)
    {
        dnslineclientDestroy(ts->chain_client);
        ts->chain_client = NULL;
    }
    tunnelDestroy(t);
}

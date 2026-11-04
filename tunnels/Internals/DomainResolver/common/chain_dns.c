#include "structure.h"

/*
 * Chain-mode host hooks for DnsLineClient. The query line is an owned normal
 * line of DnsLineClient; this resolver only binds it to its per-line state so
 * the line's downstream callbacks (which return here because the resolver is
 * the injection point's prev, or the standalone resolver's own next side) reach
 * the client. The line never runs this resolver's upstream Init, so its state
 * stays zero apart from chain_query and no ordinary resolving/pending path can
 * observe it.
 */

void domainresolverChainOpenLine(tunnel_t *t, line_t *l, dnslineclient_query_t *query)
{
    domainresolver_tstate_t *ts = tunnelGetState(t);
    domainresolver_lstate_t *ls = lineGetState(l, t);

    assert(query != NULL);
    assert(addresscontextIsResolverOrigin(lineGetDestinationAddressContext(l)));
    assert(ls->chain_query == NULL && ls->phase == kDomainResolverPhaseIdle);

    ls->chain_query = query;
    ts->inject(ts->inject_owner, l);
}

void domainresolverChainDetachLine(tunnel_t *t, line_t *l)
{
    memoryZeroAligned32(lineGetState(l, t), t->lstate_size);
}

void domainresolverChainInjectNext(tunnel_t *owner, line_t *l)
{
    tunnelNextUpStreamInit(owner, l);
}

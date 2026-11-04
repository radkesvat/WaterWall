#include "structure.h"

/*
 * DNS "chain" mode: the internal DomainResolver's DnsLineClient creates an owned
 * normal UDP query line (destination = DNS server IP, resolver-origin flag set)
 * and injects it here. The internal resolver is Router's prev, so entering
 * Router's own Init skips that resolver while every downstream callback of the
 * line still returns through it. Router classifies the line during Init: its
 * protocol is known from the resolver-origin flag, so no payload is awaited.
 * The line comes from this chain's line pools, so every rule target already has
 * a per-line state slot.
 */
void routerInjectResolverLine(tunnel_t *router, line_t *l)
{
    assert(addresscontextIsResolverOrigin(lineGetDestinationAddressContext(l)));
    assert(tunnelIsActiveForLine(router, l));
    routerTunnelUpStreamInit(router, l);
}

#include "internal.h"

#include "ProxyClientCommon/destination.h"

bool vlessclientApplyTargetContext(tunnel_t *t, line_t *l)
{
    vlessclient_tstate_t            *ts        = tunnelGetState(t);
    address_context_t               *dest_ctx  = lineGetDestinationAddressContext(l);
    const proxy_client_destination_t selection = {
        .target               = &ts->target_addr,
        .protocol             = ts->protocol == kVlessClientProtocolDestContext ? kProxyClientProtocolDestContext
                                : ts->protocol == kVlessClientProtocolTcp       ? kProxyClientProtocolTcp
                                                                                : kProxyClientProtocolUdp,
        .address_from_context = ts->target_addr_source != kDvsConstant,
        .port_from_context    = ts->target_port_source != kDvsConstant,
    };
    if (! proxyClientApplyDestination(dest_ctx, &selection, "VlessClient"))
        return false;

    if (ts->resolve_domains)
    {
        addresscontextSetDomainStrategy(dest_ctx, (enum domain_strategy) ts->domain_strategy);
    }
    return true;
}

bool vlessclientDomainResolverPrepare(tunnel_t *resolver, tunnel_t *client, line_t *l, void *user_lstate)
{
    discard resolver;

    discard user_lstate;
    return vlessclientApplyTargetContext(client, l);
}

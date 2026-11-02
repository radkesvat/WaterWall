#include "internal.h"

#include "ProxyClientCommon/destination.h"

bool socks5clientApplyTargetContext(tunnel_t *t, line_t *l)
{
    socks5client_tstate_t           *ts        = tunnelGetState(t);
    address_context_t               *dest_ctx  = lineGetDestinationAddressContext(l);
    const proxy_client_destination_t selection = {
        .target               = &ts->target_addr,
        .protocol             = ts->protocol == kSocks5ClientProtocolDestContext ? kProxyClientProtocolDestContext
                                : ts->protocol == kSocks5ClientProtocolTcp       ? kProxyClientProtocolTcp
                                                                                 : kProxyClientProtocolUdp,
        .address_from_context = ts->target_addr_source != kDvsConstant,
        .port_from_context    = ts->target_port_source != kDvsConstant,
    };
    if (! proxyClientApplyDestination(dest_ctx, &selection, "Socks5Client"))
        return false;

    // Target preparation also runs before local DNS can retain early input.
    if (dest_ctx->proto_udp)
        linePreferOrdinaryReadBoth(l);

    if (ts->resolve_domains)
    {
        addresscontextSetDomainStrategy(dest_ctx, (enum domain_strategy) ts->domain_strategy);
    }
    return true;
}

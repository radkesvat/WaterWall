#include "internal.h"

#include "ProxyClientCommon/destination.h"
#include "loggers/network_logger.h"

bool vmessclientApplyTargetContext(tunnel_t *t, line_t *l)
{
    vmessclient_tstate_t            *ts        = tunnelGetState(t);
    address_context_t               *dest_ctx  = lineGetDestinationAddressContext(l);
    const proxy_client_destination_t selection = {
        .target               = &ts->target_addr,
        .protocol             = ts->protocol == kVmessClientProtocolDestContext ? kProxyClientProtocolDestContext
                                : ts->protocol == kVmessClientProtocolTcp       ? kProxyClientProtocolTcp
                                                                                : kProxyClientProtocolUdp,
        .address_from_context = ts->target_addr_source != kDvsConstant,
        .port_from_context    = ts->target_port_source != kDvsConstant,
    };
    if (! proxyClientApplyDestination(dest_ctx, &selection, "VmessClient"))
        return false;

    if (! vmessModeValid(ts->security, ts->options, dest_ctx->proto_udp ? 2 : 1) || ! addresscontextIsValid(dest_ctx) ||
        dest_ctx->port == 0 ||
        (addresscontextIsDomain(dest_ctx) &&
         (dest_ctx->domain_len == 0 || memchr(dest_ctx->domain, 0, dest_ctx->domain_len) != NULL ||
          vmessIsPacketAddrDomain((const uint8_t *) dest_ctx->domain, dest_ctx->domain_len))))
    {
        LOGW("VmessClient: unsupported target or protocol/framing combination");
        return false;
    }

    if (ts->resolve_domains)
    {
        addresscontextSetDomainStrategy(dest_ctx, (enum domain_strategy) ts->domain_strategy);
    }
    return true;
}

bool vmessclientDomainResolverPrepare(tunnel_t *resolver, tunnel_t *client, line_t *l, void *user_lstate)
{
    discard resolver;

    discard user_lstate;
    return vmessclientApplyTargetContext(client, l);
}

bool vmessclientPacketTarget(const address_context_t *target, vmess_packet_addr_t *out)
{
    *out = (vmess_packet_addr_t) {.port = target->port};
    if (addresscontextIsIpv4(target))
    {
        out->address_type = 1;
        memoryCopy(out->address, &target->ip_address.u_addr.ip4.addr, 4);
    }
    else if (addresscontextIsIpv6(target))
    {
        out->address_type = 3;
        memoryCopy(out->address, &target->ip_address.u_addr.ip6, 16);
    }
    else
        return false;
    return out->port != 0;
}

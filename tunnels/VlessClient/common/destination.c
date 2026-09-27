#include "internal.h"

#include "loggers/network_logger.h"

static bool getProtocolFromContext(const address_context_t *ctx, vlessclient_protocol_t *protocol_out)
{
    if (ctx->proto_tcp && ! ctx->proto_udp && ! ctx->proto_icmp && ! ctx->proto_packet)
    {
        *protocol_out = kVlessClientProtocolTcp;
        return true;
    }

    if (ctx->proto_udp && ! ctx->proto_tcp && ! ctx->proto_icmp && ! ctx->proto_packet)
    {
        *protocol_out = kVlessClientProtocolUdp;
        return true;
    }

    return false;
}

static vlessclient_protocol_t resolveConfiguredProtocol(const vlessclient_tstate_t *ts,
                                                        const address_context_t    *current_dest_ctx)
{
    if (ts->protocol != kVlessClientProtocolDestContext)
    {
        return ts->protocol;
    }

    vlessclient_protocol_t protocol = kVlessClientProtocolTcp;
    if (getProtocolFromContext(current_dest_ctx, &protocol))
    {
        return protocol;
    }

    LOGW("VlessClient: configured protocol is dest_context->protocol, but the destination context protocol was "
         "missing or invalid (tcp=%u, udp=%u, icmp=%u, packet=%u); falling back to TCP",
         (unsigned int) current_dest_ctx->proto_tcp,
         (unsigned int) current_dest_ctx->proto_udp,
         (unsigned int) current_dest_ctx->proto_icmp,
         (unsigned int) current_dest_ctx->proto_packet);
    return kVlessClientProtocolTcp;
}

bool vlessclientApplyTargetContext(tunnel_t *t, line_t *l)
{
    vlessclient_tstate_t *ts       = tunnelGetState(t);
    address_context_t    *dest_ctx = lineGetDestinationAddressContext(l);
    address_context_t     current  = {0};
    bool uses_current_dest = (ts->target_addr_source != kDvsConstant) || (ts->target_port_source != kDvsConstant) ||
                             (ts->protocol == kVlessClientProtocolDestContext);

    if (uses_current_dest)
    {
        addresscontextCopy(&current, dest_ctx);
    }

    vlessclient_protocol_t resolved_protocol = resolveConfiguredProtocol(ts, &current);

    if (ts->target_addr_source == kDvsConstant)
    {
        addresscontextCopy(dest_ctx, &ts->target_addr);
    }
    else
    {
        if (UNLIKELY(! addresscontextIsValid(&current)))
        {
            LOGE("VlessClient: configured to use dest_context->address, but line destination address is not set");
            addresscontextReset(&current);
            return false;
        }

        addresscontextCopy(dest_ctx, &current);
    }

    if (ts->target_port_source == kDvsConstant)
    {
        addresscontextSetPort(dest_ctx, ts->target_addr.port);
    }
    else
    {
        if (UNLIKELY(current.port == 0))
        {
            LOGE("VlessClient: configured to use dest_context->port, but line destination port is not set");
            addresscontextReset(&current);
            return false;
        }

        addresscontextSetPort(dest_ctx, current.port);
    }

    if (resolved_protocol == kVlessClientProtocolTcp)
    {
        addresscontextSetOnlyProtocol(dest_ctx, IP_PROTO_TCP);
    }
    else
    {
        addresscontextSetOnlyProtocol(dest_ctx, IP_PROTO_UDP);
    }

    if (uses_current_dest)
    {
        addresscontextReset(&current);
    }

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

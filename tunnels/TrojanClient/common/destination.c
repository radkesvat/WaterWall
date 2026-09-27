#include "internal.h"

#include "loggers/network_logger.h"

static bool getProtocolFromContext(const address_context_t *ctx, trojanclient_protocol_t *protocol_out)
{
    if (ctx->proto_tcp && ! ctx->proto_udp && ! ctx->proto_icmp && ! ctx->proto_packet)
    {
        *protocol_out = kTrojanClientProtocolTcp;
        return true;
    }

    if (ctx->proto_udp && ! ctx->proto_tcp && ! ctx->proto_icmp && ! ctx->proto_packet)
    {
        *protocol_out = kTrojanClientProtocolUdp;
        return true;
    }

    return false;
}

static trojanclient_protocol_t resolveConfiguredProtocol(const trojanclient_tstate_t *ts,
                                                         const address_context_t     *current_dest_ctx)
{
    if (ts->protocol != kTrojanClientProtocolDestContext)
    {
        return ts->protocol;
    }

    trojanclient_protocol_t protocol = kTrojanClientProtocolTcp;
    if (getProtocolFromContext(current_dest_ctx, &protocol))
    {
        return protocol;
    }

    LOGW("TrojanClient: configured protocol is dest_context->protocol, but the destination context protocol was "
         "missing or invalid (tcp=%u, udp=%u, icmp=%u, packet=%u); falling back to TCP",
         (unsigned int) current_dest_ctx->proto_tcp,
         (unsigned int) current_dest_ctx->proto_udp,
         (unsigned int) current_dest_ctx->proto_icmp,
         (unsigned int) current_dest_ctx->proto_packet);
    return kTrojanClientProtocolTcp;
}

bool trojanclientApplyTargetContext(tunnel_t *t, line_t *l)
{
    trojanclient_tstate_t *ts       = tunnelGetState(t);
    address_context_t     *dest_ctx = lineGetDestinationAddressContext(l);
    address_context_t      current  = {0};
    bool uses_current_dest = (ts->target_addr_source != kDvsConstant) || (ts->target_port_source != kDvsConstant) ||
                             (ts->protocol == kTrojanClientProtocolDestContext);

    if (uses_current_dest)
    {
        addresscontextCopy(&current, dest_ctx);
    }

    trojanclient_protocol_t resolved_protocol = resolveConfiguredProtocol(ts, &current);

    if (ts->target_addr_source == kDvsConstant)
    {
        addresscontextCopy(dest_ctx, &ts->target_addr);
    }
    else
    {
        if (UNLIKELY(! addresscontextIsValid(&current)))
        {
            LOGE("TrojanClient: configured to use dest_context->address, but line destination address is not set");
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
            LOGE("TrojanClient: configured to use dest_context->port, but line destination port is not set");
            addresscontextReset(&current);
            return false;
        }

        addresscontextSetPort(dest_ctx, current.port);
    }

    if (resolved_protocol == kTrojanClientProtocolTcp)
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

bool trojanclientDomainResolverPrepare(tunnel_t *resolver, tunnel_t *client, line_t *l, void *user_lstate)
{
    discard resolver;

    discard user_lstate;
    return trojanclientApplyTargetContext(client, l);
}

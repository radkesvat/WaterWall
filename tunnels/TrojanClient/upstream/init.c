#include "structure.h"

#include "loggers/network_logger.h"

void trojanclientTunnelUpStreamInit(tunnel_t *t, line_t *l)
{
    trojanclient_tstate_t   *ts       = tunnelGetState(t);
    trojanclient_lstate_t   *ls       = lineGetState(l, t);
    trojanclient_protocol_t  protocol = kTrojanClientProtocolTcp;
    address_context_t *target = lineGetDestinationAddressContext(l);

    if (ts->resolve_domains)
    {
        trojanclient_domain_resolver_lstate_t *resolver_ls =
            domainresolverTunnelGetUserLineState(ts->domain_resolver_tunnel, l);
        protocol = resolver_ls->protocol;
    }
    else if (UNLIKELY(! trojanclientApplyTargetContext(t, l, &protocol)))
    {
        tunnelPrevDownStreamFinish(t, l);
        return;
    }

    trojanclientLinestateInitialize(ls, t, l);
    ls->protocol = protocol;
    ls->kind     = ls->protocol == kTrojanClientProtocolUdp ? kTrojanClientLineKindUdpApp : kTrojanClientLineKindDirect;
    addresscontextAddrCopy(&ls->target_addr, target);
    addresscontextSetPort(&ls->target_addr, target->port);

    if (ts->verbose)
    {
        LOGD("TrojanClient: line init protocol=%s port=%u",
             ls->protocol == kTrojanClientProtocolTcp ? "tcp" : "udp",
             (unsigned int) target->port);
    }

    if (ls->protocol == kTrojanClientProtocolUdp)
    {
        bool line_alive = true;
        if (UNLIKELY(! trojanclientStartUdpCarrier(t, l, ls, &line_alive)))
        {
            if (! line_alive)
            {
                return;
            }
            trojanclientLinestateDestroy(ls);
            tunnelPrevDownStreamFinish(t, l);
        }
        return;
    }

    tunnelNextUpStreamInit(t, l);
}

bool trojanclientDomainResolverPrepare(tunnel_t *resolver, tunnel_t *client, line_t *l,
                                       domainresolver_direction_t direction, void *user_lstate)
{
    discard resolver;
    discard direction;

    trojanclient_domain_resolver_lstate_t *ls = user_lstate;
    ls->protocol = kTrojanClientProtocolTcp;

    if (UNLIKELY(! trojanclientApplyTargetContext(client, l, &ls->protocol)))
    {
        return false;
    }

    return true;
}

#include "structure.h"

#include "loggers/network_logger.h"

void vlessclientTunnelUpStreamInit(tunnel_t *t, line_t *l)
{
    vlessclient_tstate_t   *ts       = tunnelGetState(t);
    vlessclient_lstate_t   *ls       = lineGetState(l, t);
    vlessclient_protocol_t  protocol = kVlessClientProtocolTcp;
    address_context_t *target = lineGetDestinationAddressContext(l);

    if (ts->resolve_domains)
    {
        vlessclient_domain_resolver_lstate_t *resolver_ls =
            domainresolverTunnelGetUserLineState(ts->domain_resolver_tunnel, l);
        protocol = resolver_ls->protocol;
    }
    else if (UNLIKELY(! vlessclientApplyTargetContext(t, l, &protocol)))
    {
        tunnelPrevDownStreamFinish(t, l);
        return;
    }

    vlessclientLinestateInitialize(ls, t, l);
    ls->protocol = protocol;
    ls->kind     = ls->protocol == kVlessClientProtocolUdp ? kVlessClientLineKindUdpApp : kVlessClientLineKindDirect;
    addresscontextAddrCopy(&ls->target_addr, target);
    addresscontextSetPort(&ls->target_addr, target->port);

    if (ts->verbose)
    {
        LOGD("VlessClient: line init protocol=%s port=%u",
             ls->protocol == kVlessClientProtocolTcp ? "tcp" : "udp",
             (unsigned int) target->port);
    }

    if (ls->protocol == kVlessClientProtocolUdp)
    {
        bool line_alive = true;
        if (UNLIKELY(! vlessclientStartUdpCarrier(t, l, ls, &line_alive)))
        {
            if (! line_alive)
            {
                return;
            }
            vlessclientLinestateDestroy(ls);
            tunnelPrevDownStreamFinish(t, l);
        }
        return;
    }

    tunnelNextUpStreamInit(t, l);
}

bool vlessclientDomainResolverPrepare(tunnel_t *resolver, tunnel_t *client, line_t *l,
                                      domainresolver_direction_t direction, void *user_lstate)
{
    discard resolver;
    discard direction;

    vlessclient_domain_resolver_lstate_t *ls = user_lstate;
    ls->protocol = kVlessClientProtocolTcp;

    if (UNLIKELY(! vlessclientApplyTargetContext(client, l, &ls->protocol)))
    {
        return false;
    }

    return true;
}

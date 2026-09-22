#include "structure.h"

#include "loggers/network_logger.h"

void vlessclientTunnelUpStreamInit(tunnel_t *t, line_t *l)
{
    vlessclient_tstate_t   *ts       = tunnelGetState(t);
    vlessclient_lstate_t   *ls       = lineGetState(l, t);
    address_context_t      *target   = lineGetDestinationAddressContext(l);

    /* With local DNS, the prepare hook already applied the target before resolution. */
    if (! ts->resolve_domains && UNLIKELY(! vlessclientApplyTargetContext(t, l)))
    {
        tunnelPrevDownStreamFinish(t, l);
        return;
    }
    assert(target->proto_tcp != target->proto_udp);

    vlessclientLinestateInitialize(ls, t, l);
    ls->protocol = target->proto_udp ? kVlessClientProtocolUdp : kVlessClientProtocolTcp;
    ls->kind     = ls->protocol == kVlessClientProtocolUdp ? kVlessClientLineKindUdpApp : kVlessClientLineKindDirect;
    addresscontextCopy(&ls->target_addr, target);

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

    discard user_lstate;
    return vlessclientApplyTargetContext(client, l);
}

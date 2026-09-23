#include "structure.h"

#include "loggers/network_logger.h"

void trojanclientTunnelUpStreamInit(tunnel_t *t, line_t *l)
{
    trojanclient_tstate_t *ts     = tunnelGetState(t);
    trojanclient_lstate_t *ls     = lineGetState(l, t);
    address_context_t     *target = lineGetDestinationAddressContext(l);

    /* With local DNS, the prepare hook already applied the target before resolution. */
    if (! ts->resolve_domains && UNLIKELY(! trojanclientApplyTargetContext(t, l)))
    {
        tunnelPrevDownStreamFinish(t, l);
        return;
    }
    assert(target->proto_tcp != target->proto_udp);

    trojanclientLinestateInitialize(ls, l);
    ls->tunnel   = t;
    ls->protocol = target->proto_udp ? kTrojanClientProtocolUdp : kTrojanClientProtocolTcp;
    ls->kind =
        ls->protocol == kTrojanClientProtocolUdp ? kTrojanClientLineKindUdpApplication : kTrojanClientLineKindDirect;
    addresscontextCopy(&ls->target_addr, target);

    if (ts->verbose)
    {
        LOGD("TrojanClient: line init protocol=%s port=%u",
             ls->protocol == kTrojanClientProtocolTcp ? "tcp" : "udp",
             (unsigned int) target->port);
    }

    if (ls->protocol == kTrojanClientProtocolUdp)
    {
        trojanclientStartUdpCarrier(t, l, ls);
        return;
    }

    ls->next_started = true;
    tunnelNextUpStreamInit(t, l);
}

bool trojanclientDomainResolverPrepare(tunnel_t *resolver, tunnel_t *client, line_t *l, void *user_lstate)
{
    discard resolver;

    discard user_lstate;
    return trojanclientApplyTargetContext(client, l);
}

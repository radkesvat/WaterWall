#include "internal.h"

#include "loggers/network_logger.h"

void trojanclientTunnelUpStreamInit(tunnel_t *t, line_t *l)
{
    trojanclient_tstate_t *ts     = tunnelGetState(t);
    trojanclient_lstate_t *ls     = lineGetState(l, t);
    address_context_t     *target = lineGetDestinationAddressContext(l);

    trojanclientLinestateInitialize(ls, l);
    ls->tunnel = t;
    if (UNLIKELY(! wloopNormalDispatchAllowed(getWorkerLoop(lineGetWID(l)))))
    {
        trojanclientLinestateDestroy(ls);
        tunnelPrevDownStreamFinish(t, l);
        return;
    }

    /* With local DNS, the prepare hook already applied the target before resolution. */
    if (! ts->resolve_domains && UNLIKELY(! trojanclientApplyTargetContext(t, l)))
    {
        trojanclientLinestateDestroy(ls);
        tunnelPrevDownStreamFinish(t, l);
        return;
    }
    assert(target->proto_tcp != target->proto_udp);

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

    tunnelNextUpStreamInit(t, l);
}

#include "structure.h"

#include "loggers/network_logger.h"

void trojanclientTunnelUpStreamInit(tunnel_t *t, line_t *l)
{
    trojanclient_tstate_t *ts = tunnelGetState(t);
    trojanclient_lstate_t *ls = lineGetState(l, t);

    trojanclientLinestateInitialize(ls, t, l);
    if (UNLIKELY(! trojanclientApplyTargetContext(t, l)))
    {
        trojanclientLinestateDestroy(ls);
        tunnelPrevDownStreamFinish(t, l);
        return;
    }

    ls->kind = ls->protocol == kTrojanClientProtocolUdp ? kTrojanClientLineKindUdpApp : kTrojanClientLineKindDirect;

    bool resolving = false;
    if (UNLIKELY(! trojanclientStartDomainResolveIfNeeded(t, l, ls, &resolving)))
    {
        trojanclientLinestateDestroy(ls);
        tunnelPrevDownStreamFinish(t, l);
        return;
    }

    if (resolving)
    {
        return;
    }

    if (ts->verbose)
    {
        address_context_t *target = lineGetDestinationAddressContext(l);
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

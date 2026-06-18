#include "structure.h"

#include "loggers/network_logger.h"

void vlessclientTunnelUpStreamInit(tunnel_t *t, line_t *l)
{
    vlessclient_tstate_t *ts = tunnelGetState(t);
    vlessclient_lstate_t *ls = lineGetState(l, t);

    vlessclientLinestateInitialize(ls, t, l);
    if (UNLIKELY(! vlessclientApplyTargetContext(t, l)))
    {
        vlessclientLinestateDestroy(ls);
        tunnelPrevDownStreamFinish(t, l);
        return;
    }

    ls->kind = ls->protocol == kVlessClientProtocolUdp ? kVlessClientLineKindUdpApp : kVlessClientLineKindDirect;

    bool resolving = false;
    if (UNLIKELY(! vlessclientStartDomainResolveIfNeeded(t, l, ls, &resolving)))
    {
        vlessclientLinestateDestroy(ls);
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

#include "structure.h"

#include "loggers/network_logger.h"

void trojanclientTunnelUpStreamInit(tunnel_t *t, line_t *l)
{
    trojanclient_tstate_t *ts = tunnelGetState(t);
    trojanclient_lstate_t *ls = lineGetState(l, t);
    trojanclient_domain_setup_lstate_t *setup_ls = lineGetState(l, ts->domain_setup_tunnel);
    address_context_t *target = lineGetDestinationAddressContext(l);

    trojanclientLinestateInitialize(ls, t, l);
    ls->protocol = setup_ls->protocol;
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

void trojanclientDomainSetupTunnelUpStreamInit(tunnel_t *t, line_t *l)
{
    trojanclient_domain_setup_tstate_t *setup_ts = tunnelGetState(t);
    tunnel_t                           *client   = setup_ts->client_tunnel;
    trojanclient_domain_setup_lstate_t *ls       = lineGetState(l, t);

    trojanclientDomainSetupLinestateInitialize(ls);

    if (UNLIKELY(! trojanclientApplyTargetContext(client, l)))
    {
        trojanclientDomainSetupLinestateDestroy(ls);
        tunnelPrevDownStreamFinish(t, l);
        return;
    }

    tunnelNextUpStreamInit(t, l);
}

#include "structure.h"

#include "loggers/network_logger.h"

void vlessclientTunnelUpStreamInit(tunnel_t *t, line_t *l)
{
    vlessclient_tstate_t *ts = tunnelGetState(t);
    vlessclient_lstate_t *ls = lineGetState(l, t);
    vlessclient_domain_setup_lstate_t *setup_ls = lineGetState(l, ts->domain_setup_tunnel);
    address_context_t *target = lineGetDestinationAddressContext(l);

    vlessclientLinestateInitialize(ls, t, l);
    ls->protocol = setup_ls->protocol;
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

void vlessclientDomainSetupTunnelUpStreamInit(tunnel_t *t, line_t *l)
{
    vlessclient_domain_setup_tstate_t *setup_ts = tunnelGetState(t);
    tunnel_t                          *client   = setup_ts->client_tunnel;
    vlessclient_domain_setup_lstate_t *ls       = lineGetState(l, t);

    vlessclientDomainSetupLinestateInitialize(ls);

    if (UNLIKELY(! vlessclientApplyTargetContext(client, l)))
    {
        vlessclientDomainSetupLinestateDestroy(ls);
        tunnelPrevDownStreamFinish(t, l);
        return;
    }

    tunnelNextUpStreamInit(t, l);
}

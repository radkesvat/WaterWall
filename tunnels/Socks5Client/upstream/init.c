#include "structure.h"

#include "loggers/network_logger.h"

void socks5clientTunnelUpStreamInit(tunnel_t *t, line_t *l)
{
    socks5client_tstate_t *ts = tunnelGetState(t);
    socks5client_lstate_t *ls = lineGetState(l, t);
    socks5client_domain_setup_lstate_t *setup_ls = lineGetState(l, ts->domain_setup_tunnel);
    address_context_t *target = lineGetDestinationAddressContext(l);

    socks5clientLinestateInitialize(ls, t, l);
    ls->protocol = setup_ls->protocol;
    ls->kind     = ls->protocol == kSocks5ClientProtocolUdp ? kSocks5ClientLineKindUdpApp : kSocks5ClientLineKindDirect;
    addresscontextAddrCopy(&ls->target_addr, target);
    addresscontextSetPort(&ls->target_addr, target->port);

    if (ts->verbose)
    {
        LOGD("Socks5Client: line init protocol=%s port=%u auth=%s",
             ls->protocol == kSocks5ClientProtocolTcp ? "tcp" : "udp",
             (unsigned int) target->port,
             ts->username != NULL ? "username/password" : "none");
    }

    if (ls->protocol == kSocks5ClientProtocolUdp)
    {
        bool line_alive = true;
        if (! socks5clientStartUdpAssociation(t, l, ls, &line_alive))
        {
            if (! line_alive)
            {
                return;
            }
            socks5clientLinestateDestroy(ls);
            tunnelPrevDownStreamFinish(t, l);
        }
        if (! line_alive)
        {
            return;
        }
        return;
    }

    tunnelNextUpStreamInit(t, l);
}

void socks5clientDomainSetupTunnelUpStreamInit(tunnel_t *t, line_t *l)
{
    socks5client_domain_setup_tstate_t *setup_ts = tunnelGetState(t);
    tunnel_t                           *client   = setup_ts->client_tunnel;
    socks5client_domain_setup_lstate_t *ls       = lineGetState(l, t);

    socks5clientDomainSetupLinestateInitialize(ls);

    if (UNLIKELY(! socks5clientApplyTargetContext(client, l)))
    {
        socks5clientDomainSetupLinestateDestroy(ls);
        tunnelPrevDownStreamFinish(t, l);
        return;
    }

    tunnelNextUpStreamInit(t, l);
}

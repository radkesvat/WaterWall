#include "structure.h"

#include "loggers/network_logger.h"

void socks5clientTunnelUpStreamInit(tunnel_t *t, line_t *l)
{
    socks5client_tstate_t   *ts       = tunnelGetState(t);
    socks5client_lstate_t   *ls       = lineGetState(l, t);
    socks5client_protocol_t  protocol = kSocks5ClientProtocolTcp;
    address_context_t *target = lineGetDestinationAddressContext(l);

    if (ts->resolve_domains)
    {
        socks5client_domain_resolver_lstate_t *resolver_ls =
            domainresolverTunnelGetUserLineState(ts->domain_resolver_tunnel, l);
        protocol = resolver_ls->protocol;
    }
    else if (! socks5clientApplyTargetContext(t, l, &protocol))
    {
        tunnelPrevDownStreamFinish(t, l);
        return;
    }

    socks5clientLinestateInitialize(ls, t, l);
    ls->protocol = protocol;
    ls->kind     = ls->protocol == kSocks5ClientProtocolUdp ? kSocks5ClientLineKindUdpApp : kSocks5ClientLineKindDirect;
    addresscontextCopy(&ls->target_addr, target);

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

bool socks5clientDomainResolverPrepare(tunnel_t *resolver, tunnel_t *client, line_t *l,
                                       domainresolver_direction_t direction, void *user_lstate)
{
    discard resolver;
    discard direction;

    socks5client_domain_resolver_lstate_t *ls = user_lstate;
    ls->protocol = kSocks5ClientProtocolTcp;

    if (UNLIKELY(! socks5clientApplyTargetContext(client, l, &ls->protocol)))
    {
        return false;
    }

    return true;
}

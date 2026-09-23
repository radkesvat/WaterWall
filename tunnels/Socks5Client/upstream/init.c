#include "structure.h"

#include "loggers/network_logger.h"

void socks5clientTunnelUpStreamInit(tunnel_t *t, line_t *l)
{
    socks5client_tstate_t   *ts       = tunnelGetState(t);
    socks5client_lstate_t   *ls       = lineGetState(l, t);
    address_context_t       *target   = lineGetDestinationAddressContext(l);

    /* With local DNS, the prepare hook already applied the target before resolution. */
    if (! ts->resolve_domains && UNLIKELY(! socks5clientApplyTargetContext(t, l)))
    {
        tunnelPrevDownStreamFinish(t, l);
        return;
    }
    assert(target->proto_tcp != target->proto_udp);

    socks5clientLinestateInitialize(ls, t, l);
    ls->protocol = target->proto_udp ? kSocks5ClientProtocolUdp : kSocks5ClientProtocolTcp;
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

bool socks5clientDomainResolverPrepare(tunnel_t *resolver, tunnel_t *client, line_t *l, void *user_lstate)
{
    discard resolver;

    discard user_lstate;
    return socks5clientApplyTargetContext(client, l);
}

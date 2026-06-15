#include "structure.h"

#include "loggers/network_logger.h"

void socks5clientTunnelUpStreamInit(tunnel_t *t, line_t *l)
{
    socks5client_tstate_t *ts = tunnelGetState(t);
    socks5client_lstate_t *ls = lineGetState(l, t);

    socks5clientLinestateInitialize(ls, t, l);
    ls->kind = ts->protocol == kSocks5ClientProtocolUdp ? kSocks5ClientLineKindUdpApp : kSocks5ClientLineKindDirect;
    if (! socks5clientApplyTargetContext(t, l))
    {
        socks5clientLinestateDestroy(ls);
        tunnelPrevDownStreamFinish(t, l);
        return;
    }

    if (ts->verbose)
    {
        address_context_t *target = lineGetDestinationAddressContext(l);
        LOGD("Socks5Client: line init protocol=%s port=%u auth=%s",
             ts->protocol == kSocks5ClientProtocolTcp ? "tcp" : "udp",
             (unsigned int) target->port,
             ts->username != NULL ? "username/password" : "none");
    }

    if (ts->protocol == kSocks5ClientProtocolUdp)
    {
        if (! socks5clientStartUdpAssociation(t, l, ls))
        {
            socks5clientLinestateDestroy(ls);
            tunnelPrevDownStreamFinish(t, l);
        }
        return;
    }

    tunnelNextUpStreamInit(t, l);
}

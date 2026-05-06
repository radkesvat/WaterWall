#include "structure.h"

#include "loggers/network_logger.h"

static bool udpconnectorPayloadSockAddrEquals(const sockaddr_u *lhs, const sockaddr_u *rhs)
{
    if (lhs == NULL || rhs == NULL || lhs->sa.sa_family != rhs->sa.sa_family)
    {
        return false;
    }

    switch (lhs->sa.sa_family)
    {
    case AF_INET:
        return lhs->sin.sin_port == rhs->sin.sin_port && lhs->sin.sin_addr.s_addr == rhs->sin.sin_addr.s_addr;
    case AF_INET6:
        return lhs->sin6.sin6_port == rhs->sin6.sin6_port &&
               memoryCompare(lhs->sin6.sin6_addr.s6_addr, rhs->sin6.sin6_addr.s6_addr,
                             sizeof(lhs->sin6.sin6_addr.s6_addr)) == 0;
    default:
        return false;
    }
}

void udpconnectorTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    udpconnector_tstate_t *ts = tunnelGetState(t);
    udpconnector_lstate_t *ls = lineGetState(l, t);

    wio_t *io = ls->io;
    if (UNLIKELY(wioIsClosed(io)))
    {
        // should not happen in our structure
        LOGF("UdpConnector: UpStream Payload is called on closed wio. This should not happen");
        lineReuseBuffer(l, buf);
        // tunnelPrevDownStreamFinish(t, l);
        assert(false);
        terminateProgram(1);
    }
    // LOGD("writing %d bytes", sbufGetLength(buf));

    idletableKeepIdleItemForAtleast(ts->idle_table, ls->idle_handle, kUdpKeepExpireTime);

    // recvfrom() mutates io->peeraddr, so refresh the selected remote peer before every send.
    if (! udpconnectorPayloadSockAddrEquals(wioGetPeerAddrU(io), &ls->peer_addr))
    {
        wioSetPeerAddr(io, &ls->peer_addr.sa, sockaddrLen(&ls->peer_addr));
    }

    wioWrite(io, buf);
}

#include "structure.h"

#include "loggers/network_logger.h"

static bool udpstatelesssocketSockAddrEquals(const sockaddr_u *lhs, const sockaddr_u *rhs)
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

static sockaddr_u udpstatelesssocketSockAddrFromContext(const address_context_t *context)
{
    sockaddr_u addr = {0};

    assert(context != NULL);
    assert(addresscontextCanConvertToSockAddr(context));

    if (addresscontextIsIpv4(context))
    {
        addr.sin.sin_family      = AF_INET;
        addr.sin.sin_port        = htons(context->port);
        addr.sin.sin_addr.s_addr = context->ip_address.u_addr.ip4.addr;
        return addr;
    }

    if (addresscontextIsIpv6(context))
    {
        addr.sin6.sin6_family = AF_INET6;
        addr.sin6.sin6_port   = htons(context->port);
        memoryCopy(&addr.sin6.sin6_addr.s6_addr, &context->ip_address.u_addr.ip6, sizeof(addr.sin6.sin6_addr.s6_addr));
        return addr;
    }

    assert(false);
    return addr;
}

static bool udpstatelesssocketGetLinePeerAddr(line_t *l, sockaddr_u *addr_out)
{
    address_context_t *dest_ctx = lineGetDestinationAddressContext(l);

    if (! addresscontextCanConvertToSockAddr(dest_ctx) || ! addresscontextHasPort(dest_ctx))
    {
        return false;
    }

    *addr_out = udpstatelesssocketSockAddrFromContext(dest_ctx);
    return true;
}

static void udpstatelesssocketWriteOwnerPeer(tunnel_t *t, sbuf_t *buf)
{
    udpstatelesssocket_tstate_t *state = tunnelGetState(t);

    assert(getWID() == state->io_wid);

    if (state->cached_peer_valid)
    {
        if (! udpstatelesssocketSockAddrEquals(wioGetPeerAddrU(state->io), &state->cached_peer_addr))
        {
            wioSetPeerAddr(state->io, &state->cached_peer_addr.sa, (int) sockaddrLen(&state->cached_peer_addr));
        }
    }
    else if (wioGetPeerAddrU(state->io)->sa.sa_family == 0)
    {
        LOGE("UdpStatelessSocket: no owner-worker peer is available for this UDP send");
        bufferpoolReuseBuffer(getWorkerBufferPool(getWID()), buf);
        return;
    }

    wioWrite(state->io, buf);
}

void udpstatelesssocketOnRecvFrom(wio_t *io, sbuf_t *buf)
{
    tunnel_t *t   = (tunnel_t *) (weventGetUserdata(io));
    wid_t     wid = wloopGetWid(weventGetLoop(io));
    udpstatelesssocket_tstate_t *state;

    if (UNLIKELY(t == NULL))
    {
        assert(false);
        bufferpoolReuseBuffer(getWorkerBufferPool(wid), buf);
        return;
    }

    if (wioGetPeerAddrU(io)->sa.sa_family == 0)
    {
        assert(false);
        bufferpoolReuseBuffer(getWorkerBufferPool(wid), buf);
        return;
    }

    state = tunnelGetState(t);

    if (UNLIKELY(wid != state->io_wid))
    {
        assert(false);
        bufferpoolReuseBuffer(getWorkerBufferPool(wid), buf);
        return;
    }

    line_t *l = tunnelchainGetWorkerPacketLine(tunnelGetChain(t), state->io_wid);

    char localaddrstr[SOCKADDR_STRLEN] = {0};
    char peeraddrstr[SOCKADDR_STRLEN]  = {0};

    LOGD("UdpStatelessSocket: received %u bytes from [%s] <= [%s]",
         sbufGetLength(buf),
         SOCKADDR_STR(wioGetLocaladdrU(io), localaddrstr),
         SOCKADDR_STR(wioGetPeerAddrU(io), peeraddrstr));

    addresscontextFromSockAddrWithProtocol(&l->routing_context.src_ctx, wioGetPeerAddrU(io), IP_PROTO_UDP);
    l->routing_context.local_listener_port = sockaddrPort(wioGetLocaladdrU(io));

#ifdef DEBUG
    lineLock(l);
#endif

    state->WriteReceivedPacket(state->write_tunnel, l, buf);

#ifdef DEBUG
    if (! lineIsAlive(l))
    {
        LOGF("UdpStatelessSocket: line is not alive, rule of packet tunnels is violated");
        terminateProgram(1);
    }

    lineUnlock(l);
#endif
}

void udpstatelesssocketLocalThreadSocketUpStream(void *worker, void *arg1, void *arg2, void *arg3)
{
    discard worker;
    discard arg3;

    tunnel_t *t   = (tunnel_t *) arg1;
    sbuf_t   *buf = (sbuf_t *) arg2;

    udpstatelesssocketWriteOwnerPeer(t, buf);
}

void udpstatelesssocketTunnelWritePayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    udpstatelesssocket_tstate_t *state = tunnelGetState(t);

    if (lineGetWID(l) == state->io_wid)
    {
        sockaddr_u addr;

        if (! udpstatelesssocketGetLinePeerAddr(l, &addr))
        {
            LOGE("UdpStatelessSocket: outbound destination address is not ready");
            lineReuseBuffer(l, buf);
            return;
        }

        {
            char peeraddrstr[SOCKADDR_STRLEN] = {0};
            LOGD("UdpStatelessSocket: %u bytes Packet to => [%s]", sbufGetLength(buf), SOCKADDR_STR(&addr, peeraddrstr));
        }

        state->cached_peer_addr   = addr;
        state->cached_peer_valid  = true;
        udpstatelesssocketWriteOwnerPeer(t, buf);
        return;
    }

    sendWorkerMessage(state->io_wid, udpstatelesssocketLocalThreadSocketUpStream, t, buf, NULL);
}

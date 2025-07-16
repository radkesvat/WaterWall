#include "structure.h"

#include "loggers/network_logger.h"

void udpstatelesssocketOnRecvFrom(wio_t *io, sbuf_t *buf)
{
    tunnel_t *t   = (tunnel_t *) (weventGetUserdata(io));
    wid_t     wid = wloopGetWid(weventGetLoop(io));

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

    line_t *l = tunnelchainGetPacketLine(tunnelGetChain(t), wid);

    char localaddrstr[SOCKADDR_STRLEN] = {0};
    char peeraddrstr[SOCKADDR_STRLEN]  = {0};

    LOGD("UdpStatelessSocket: received %u bytes from [%s] <= [%s]", sbufGetLength(buf),
         SOCKADDR_STR(wioGetLocaladdrU(io), localaddrstr), SOCKADDR_STR(wioGetPeerAddrU(io), peeraddrstr));

    addresscontextFromSockAddr(&l->routing_context.src_ctx, wioGetPeerAddrU(io));

#ifdef DEBUG
    lineLock(l);
#endif


    udpstatelesssocket_tstate_t *state = tunnelGetState(t);
    state->WriteReceivedPacket(t, l, buf);

#ifdef DEBUG
    if (! lineIsAlive(l))
    {
        LOGF("UdpStatelessSocket: line is not alive, rule of packet tunnels is violated");
        terminateProgram(1);
    }

    lineUnlock(l);
#endif
}

void UdpStatelessLocalThreadSocketUpStream(struct worker_s *worker, void *arg1, void *arg2, void *arg3)
{
    discard worker;
    tunnel_t *t   = arg1;
    line_t   *l   = arg2;
    sbuf_t   *buf = arg3;
    udpstatelesssocket_tstate_t *state = tunnelGetState(t);

    if (addresscontextIsValid(&(l->routing_context.dest_ctx)) == false)
    {
        LOGE("udpstatelesssocketTunnelUpStreamPayload: address not initialized");
        bufferpoolReuseBuffer(getWorkerBufferPool(lineGetWID(l)), buf);
        return;
    }

    sockaddr_u addr = addresscontextToSockAddr(&(l->routing_context.dest_ctx));

    {
        char peeraddrstr[SOCKADDR_STRLEN] = {0};
        LOGD("UdpStatelessSocket: %u bytes Packet to => [%s]", sbufGetLength(buf), SOCKADDR_STR(&addr, peeraddrstr));
    }
    // tunnelPrevDownStreamPayload(t, l, buf);

    wioSetPeerAddr(state->io, &(addr.sa), (int) sockaddrLen(&addr));

    wioWrite(state->io, buf);
}

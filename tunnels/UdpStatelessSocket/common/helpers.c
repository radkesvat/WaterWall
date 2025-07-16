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

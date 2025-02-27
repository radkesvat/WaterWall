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

    line_t *line      = tunnelchainGetPacketLine(tunnelGetChain(t), wid);
    line->established = true;

    char localaddrstr[SOCKADDR_STRLEN] = {0};
    char peeraddrstr[SOCKADDR_STRLEN]  = {0};

    LOGD("UdpStatelessSocket: received %u bytes from [%s] <= [%s]", sbufGetLength(buf),
         SOCKADDR_STR(wioGetLocaladdrU(io), localaddrstr), SOCKADDR_STR(wioGetPeerAddrU(io), peeraddrstr));

    addresscontextFromSockAddr(&line->routing_context.src_ctx, wioGetPeerAddrU(io));

    lineLock(line);
    tunnelPrevDownStreamPayload(t, line, buf);

    if (! lineIsAlive(line))
    {
        LOGF("UdpStatelessSocket: line is not alive, rule of packet tunnels is violated");
        exit(1);
    }
    lineUnlock(line);
}

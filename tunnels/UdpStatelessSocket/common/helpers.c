#include "structure.h"

#include "loggers/network_logger.h"

void udpstatelesssocketOnRecvFrom(wio_t *io, sbuf_t *buf)
{
    tunnel_t *t = (tunnel_t *) (weventGetUserdata(io));
    if (UNLIKELY(t == NULL))
    {
        assert(false);
        bufferpoolReuseBuffer(getWorkerBufferPool(getWID()), buf);
        return;
    }

    if(wioGetPeerAddrU(io)->sa.sa_family == 0)
    {
        assert(false);
        bufferpoolReuseBuffer(getWorkerBufferPool(getWID()), buf);
        return;
    }

    line_t *line      = tunnelchainGetPacketLine(tunnelGetChain(t), getWID());
    line->established = true;
 
    char localaddrstr[SOCKADDR_STRLEN] = {0};
    char peeraddrstr[SOCKADDR_STRLEN]  = {0};

    LOGD("UdpStatelessSocket: received %u bytes from [%s] <= [%s]", sbufGetBufLength(buf),
         SOCKADDR_STR(wioGetLocaladdrU(io), localaddrstr), SOCKADDR_STR(wioGetPeerAddrU(io), peeraddrstr));
   
    line->routing_context.src_ctx = addresscontextFromSockAddr(wioGetPeerAddrU(io));

    lineLock(line);
    tunnelPrevDownStreamPayload(t, line, buf);

    if (! lineIsAlive(line))
    {
        LOGF("UdpStatelessSocket: line is not alive, rule of packet tunnels is violated");
        exit(1);
    }
    lineUnlock(line);
}

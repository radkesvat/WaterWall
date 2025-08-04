#include "structure.h"

#include "loggers/network_logger.h"

void udpconnectorTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    udpconnector_tstate_t *ts = tunnelGetState(t);
    udpconnector_lstate_t *ls = lineGetState(l, t);

    wio_t *io = ls->io;
    if (UNLIKELY(wioIsClosed(io)))
    {
        // should not happen in our structure
        LOGF("UdpConnector: UpStream Payload is called on closed wio. This should not happen");
        bufferpoolReuseBuffer(lineGetBufferPool(l), buf);
        // tunnelPrevDownStreamFinish(t, l);
        assert(false);
        terminateProgram(1);
    }
    // LOGD("writing %d bytes", sbufGetLength(buf));


    // this code is not required, cuz we dont change the destination address of the UDP socket
    // address_context_t *dest_ctx = lineGetDestinationAddressContext(l);
    // sockaddr_u addr = addresscontextToSockAddr(dest_ctx);
    // wioSetPeerAddr(ls->io, &addr.sa, sockaddrLen(&addr));
   
    idletableKeepIdleItemForAtleast(ts->idle_table, ls->idle_handle, kUdpKeepExpireTime);
    
    wioWrite(io, buf);
}

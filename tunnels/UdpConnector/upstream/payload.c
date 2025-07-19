#include "structure.h"

#include "loggers/network_logger.h"

void udpconnectorTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
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

    wioWrite(io, buf);
}

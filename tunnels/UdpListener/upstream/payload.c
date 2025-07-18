#include "structure.h"

#include "loggers/network_logger.h"

void udplistenerTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    discard t;
    discard l;
    discard buf;
    LOGF("UdpListener: upStreamPayload disabled");
    bufferpoolReuseBuffer(lineGetBufferPool(l), buf);
    terminateProgram(1);
}

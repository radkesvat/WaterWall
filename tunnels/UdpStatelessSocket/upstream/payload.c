#include "structure.h"

#include "loggers/network_logger.h"

static inline void localThreadUdpStatelessSocketUpStream(struct worker_s *worker, void *arg1, void *arg2, void *arg3)
{
    (void) worker;
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

    sockaddr_u addr = connectioncontextToSockAddr(&(l->routing_context.dest_ctx));

    {
        char peeraddrstr[SOCKADDR_STRLEN] = {0};
        LOGD("UdpStatelessSocket: %u bytes Packet to => [%s]", sbufGetBufLength(buf), SOCKADDR_STR(&addr, peeraddrstr));
    }
    // tunnelPrevDownStreamPayload(t, l, buf);

    wioSetPeerAddr(state->io, &(addr.sa), (int) sockaddrLen(&addr));

    wioWrite(state->io, buf);
}

void udpstatelesssocketTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{

    udpstatelesssocket_tstate_t *state = tunnelGetState(t);

    if (lineGetWID(l) != state->io_wid)
    {
        sendWorkerMessage(state->io_wid, localThreadUdpStatelessSocketUpStream, t, l, buf);
    }
    else
    {
        localThreadUdpStatelessSocketUpStream(NULL, t, l, buf);
    }
}

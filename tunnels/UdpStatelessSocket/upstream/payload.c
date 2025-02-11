#include "structure.h"

#include "loggers/network_logger.h"

void udpstatelesssocketTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{

    udpstatelesssocket_tstate_t *state = tunnelGetState(t);
    mutexLock(&state->mutex);

    if (addresscontextIsValid(&(l->routing_context.dest_ctx)) == false)
    {
        LOGE("udpstatelesssocketTunnelUpStreamPayload: address not initialized");
        bufferpoolReuseBuffer(getWorkerBufferPool(lineGetWID(l)), buf);
        goto normalexit;
    }

    sockaddr_u addr = addresscontextToSockAddr(&(l->routing_context.dest_ctx));

    {
        char peeraddrstr[SOCKADDR_STRLEN] = {0};
        LOGD("UdpStatelessSocket: %u bytes Packet to => [%s]", sbufGetBufLength(buf), SOCKADDR_STR(&addr, peeraddrstr));
    }

    (void) state;
    // tunnelPrevDownStreamPayload(t, l, buf);

    wioSetPeerAddr(state->io, &(addr.sa), (int) sockaddrLen(&addr));
    wioWrite(state->io, buf);

normalexit:
    mutexUnlock(&state->mutex);
}

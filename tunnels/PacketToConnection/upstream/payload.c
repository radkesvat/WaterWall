#include "structure.h"

#include "loggers/network_logger.h"

void ptcTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{

    ptc_tstate_t *state = tunnelGetState(t);


    struct pbuf *p = pbufAlloc(PBUF_RAW, sbufGetBufLength(buf), PBUF_REF);

    p->payload = &buf->buf[0];
    // LOCK_TCPIP_CORE();
    state->netif.input(p, &state->netif);
    // UNLOCK_TCPIP_CORE();

    // since PBUF_REF is used, lwip wont delay this buffer after call stack, if it needs queue then it will be duplicated
    // so we can free it now
    bufferpoolReuseBuffer(getWorkerBufferPool(lineGetWID(l)), buf);
}

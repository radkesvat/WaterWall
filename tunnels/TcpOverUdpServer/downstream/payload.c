#include "structure.h"

void tcpoverudpserverTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    tcpoverudpserver_lstate_t *ls = lineGetState(l, t);
    assert(ls->kind == kTcpOverUdpServerService && ls->session != NULL);
    if (! ls->carrier->active)
    {
        bufferpoolReuseBuffer(ls->carrier->pool, buf);
        return;
    }
    /* The common driver admits the complete input before pressure/output callbacks can reenter. */
    touSessionSend(ls->session->engine, buf);
}

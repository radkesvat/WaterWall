#include "structure.h"

void kcpserverTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    kcpserver_lstate_t *ls = lineGetState(l, t);
    assert(ls->kind == kKcpServerCarrier && ls->carrier != NULL);
    kcpserverCarrierInput(ls->carrier, buf);
}

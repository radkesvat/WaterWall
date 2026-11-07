#include "structure.h"

void kcpserverTunnelUpStreamFinish(tunnel_t *t, line_t *l)
{
    kcpserver_lstate_t *ls = lineGetState(l, t);
    assert(ls->kind == kKcpServerCarrier && ls->carrier != NULL);
    /* Never reflect Finish toward the borrowed carrier's owner. */
    kcpserverCarrierClose(ls->carrier, false);
}

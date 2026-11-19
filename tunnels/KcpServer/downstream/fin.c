#include "structure.h"

void kcpserverTunnelDownStreamFinish(tunnel_t *t, line_t *l)
{
    kcpserver_lstate_t *ls = lineGetState(l, t);
    assert(ls->kind == kKcpServerService && ls->session != NULL);
    kcpserverFinishService(ls->session);
}

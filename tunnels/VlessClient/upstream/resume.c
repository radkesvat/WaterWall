#include "internal.h"

void vlessclientTunnelUpStreamResume(tunnel_t *t, line_t *l)
{
    vlessclient_lstate_t *ls = lineGetState(l, t);
    if (ls->phase == kVlessClientPhaseClosed)
        return;
    line_t *next = ls->kind == kVlessClientLineKindUdpApplication ? ls->carrier_line : l;
    tunnelNextUpStreamResume(t, next);
}

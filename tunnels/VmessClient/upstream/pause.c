#include "internal.h"

void vmessclientTunnelUpStreamPause(tunnel_t *t, line_t *l)
{
    vmessclient_lstate_t *ls = lineGetState(l, t);
    if (ls->phase == kVmessClientPhaseClosed)
        return;
    line_t *next = ls->kind == kVmessClientLineKindUdpApplication ? ls->carrier_line : l;
    tunnelNextUpStreamPause(t, next);
}

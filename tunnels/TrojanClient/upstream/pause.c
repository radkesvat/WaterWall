#include "internal.h"

void trojanclientTunnelUpStreamPause(tunnel_t *t, line_t *l)
{
    trojanclient_lstate_t *ls = lineGetState(l, t);
    if (ls->phase == kTrojanClientPhaseClosed)
        return;
    line_t *next = ls->kind == kTrojanClientLineKindUdpApplication ? ls->carrier_line : l;
    tunnelNextUpStreamPause(t, next);
}

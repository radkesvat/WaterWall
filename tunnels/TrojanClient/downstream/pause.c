#include "structure.h"

void trojanclientTunnelDownStreamPause(tunnel_t *t, line_t *l)
{
    trojanclient_lstate_t *ls = lineGetState(l, t);
    if (ls->phase == kTrojanClientPhaseClosed || ls->kind == kTrojanClientLineKindUdpApp)
        return;
    ls->next_paused = true;
    trojanclientPump(t, l);
}

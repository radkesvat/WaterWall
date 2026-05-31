#include "structure.h"

void sniffrouterTunnelDownStreamInit(tunnel_t *t, line_t *l)
{
    sniffrouter_lstate_t *ls = lineGetState(l, t);

    if (ls->prev_finished || ls->next_finished)
    {
        return;
    }

    tunnelPrevDownStreamInit(t, l);
}

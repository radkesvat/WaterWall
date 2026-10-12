#include "structure.h"

void realityclientTunnelDownStreamResume(tunnel_t *t, line_t *l)
{
    realityclient_lstate_t *ls = lineGetState(l, t);
    if (ls->terminal_closing || ls->prev_finished)
    {
        return;
    }
    tunnelPrevDownStreamResume(t, l);
}

#include "structure.h"

void realityclientTunnelUpStreamResume(tunnel_t *t, line_t *l)
{
    realityclient_lstate_t *ls = lineGetState(l, t);
    if (ls->terminal_closing || ls->next_finished)
    {
        return;
    }
    tunnelNextUpStreamResume(t, l);
}

#include "structure.h"

void realityclientTunnelUpStreamPause(tunnel_t *t, line_t *l)
{
    realityclient_lstate_t *ls = lineGetState(l, t);
    if (ls->terminal_closing || ls->next_finished)
    {
        return;
    }
    tunnelNextUpStreamPause(t, l);
}

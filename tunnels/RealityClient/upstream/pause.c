#include "structure.h"

void realityclientTunnelUpStreamPause(tunnel_t *t, line_t *l)
{
    realityclient_lstate_t *ls = lineGetState(l, t);
    if (! ls->next_finished)
    {
        tunnelNextUpStreamPause(t, l);
    }
}

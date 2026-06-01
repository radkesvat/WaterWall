#include "structure.h"

void realityclientTunnelUpStreamResume(tunnel_t *t, line_t *l)
{
    realityclient_lstate_t *ls = lineGetState(l, t);
    if (! ls->next_finished)
    {
        tunnelNextUpStreamResume(t, l);
    }
}

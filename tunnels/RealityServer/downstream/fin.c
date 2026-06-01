#include "structure.h"

void realityserverTunnelDownStreamFinish(tunnel_t *t, line_t *l)
{
    realityserver_lstate_t *ls = lineGetState(l, t);
    if (ls->closing_destination_for_authorized)
    {
        return;
    }

    realityserverLinestateDestroy(ls);

    tunnelPrevDownStreamFinish(t, l);
}

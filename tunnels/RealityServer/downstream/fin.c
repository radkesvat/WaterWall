#include "structure.h"

void realityserverTunnelDownStreamFinish(tunnel_t *t, line_t *l)
{
    realityserver_lstate_t *ls = lineGetState(l, t);
    if (ls->closing_destination_for_authorized)
    {
        return;
    }

    lineLock(l);

    ls = lineGetState(l, t);
    bool send_prev = ! ls->prev_finished;

    ls->prev_finished = true;
    realityserverLinestateDestroy(ls);

    if (send_prev)
    {
        tunnelPrevDownStreamFinish(t, l);
    }

    lineUnlock(l);
}

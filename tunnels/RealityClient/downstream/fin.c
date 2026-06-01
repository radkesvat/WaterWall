#include "structure.h"

void realityclientTunnelDownStreamFinish(tunnel_t *t, line_t *l)
{
    lineLock(l);

    realityclient_lstate_t *ls        = lineGetState(l, t);
    bool                    send_prev = ! ls->prev_finished;

    ls->prev_finished = true;
    realityclientLinestateDestroy(ls);

    if (send_prev)
    {
        tunnelPrevDownStreamFinish(t, l);
    }

    lineUnlock(l);
}

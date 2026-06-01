#include "structure.h"

void realityclientTunnelUpStreamFinish(tunnel_t *t, line_t *l)
{
    lineLock(l);

    realityclient_lstate_t *ls        = lineGetState(l, t);
    bool                    send_next = ! ls->next_finished;

    ls->next_finished = true;
    realityclientLinestateDestroy(ls);

    if (send_next)
    {
        tunnelNextUpStreamFinish(t, l);
    }

    lineUnlock(l);
}

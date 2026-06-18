#include "structure.h"

void routerTunnelDownStreamFinish(tunnel_t *t, line_t *l)
{
    router_lstate_t *ls = lineGetState(l, t);

    if (ls->next_finished)
    {
        return;
    }

    /*
     * The selected branch is closing. Mark both sides and clear our line state
     * before forwarding to prev, because that path reaches the line-owning
     * adapter and may destroy the line before returning.
     */
    ls->next_finished = true;
    ls->prev_finished = true;

    lineLock(l);
    routerLinestateDestroy(l, ls);
    tunnelPrevDownStreamFinish(t, l);
    lineUnlock(l);
}

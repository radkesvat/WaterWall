#include "structure.h"

void sniffrouterTunnelDownStreamFinish(tunnel_t *t, line_t *l)
{
    sniffrouter_lstate_t *ls = lineGetState(l, t);

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
    sniffrouterLinestateDestroy(l, ls);
    tunnelPrevDownStreamFinish(t, l);
    lineUnlock(l);
}

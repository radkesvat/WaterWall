#include "structure.h"

void sniffrouterTunnelDownStreamFinish(tunnel_t *t, line_t *l)
{
    sniffrouter_lstate_t *ls = lineGetState(l, t);

    /*
     * The selected branch is closing. Clear our line state before forwarding to
     * prev, because that path reaches the line-owning adapter and may destroy
     * the line before returning.
     */
    lineLock(l);
    sniffrouterLinestateDestroy(l, ls);
    tunnelPrevDownStreamFinish(t, l);
    lineUnlock(l);
}

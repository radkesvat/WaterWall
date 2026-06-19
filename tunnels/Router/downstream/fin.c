#include "structure.h"

void routerTunnelDownStreamFinish(tunnel_t *t, line_t *l)
{
    router_lstate_t *ls = lineGetState(l, t);

    /*
     * The selected branch is closing. Clear our line state before forwarding to
     * prev, because that path reaches the line-owning adapter and may destroy
     * the line before returning.
     */
    lineLock(l);
    routerLinestateDestroy(l, ls);
    tunnelPrevDownStreamFinish(t, l);
    lineUnlock(l);
}

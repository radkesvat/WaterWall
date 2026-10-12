#include "structure.h"

void reverseclientTunnelDownStreamPause(tunnel_t *t, line_t *l)
{
    reverseclient_pair_t *pair = ((reverseclient_lstate_t *) lineGetState(l, t))->pair;
    if (! pair->downstream_init_sent)
    {
        pair->pending_downstream_pause = true;
        return;
    }
    pair->pending_downstream_pause = false;
    tunnelPrevDownStreamPause(t, pair->d);
}

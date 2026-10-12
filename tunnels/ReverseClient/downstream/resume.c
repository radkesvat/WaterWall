#include "structure.h"

void reverseclientTunnelDownStreamResume(tunnel_t *t, line_t *l)
{
    reverseclient_pair_t *pair = ((reverseclient_lstate_t *) lineGetState(l, t))->pair;
    pair->pending_downstream_pause = false;
    if (pair->downstream_init_sent)
    {
        tunnelPrevDownStreamResume(t, pair->d);
    }
}

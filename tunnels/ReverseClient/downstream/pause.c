#include "structure.h"

void reverseclientTunnelDownStreamPause(tunnel_t *t, line_t *l)
{
    reverseclient_pair_t *pair = ((reverseclient_lstate_t *) lineGetState(l, t))->pair;
    if (pair->phase == kReverseClientPairActive)
    {
        tunnelPrevDownStreamPause(t, pair->d);
    }
}

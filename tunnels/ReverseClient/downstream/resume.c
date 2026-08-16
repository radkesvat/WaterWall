#include "structure.h"

void reverseclientTunnelDownStreamResume(tunnel_t *t, line_t *l)
{
    reverseclient_pair_t *pair = ((reverseclient_lstate_t *) lineGetState(l, t))->pair;
    if (pair->phase == kReverseClientPairActive)
    {
        tunnelPrevDownStreamResume(t, pair->d);
    }
}

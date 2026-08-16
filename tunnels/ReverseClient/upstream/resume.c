#include "structure.h"

void reverseclientTunnelUpStreamResume(tunnel_t *t, line_t *l)
{
    reverseclient_pair_t *pair = ((reverseclient_lstate_t *) lineGetState(l, t))->pair;
    tunnelNextUpStreamResume(t, pair->u);
}

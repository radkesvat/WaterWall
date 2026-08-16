#include "structure.h"

void reverseclientTunnelUpStreamPause(tunnel_t *t, line_t *l)
{
    reverseclient_pair_t *pair = ((reverseclient_lstate_t *) lineGetState(l, t))->pair;
    tunnelNextUpStreamPause(t, pair->u);
}

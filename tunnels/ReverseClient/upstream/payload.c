#include "structure.h"

void reverseclientTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    reverseclient_pair_t *pair = ((reverseclient_lstate_t *) lineGetState(l, t))->pair;
    tunnelNextUpStreamPayload(t, pair->u, buf);
}

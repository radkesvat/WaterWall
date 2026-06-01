#include "structure.h"

void realityclientTunnelUpStreamInit(tunnel_t *t, line_t *l)
{
    realityclient_lstate_t *ls = lineGetState(l, t);
    realityclientLinestateInitialize(ls, lineGetBufferPool(l));

    tunnelNextUpStreamInit(t, l);
}

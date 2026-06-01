#include "structure.h"

void realityclientTunnelUpStreamFinish(tunnel_t *t, line_t *l)
{
    realityclient_lstate_t *ls = lineGetState(l, t);
    realityclientLinestateDestroy(ls);

    tunnelNextUpStreamFinish(t, l);
}

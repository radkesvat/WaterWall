#include "structure.h"

void realityclientTunnelDownStreamFinish(tunnel_t *t, line_t *l)
{
    realityclient_lstate_t *ls = lineGetState(l, t);
    realityclientLinestateDestroy(ls);

    tunnelPrevDownStreamFinish(t, l);
}

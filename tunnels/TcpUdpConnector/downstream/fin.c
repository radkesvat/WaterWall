#include "structure.h"

void tcpudpconnectorTunnelDownStreamFinish(tunnel_t *t, line_t *l)
{
    tcpudpconnector_lstate_t *ls = lineGetState(l, t);

    tcpudpconnectorLinestateDestroy(ls);
    tunnelPrevDownStreamFinish(t, l);
}

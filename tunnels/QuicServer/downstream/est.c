#include "structure.h"

void quicserverTunnelDownStreamEst(tunnel_t *t, line_t *l)
{
    if (quicCanRelay(t, l))
    {
        tunnelPrevDownStreamEst(t, l);
    }
}

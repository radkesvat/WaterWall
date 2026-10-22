#include "structure.h"

void quicclientTunnelDownStreamEst(tunnel_t *t, line_t *l)
{
    if (quicCanRelay(t, l))
    {
        tunnelPrevDownStreamEst(t, l);
    }
}

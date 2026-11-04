#include "structure.h"

void quicserverTunnelDownStreamEst(tunnel_t *t, line_t *l)
{
    quicRelayDown(t, l, tunnelPrevDownStreamEst);
}

#include "structure.h"

void quicclientTunnelDownStreamPause(tunnel_t *t, line_t *l)
{
    quicRelayDown(t, l, tunnelPrevDownStreamPause);
}

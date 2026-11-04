#include "structure.h"

void quicserverTunnelDownStreamResume(tunnel_t *t, line_t *l)
{
    quicRelayDown(t, l, tunnelPrevDownStreamResume);
}

#include "structure.h"

void quicclientTunnelDownStreamResume(tunnel_t *t, line_t *l)
{
    quicRelayDown(t, l, tunnelPrevDownStreamResume);
}

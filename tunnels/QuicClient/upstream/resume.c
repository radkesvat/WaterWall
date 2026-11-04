#include "structure.h"

void quicclientTunnelUpStreamResume(tunnel_t *t, line_t *l)
{
    quicRelayUp(t, l, tunnelNextUpStreamResume);
}

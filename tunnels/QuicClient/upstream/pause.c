#include "structure.h"

void quicclientTunnelUpStreamPause(tunnel_t *t, line_t *l)
{
    quicRelayUp(t, l, tunnelNextUpStreamPause);
}

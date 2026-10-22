#include "structure.h"

void quicclientTunnelUpStreamPause(tunnel_t *t, line_t *l)
{
    if (quicCanRelay(t, l))
    {
        tunnelNextUpStreamPause(t, l);
    }
}

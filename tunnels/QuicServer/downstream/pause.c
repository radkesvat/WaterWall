#include "structure.h"

void quicserverTunnelDownStreamPause(tunnel_t *t, line_t *l)
{
    if (quicCanRelay(t, l))
    {
        tunnelPrevDownStreamPause(t, l);
    }
}

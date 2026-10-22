#include "structure.h"

void quicserverTunnelDownStreamResume(tunnel_t *t, line_t *l)
{
    if (quicCanRelay(t, l))
    {
        tunnelPrevDownStreamResume(t, l);
    }
}

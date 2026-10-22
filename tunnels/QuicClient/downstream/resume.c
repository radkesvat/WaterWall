#include "structure.h"

void quicclientTunnelDownStreamResume(tunnel_t *t, line_t *l)
{
    if (quicCanRelay(t, l))
    {
        tunnelPrevDownStreamResume(t, l);
    }
}

#include "structure.h"

void quicclientTunnelUpStreamResume(tunnel_t *t, line_t *l)
{
    if (quicCanRelay(t, l))
    {
        tunnelNextUpStreamResume(t, l);
    }
}

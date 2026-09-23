#include "structure.h"

void vlessclientTunnelDownStreamPause(tunnel_t *t, line_t *l)
{
    vlessclientSetNextPaused(t, l, true);
}

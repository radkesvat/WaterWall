#include "structure.h"

void vlessclientTunnelDownStreamResume(tunnel_t *t, line_t *l)
{
    vlessclientSetNextPaused(t, l, false);
}

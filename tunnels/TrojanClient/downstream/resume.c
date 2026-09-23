#include "structure.h"

void trojanclientTunnelDownStreamResume(tunnel_t *t, line_t *l)
{
    trojanclientSetNextPaused(t, l, false);
}

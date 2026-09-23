#include "structure.h"

void trojanclientTunnelDownStreamPause(tunnel_t *t, line_t *l)
{
    trojanclientSetNextPaused(t, l, true);
}

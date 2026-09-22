#include "structure.h"

void trojanclientTunnelUpStreamPause(tunnel_t *t, line_t *l)
{
    trojanclientSetPrevPaused(t, l, true);
}

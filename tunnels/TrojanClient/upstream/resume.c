#include "structure.h"

void trojanclientTunnelUpStreamResume(tunnel_t *t, line_t *l)
{
    trojanclientSetPrevPaused(t, l, false);
}

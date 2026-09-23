#include "structure.h"

void vlessclientTunnelUpStreamPause(tunnel_t *t, line_t *l)
{
    vlessclientSetPrevPaused(t, l, true);
}

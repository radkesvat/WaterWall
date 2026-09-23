#include "structure.h"

void vlessclientTunnelUpStreamResume(tunnel_t *t, line_t *l)
{
    vlessclientSetPrevPaused(t, l, false);
}

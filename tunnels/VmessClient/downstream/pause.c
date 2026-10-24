#include "internal.h"

void vmessclientTunnelDownStreamPause(tunnel_t *t, line_t *l)
{
    vmessclientSetNextPaused(t, l, true);
}

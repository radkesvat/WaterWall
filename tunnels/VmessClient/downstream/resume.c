#include "internal.h"

void vmessclientTunnelDownStreamResume(tunnel_t *t, line_t *l)
{
    vmessclientSetNextPaused(t, l, false);
}

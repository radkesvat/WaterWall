#include "structure.h"

void halfduplexclientTunnelDownStreamResume(tunnel_t *t, line_t *l)
{
    halfduplexclientSetNextPaused(t, l, false);
}

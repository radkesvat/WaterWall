#include "structure.h"

void halfduplexclientTunnelDownStreamPause(tunnel_t *t, line_t *l)
{
    halfduplexclientSetNextPaused(t, l, true);
}

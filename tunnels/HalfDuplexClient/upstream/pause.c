#include "structure.h"

void halfduplexclientTunnelUpStreamPause(tunnel_t *t, line_t *l)
{
    halfduplexclientSetPrevPaused(t, l, true);
}

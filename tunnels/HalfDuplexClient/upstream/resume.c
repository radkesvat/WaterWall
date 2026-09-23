#include "structure.h"

void halfduplexclientTunnelUpStreamResume(tunnel_t *t, line_t *l)
{
    halfduplexclientSetPrevPaused(t, l, false);
}

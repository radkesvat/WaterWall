#include "structure.h"

void trojanserverTunnelDownStreamResume(tunnel_t *t, line_t *l)
{
    trojanserverSetNextPaused(t, l, false);
}

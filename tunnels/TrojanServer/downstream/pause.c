#include "structure.h"

void trojanserverTunnelDownStreamPause(tunnel_t *t, line_t *l)
{
    trojanserverSetNextPaused(t, l, true);
}

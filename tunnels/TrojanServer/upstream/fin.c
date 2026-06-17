#include "structure.h"

void trojanserverTunnelUpStreamFinish(tunnel_t *t, line_t *l)
{
    trojanserverCloseLineFromUpstream(t, l);
}

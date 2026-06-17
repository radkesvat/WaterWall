#include "structure.h"

void trojanserverTunnelDownStreamFinish(tunnel_t *t, line_t *l)
{
    trojanserverCloseLineFromDownstream(t, l);
}

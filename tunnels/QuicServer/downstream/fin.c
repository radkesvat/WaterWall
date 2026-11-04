#include "structure.h"

void quicserverTunnelDownStreamFinish(tunnel_t *t, line_t *l)
{
    quicFinishApplication(t, l);
}

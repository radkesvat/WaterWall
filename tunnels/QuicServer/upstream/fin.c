#include "structure.h"

void quicserverTunnelUpStreamFinish(tunnel_t *t, line_t *l)
{
    quicFinishCarrier(t, l);
}

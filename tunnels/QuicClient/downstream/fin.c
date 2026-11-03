#include "structure.h"

void quicclientTunnelDownStreamFinish(tunnel_t *t, line_t *l)
{
    quicFinishCarrier(t, l);
}

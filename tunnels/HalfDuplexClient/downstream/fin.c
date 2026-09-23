#include "structure.h"

void halfduplexclientTunnelDownStreamFinish(tunnel_t *t, line_t *l)
{
    halfduplexclientClosePair(t, l, false, true);
}

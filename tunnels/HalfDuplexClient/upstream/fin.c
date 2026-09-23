#include "structure.h"

void halfduplexclientTunnelUpStreamFinish(tunnel_t *t, line_t *l)
{
    halfduplexclientClosePair(t, l, true, false);
}

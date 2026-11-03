#include "structure.h"

void quicclientTunnelUpStreamFinish(tunnel_t *t, line_t *l)
{
    quicFinishApplication(t, l);
}

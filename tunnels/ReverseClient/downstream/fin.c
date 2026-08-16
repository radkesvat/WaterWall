#include "structure.h"

void reverseclientTunnelDownStreamFinish(tunnel_t *t, line_t *l)
{
    reverseclient_lstate_t *ls = lineGetState(l, t);
    reverseclientClosePair(ls->pair, kReverseClientCloseFromNext);
}

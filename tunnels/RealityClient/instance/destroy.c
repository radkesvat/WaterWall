#include "structure.h"

void realityclientTunnelDestroy(tunnel_t *t)
{
    realityclient_tstate_t *ts = tunnelGetState(t);
    realityclientTunnelstateDestroy(ts);
    tunnelDestroy(t);
}

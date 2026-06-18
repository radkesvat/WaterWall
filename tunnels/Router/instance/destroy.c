#include "structure.h"

void routerTunnelDestroy(tunnel_t *t)
{
    router_tstate_t *ts = tunnelGetState(t);
    routerRuleTableDestroy(ts);
    tunnelDestroy(t);
}

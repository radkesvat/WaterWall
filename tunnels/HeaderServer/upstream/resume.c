#include "structure.h"

#include "loggers/network_logger.h"

void headerserverTunnelUpStreamResume(tunnel_t *t, line_t *l)
{
    headerserver_lstate_t *ls = lineGetState(l, t);

    if (ls->phase == kHeaderServerPhaseNone)
    {
        return;
    }
    if (nextinitgateSignal(&ls->gate, false))
    {
        tunnelNextUpStreamResume(t, l);
    }
}

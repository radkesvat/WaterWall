#include "structure.h"

#include "loggers/network_logger.h"

void headerserverTunnelUpStreamInit(tunnel_t *t, line_t *l)
{
    headerserver_tstate_t *ts = tunnelGetState(t);
    headerserver_lstate_t *ls = lineGetState(l, t);

    headerserverLinestateInitialize(ls, l, ts);

    if (ts->override_mode == kHeaderServerOverrideModeConstant)
    {
        addresscontextSetPort(lineGetDestinationAddressContext(l), ts->constant_port);
        tunnelNextUpStreamInit(t, l);
    }
}

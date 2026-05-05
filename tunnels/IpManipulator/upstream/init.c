#include "structure.h"

#include "loggers/network_logger.h"

void ipmanipulatorUpStreamInit(tunnel_t *t, line_t *l)
{
    ipmanipulator_tstate_t *ts = tunnelGetState(t);
    if (! withLineLocked(l, tunnelNextUpStreamInit, t))
    {
        LOGF("IpManipulator: next packet line died during upstream init");
        terminateProgram(1);
    }

    if (ts->trick_real_sni_upstream_tunnel != NULL)
    {
        tunnelUpStreamInit(ts->trick_real_sni_upstream_tunnel, l);
    }

    if (ts->trick_real_fin_upstream_tunnel != NULL && ts->trick_real_fin_upstream_tunnel != ts->trick_real_sni_upstream_tunnel)
    {
        tunnelUpStreamInit(ts->trick_real_fin_upstream_tunnel, l);
    }
}

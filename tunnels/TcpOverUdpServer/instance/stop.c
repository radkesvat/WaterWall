#include "structure.h"

#include "loggers/network_logger.h"

void tcpoverudpserverTunnelOnQuiesceRequest(tunnel_t *t, const ww_lifecycle_context_t *context)
{
    discard                    context;
    tcpoverudpserver_tstate_t *state = tunnelGetState(t);
    atomicStoreRelaxed(&state->stopping, true);
}

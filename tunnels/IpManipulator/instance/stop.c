#include "structure.h"

#include "loggers/network_logger.h"

void ipmanipulatorOnStop(tunnel_t *t)
{
    ipmanipulator_tstate_t *ts = tunnelGetState(t);

    if (ts->internal_tls_client_tunnel != NULL && tunnelGetChain(ts->internal_tls_client_tunnel) == NULL)
    {
        ts->internal_tls_client_tunnel->onStop(ts->internal_tls_client_tunnel);
    }
}

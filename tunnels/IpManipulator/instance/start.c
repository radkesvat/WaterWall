#include "structure.h"

#include "loggers/network_logger.h"

static void ipmanipulatorStartUnchainedHelper(tunnel_t *helper)
{
    if (helper != NULL && tunnelGetChain(helper) == NULL)
    {
        helper->onStart(helper);
    }
}

void ipmanipulatorOnStart(tunnel_t *t)
{
    ipmanipulator_tstate_t *ts = tunnelGetState(t);

    ipmanipulatorStartUnchainedHelper(ts->internal_tls_client_tunnel);
}

#include "structure.h"

#include "loggers/network_logger.h"

static void ipmanipulatorPrepareUnchainedHelper(tunnel_t *helper)
{
    if (helper != NULL && tunnelGetChain(helper) == NULL)
    {
        helper->onPrepare(helper);
    }
}

void ipmanipulatorOnPrepair(tunnel_t *t)
{
    ipmanipulator_tstate_t *ts = tunnelGetState(t);

    ipmanipulatorPrepareUnchainedHelper(ts->trick_real_sni_tls_client_tunnel);
    ipmanipulatorPrepareUnchainedHelper(ts->trick_overlap_sni_tls_client_tunnel);
    if (ts->trick_synfin_sni_tls_client_tunnel != ts->trick_overlap_sni_tls_client_tunnel)
    {
        ipmanipulatorPrepareUnchainedHelper(ts->trick_synfin_sni_tls_client_tunnel);
    }
}

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

    ipmanipulatorStartUnchainedHelper(ts->trick_real_sni_tls_client_tunnel);
    ipmanipulatorStartUnchainedHelper(ts->trick_overlap_sni_tls_client_tunnel);
    if (ts->trick_synfin_sni_tls_client_tunnel != NULL &&
        ts->trick_synfin_sni_tls_client_tunnel != ts->trick_overlap_sni_tls_client_tunnel)
    {
        ipmanipulatorStartUnchainedHelper(ts->trick_synfin_sni_tls_client_tunnel);
    }
}

#include "structure.h"

#include "loggers/network_logger.h"

void ipmanipulatorOnPrepair(tunnel_t *t)
{
    ipmanipulator_tstate_t *ts = tunnelGetState(t);
    if (ts->trick_real_sni_upstream_tunnel != NULL)
    {
        ts->trick_real_sni_upstream_tunnel->onPrepare(ts->trick_real_sni_upstream_tunnel);
    }

    if (ts->trick_real_fin_upstream_tunnel != NULL && ts->trick_real_fin_upstream_tunnel != ts->trick_real_sni_upstream_tunnel)
    {
        ts->trick_real_fin_upstream_tunnel->onPrepare(ts->trick_real_fin_upstream_tunnel);
    }

    if (ts->trick_overlap_sni_server_hello_upstream_tunnel != NULL &&
        ts->trick_overlap_sni_server_hello_upstream_tunnel != ts->trick_real_sni_upstream_tunnel &&
        ts->trick_overlap_sni_server_hello_upstream_tunnel != ts->trick_real_fin_upstream_tunnel)
    {
        ts->trick_overlap_sni_server_hello_upstream_tunnel->onPrepare(
            ts->trick_overlap_sni_server_hello_upstream_tunnel);
    }

    if (ts->trick_real_sni_tls_client_tunnel != NULL)
    {
        ts->trick_real_sni_tls_client_tunnel->onPrepare(ts->trick_real_sni_tls_client_tunnel);
    }

    if (ts->trick_overlap_sni_tls_client_tunnel != NULL)
    {
        ts->trick_overlap_sni_tls_client_tunnel->onPrepare(ts->trick_overlap_sni_tls_client_tunnel);
    }

    if (ts->trick_synfin_sni_tls_client_tunnel != NULL &&
        ts->trick_synfin_sni_tls_client_tunnel != ts->trick_overlap_sni_tls_client_tunnel)
    {
        ts->trick_synfin_sni_tls_client_tunnel->onPrepare(ts->trick_synfin_sni_tls_client_tunnel);
    }
}

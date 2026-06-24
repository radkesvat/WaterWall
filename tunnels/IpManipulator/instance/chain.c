#include "structure.h"

#include "loggers/network_logger.h"

void ipmanipulatorOnChain(tunnel_t *t, tunnel_chain_t *chain)
{
    ipmanipulator_tstate_t *state = tunnelGetState(t);

    if (! state->trick_smuggle_sni && ! state->trick_overlap_sni && ! state->trick_synfin_sni &&
        ! state->trick_smuggle_fin)
    {
        tunnelDefaultOnChain(t, chain);
        return;
    }

    node_t *node = tunnelGetNode(t);
    if (node->hash_next == 0x0)
    {
        LOGF("IpManipulator: smuggle helper tricks require a normal next node");
        terminateProgram(1);
    }

    node_t *normal_next_node = nodemanagerGetConfigNodeByHash(node->node_manager_config, node->hash_next);
    if (normal_next_node == NULL)
    {
        LOGF("IpManipulator: normal next node \"%s\" not found", node->next);
        terminateProgram(1);
    }

    tunnel_t *normal_next_tunnel         = normal_next_node->instance;
    tunnel_t *real_sni_upstream_tunnel   =
        state->trick_real_sni_upstream_node != NULL ? state->trick_real_sni_upstream_node->instance : NULL;
    tunnel_t *real_sni_tls_client_tunnel =
        state->trick_real_sni_tls_client_node != NULL ? state->trick_real_sni_tls_client_node->instance : NULL;
    tunnel_t *overlap_sni_server_hello_upstream_tunnel =
        state->trick_overlap_sni_server_hello_upstream_node != NULL
            ? state->trick_overlap_sni_server_hello_upstream_node->instance
            : NULL;
    tunnel_t *overlap_sni_tls_client_tunnel =
        state->trick_overlap_sni_tls_client_node != NULL ? state->trick_overlap_sni_tls_client_node->instance : NULL;
    tunnel_t *synfin_sni_tls_client_tunnel =
        state->trick_synfin_sni_tls_client_node != NULL ? state->trick_synfin_sni_tls_client_node->instance : NULL;
    tunnel_t *real_fin_upstream_tunnel   =
        state->trick_real_fin_upstream_node != NULL ? state->trick_real_fin_upstream_node->instance : NULL;

    if (normal_next_tunnel == NULL)
    {
        LOGF("IpManipulator: referenced normal next tunnel instance is not available");
        terminateProgram(1);
    }

    if (state->trick_smuggle_sni && (real_sni_upstream_tunnel == NULL || real_sni_tls_client_tunnel == NULL))
    {
        LOGF("IpManipulator: smuggle-sni referenced tunnel instances are not available");
        terminateProgram(1);
    }

    if (state->trick_overlap_sni &&
        (overlap_sni_tls_client_tunnel == NULL || overlap_sni_server_hello_upstream_tunnel == NULL))
    {
        LOGF("IpManipulator: overlap-sni referenced tunnel instances are not available");
        terminateProgram(1);
    }

    if (state->trick_synfin_sni && synfin_sni_tls_client_tunnel == NULL)
    {
        LOGF("IpManipulator: synfin-sni referenced tunnel instances are not available");
        terminateProgram(1);
    }

    if (state->trick_smuggle_fin && real_fin_upstream_tunnel == NULL)
    {
        LOGF("IpManipulator: smuggle-fin referenced tunnel instances are not available");
        terminateProgram(1);
    }

    if (real_sni_upstream_tunnel != NULL && normal_next_tunnel == real_sni_upstream_tunnel)
    {
        LOGF("IpManipulator: real-sni-upstream-node must differ from the normal next node");
        terminateProgram(1);
    }

    if (real_fin_upstream_tunnel != NULL && normal_next_tunnel == real_fin_upstream_tunnel)
    {
        LOGF("IpManipulator: real-fin-upstream-node must differ from the normal next node");
        terminateProgram(1);
    }

    if (overlap_sni_server_hello_upstream_tunnel != NULL &&
        normal_next_tunnel == overlap_sni_server_hello_upstream_tunnel)
    {
        LOGF("IpManipulator: crafted-server-hello-upstream-node must differ from the normal next node");
        terminateProgram(1);
    }

    if ((normal_next_tunnel->prev != NULL && normal_next_tunnel->prev != t) ||
        (real_sni_upstream_tunnel != NULL && real_sni_upstream_tunnel->prev != NULL && real_sni_upstream_tunnel->prev != t) ||
        (overlap_sni_server_hello_upstream_tunnel != NULL && overlap_sni_server_hello_upstream_tunnel->prev != NULL &&
         overlap_sni_server_hello_upstream_tunnel->prev != t) ||
        (real_fin_upstream_tunnel != NULL && real_fin_upstream_tunnel->prev != NULL && real_fin_upstream_tunnel->prev != t))
    {
        LOGF("IpManipulator: smuggle helper upstream nodes are already bound to another previous tunnel");
        terminateProgram(1);
    }

    if (t->next != NULL && t->next != normal_next_tunnel)
    {
        LOGF("IpManipulator: tunnel already has a different chained next tunnel");
        terminateProgram(1);
    }

    state->trick_real_sni_upstream_tunnel   = real_sni_upstream_tunnel;
    state->trick_real_sni_tls_client_tunnel = real_sni_tls_client_tunnel;
    state->trick_overlap_sni_server_hello_upstream_tunnel = overlap_sni_server_hello_upstream_tunnel;
    state->trick_overlap_sni_tls_client_tunnel = overlap_sni_tls_client_tunnel;
    state->trick_synfin_sni_tls_client_tunnel = synfin_sni_tls_client_tunnel;
    state->trick_real_fin_upstream_tunnel   = real_fin_upstream_tunnel;

    if (real_sni_upstream_tunnel != NULL)
    {
        tunnelBindDown(t, real_sni_upstream_tunnel);
    }
    if (overlap_sni_server_hello_upstream_tunnel != NULL &&
        overlap_sni_server_hello_upstream_tunnel != real_sni_upstream_tunnel)
    {
        tunnelBindDown(t, overlap_sni_server_hello_upstream_tunnel);
    }
    if (real_fin_upstream_tunnel != NULL && real_fin_upstream_tunnel != real_sni_upstream_tunnel &&
        real_fin_upstream_tunnel != overlap_sni_server_hello_upstream_tunnel)
    {
        tunnelBindDown(t, real_fin_upstream_tunnel);
    }
    tunnelBind(t, normal_next_tunnel);
    tunnelchainInsert(chain, t);

    if (normal_next_tunnel->chain != NULL)
    {
        tunnelchainCombine(normal_next_tunnel->chain, chain);
    }
    else
    {
        normal_next_tunnel->onChain(normal_next_tunnel, chain);
    }

    chain = tunnelGetChain(t);

    if (real_sni_upstream_tunnel != NULL && real_sni_upstream_tunnel->chain != NULL)
    {
        if (real_sni_upstream_tunnel->chain != chain)
        {
            tunnelchainCombine(chain, real_sni_upstream_tunnel->chain);
        }
    }
    else if (real_sni_upstream_tunnel != NULL)
    {
        real_sni_upstream_tunnel->onChain(real_sni_upstream_tunnel, chain);
    }

    if (overlap_sni_server_hello_upstream_tunnel != NULL &&
        overlap_sni_server_hello_upstream_tunnel != real_sni_upstream_tunnel)
    {
        chain = tunnelGetChain(t);

        if (overlap_sni_server_hello_upstream_tunnel->chain != NULL)
        {
            if (overlap_sni_server_hello_upstream_tunnel->chain != chain)
            {
                tunnelchainCombine(chain, overlap_sni_server_hello_upstream_tunnel->chain);
            }
        }
        else
        {
            overlap_sni_server_hello_upstream_tunnel->onChain(overlap_sni_server_hello_upstream_tunnel, chain);
        }
    }

    if (real_fin_upstream_tunnel != NULL && real_fin_upstream_tunnel != real_sni_upstream_tunnel &&
        real_fin_upstream_tunnel != overlap_sni_server_hello_upstream_tunnel)
    {
        chain = tunnelGetChain(t);

        if (real_fin_upstream_tunnel->chain != NULL)
        {
            if (real_fin_upstream_tunnel->chain != chain)
            {
                tunnelchainCombine(chain, real_fin_upstream_tunnel->chain);
            }
        }
        else
        {
            real_fin_upstream_tunnel->onChain(real_fin_upstream_tunnel, chain);
        }
    }

    // Each helper upstream may insert internal tunnels in front of itself while
    // chaining (e.g. a connector's domain setup + DomainResolver); drive the branch
    // entry bound directly below us, not the raw instance.
    if (real_sni_upstream_tunnel != NULL)
    {
        state->trick_real_sni_upstream_tunnel = tunnelGetBranchEntry(t, real_sni_upstream_tunnel);
        if (state->trick_real_sni_upstream_tunnel == NULL)
        {
            LOGF("IpManipulator: real-sni-upstream node is not reachable from IpManipulator");
            terminateProgram(1);
        }
    }
    if (overlap_sni_server_hello_upstream_tunnel != NULL)
    {
        state->trick_overlap_sni_server_hello_upstream_tunnel =
            tunnelGetBranchEntry(t, overlap_sni_server_hello_upstream_tunnel);
        if (state->trick_overlap_sni_server_hello_upstream_tunnel == NULL)
        {
            LOGF("IpManipulator: crafted-server-hello-upstream node is not reachable from IpManipulator");
            terminateProgram(1);
        }
    }
    if (real_fin_upstream_tunnel != NULL)
    {
        state->trick_real_fin_upstream_tunnel = tunnelGetBranchEntry(t, real_fin_upstream_tunnel);
        if (state->trick_real_fin_upstream_tunnel == NULL)
        {
            LOGF("IpManipulator: real-fin-upstream node is not reachable from IpManipulator");
            terminateProgram(1);
        }
    }
}

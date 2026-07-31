#include "structure.h"

#include "loggers/network_logger.h"
#include "tricks/echsnitrick/trick.h"
#include "tricks/firstsni/trick.h"
#include "tricks/overlapsni/trick.h"
#include "tricks/smugglefin/trick.h"
#include "tricks/smugglesni/trick.h"
#include "tricks/synfinsni/trick.h"

static void destroyInternalTlsClient(ipmanipulator_tstate_t *state)
{
    if (state->internal_tls_client_tunnel != NULL)
    {
        state->internal_tls_client_tunnel->onDestroy(state->internal_tls_client_tunnel);
        state->internal_tls_client_tunnel = NULL;
    }
    state->internal_tls_client_node.instance = NULL;

    if (state->internal_tls_client_settings != NULL)
    {
        cJSON_Delete(state->internal_tls_client_settings);
        state->internal_tls_client_settings = NULL;
    }

    memoryFree(state->internal_tls_client_node.name);
    memoryFree(state->internal_tls_client_node.type);
    memoryFree(state->internal_tls_client_node.next);
    memoryZero(&state->internal_tls_client_node, sizeof(state->internal_tls_client_node));

    state->trick_real_sni_tls_client_tunnel    = NULL;
    state->trick_overlap_sni_tls_client_tunnel = NULL;
    state->trick_synfin_sni_tls_client_tunnel  = NULL;
}

void ipmanipulatorDestroy(tunnel_t *t)
{
    ipmanipulator_tstate_t *state = tunnelGetState(t);

    destroyInternalTlsClient(state);
    firstsnitrickDestroyState(t);
    ipmanipulatorDestroyTlsCaptureState(t);
    overlapsnitrickDestroyState(t);
    echsnitrickDestroyState(t);
    smugglefintrickDestroyState(t);
    smugglesnitrickDestroyState(t);
    synfinsnitrickDestroyState(t);

    if (state->trick_first_sni_value != NULL)
    {
        memoryFree(state->trick_first_sni_value);
    }

    if (state->trick_smuggle_sni_value != NULL)
    {
        memoryFree(state->trick_smuggle_sni_value);
    }

    if (state->trick_overlap_sni_value != NULL)
    {
        memoryFree(state->trick_overlap_sni_value);
    }

    if (state->trick_synfin_sni_value != NULL)
    {
        memoryFree(state->trick_synfin_sni_value);
    }

    if (state->trick_ech_sni_value != NULL)
    {
        memoryFree(state->trick_ech_sni_value);
    }

    tunnelDestroy(t);
}

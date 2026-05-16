#include "structure.h"

#include "loggers/network_logger.h"
#include "tricks/echsnitrick/trick.h"
#include "tricks/firstsni/trick.h"
#include "tricks/overlapsni/trick.h"
#include "tricks/smugglefin/trick.h"
#include "tricks/smugglesni/trick.h"
#include "tricks/synfinsni/trick.h"

void ipmanipulatorDestroy(tunnel_t *t)
{
    ipmanipulator_tstate_t *state = tunnelGetState(t);

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

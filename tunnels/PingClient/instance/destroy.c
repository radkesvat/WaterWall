#include "structure.h"

void pingclientDestroy(tunnel_t *t, const ww_lifecycle_context_t *context)
{
    discard context;

    if (t == NULL)
    {
        return;
    }

    pingclient_tstate_t *state = tunnelGetState(t);
    if (state->decoded_affinity != NULL)
        packetAffinityDestroy(state->decoded_affinity);
    pingwireTrackerDestroy(state->tracker);

    memorySecureZero(state, sizeof(*state));
    tunnelDestroy(t);
}

#include "structure.h"

void pingclientDestroy(tunnel_t *t, const ww_lifecycle_context_t *context)
{
    discard context;

    if (t == NULL)
    {
        return;
    }

    pingclient_tstate_t *state = tunnelGetState(t);
    pingwireTrackerDestroy(state->tracker);
    state->tracker = NULL;

    memorySecureZero(state, sizeof(*state));
    tunnelDestroy(t);
}

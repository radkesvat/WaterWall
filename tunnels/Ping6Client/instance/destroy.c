#include "structure.h"

void ping6clientDestroy(tunnel_t *t, const ww_lifecycle_context_t *context)
{
    discard context;

    if (t == NULL)
    {
        return;
    }

    ping6client_tstate_t *state = tunnelGetState(t);
    pingwireTrackerDestroy(state->tracker);

    memorySecureZero(state, sizeof(*state));
    tunnelDestroy(t);
}

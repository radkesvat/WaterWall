#include "structure.h"

#include "loggers/network_logger.h"

void ping6clientOnPrepair(tunnel_t *t)
{
    ping6client_tstate_t *state = tunnelGetState(t);
    tunnel_chain_t       *chain = tunnelGetChain(t);

    if (state->tracker != NULL)
    {
        return;
    }

    if (chain == NULL || chain->workers_count == 0)
    {
        LOGF("Ping6Client: cannot construct node-wide Echo correlation state without packet workers");
        startupFailureRecord(1);
        return;
    }

    state->tracker = pingwireTrackerCreate();
    if (state->tracker == NULL)
    {
        LOGF("Ping6Client: failed to construct synchronized node-wide Echo correlation state");
        startupFailureRecord(1);
    }
}

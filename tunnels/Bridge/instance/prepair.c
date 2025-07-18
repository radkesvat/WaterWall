#include "structure.h"

#include "loggers/network_logger.h"

void bridgeTunnelOnPrepair(tunnel_t *t)
{

    bridge_tstate_t *state = tunnelGetState(t);

    if (state->pair_node->instance)
    {
        state->pair                 = state->pair_node->instance;
        bridge_tstate_t *pair_state = tunnelGetState(state->pair);
        pair_state->pair            = t;
    }
    else
    {
        LOGF("Bridge: pair node \"%s\" is not initialized", state->pair_node->name);
        terminateProgram(1);
    }
}

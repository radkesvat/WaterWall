#include "structure.h"

#include "loggers/network_logger.h"

tunnel_t *ipmanipulatorCreate(node_t *node)
{
    tunnel_t *t = packettunnelCreate(node, sizeof(ipmanipulator_tstate_t), sizeof(ipmanipulator_lstate_t));

    t->fnPayloadU = &ipmanipulatorUpStreamPayload;
    t->fnPayloadD = &ipmanipulatorDownStreamPayload;
    t->onPrepair  = &ipmanipulatorOnPrepair;
    t->onStart    = &ipmanipulatorOnStart;
    t->onDestroy  = &ipmanipulatorDestroy;

    ipmanipulator_tstate_t *state = tunnelGetState(t);

    const cJSON *settings = node->node_settings_json;

    if (! getIntFromJsonObjectOrDefault(&state->manip_swap_tcp, settings, "protoswap", 0))
    {
        LOGF("IpManipulator: set protoswap");
        return NULL;
    }

    return t;
}

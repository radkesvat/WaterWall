#include "structure.h"

tunnel_t *faketcpheaderclientCreate(node_t *node)
{
    tunnel_t *t = packettunnelCreate(node, sizeof(faketcpheaderclient_tstate_t), 0);
    if (t == NULL)
    {
        return NULL;
    }

    t->fnPayloadU = &faketcpheaderclientUpStreamPayload;
    t->fnPayloadD = &faketcpheaderclientDownStreamPayload;

    faketcpheaderclient_tstate_t *state = tunnelGetState(t);
    if (! faketcpheaderWireLoadSettings(node->node_settings_json, "FakeTcpHeaderClient", &state->wire))
    {
        t->onDestroy(t, wwLifecycleStartupRollback());
        return NULL;
    }

    atomicLogRateLimiterInitialize(&state->drop_log_limiter);
    return t;
}

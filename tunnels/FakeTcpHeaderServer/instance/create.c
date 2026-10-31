#include "structure.h"

tunnel_t *faketcpheaderserverCreate(node_t *node)
{
    tunnel_t *t = packettunnelCreate(node, sizeof(faketcpheaderserver_tstate_t), 0);
    if (t == NULL)
    {
        return NULL;
    }

    t->fnPayloadU = &faketcpheaderserverUpStreamPayload;
    t->fnPayloadD = &faketcpheaderserverDownStreamPayload;

    faketcpheaderserver_tstate_t *state = tunnelGetState(t);
    if (! faketcpheaderWireLoadSettings(node->node_settings_json, "FakeTcpHeaderServer", &state->wire))
    {
        t->onDestroy(t, wwLifecycleStartupRollback());
        return NULL;
    }

    atomicLogRateLimiterInitialize(&state->drop_log_limiter);
    return t;
}

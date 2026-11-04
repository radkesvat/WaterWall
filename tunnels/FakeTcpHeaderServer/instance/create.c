#include "structure.h"

tunnel_t *faketcpheaderserverCreate(node_t *node)
{
    faketcpheader_wire_config_t wire;
    if (! faketcpheaderWireLoadSettings(node->node_settings_json, "FakeTcpHeaderServer", &wire))
    {
        return NULL;
    }
    /* At most 1024 ports, with one sequence slot and one ACK slot each.
     * Only required blocks are reserved, sharing the tunnel allocation/lifetime. */
    const size_t state_count = faketcpheaderWireStateCount(&wire);
    tunnel_t    *t =
        packettunnelCreate(node, sizeof(faketcpheaderserver_tstate_t) + state_count * sizeof(atomic_u32_t), 0);
    if (t == NULL)
    {
        return NULL;
    }

    t->fnPayloadU = &faketcpheaderserverUpStreamPayload;
    t->fnPayloadD = &faketcpheaderserverDownStreamPayload;

    faketcpheaderserver_tstate_t *state = tunnelGetState(t);
    state->wire                         = wire;
    faketcpheaderWireInitState(&state->wire, state_count != 0 ? state->values : NULL);
    atomicLogRateLimiterInitialize(&state->drop_log_limiter);
    return t;
}

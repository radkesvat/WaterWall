#include "structure.h"

tunnel_t *faketcpheaderclientCreate(node_t *node)
{
    faketcpheader_wire_config_t wire;
    if (! faketcpheaderWireLoadSettings(node->node_settings_json, "FakeTcpHeaderClient", &wire))
    {
        return NULL;
    }
    /* At most 1024 ports, with sequence, ACK, and flag-position slots as needed.
     * Only required blocks are reserved, sharing the tunnel allocation/lifetime. */
    const size_t state_count = faketcpheaderWireStateCount(&wire);
    tunnel_t    *t =
        packettunnelCreate(node, sizeof(faketcpheaderclient_tstate_t) + state_count * sizeof(atomic_u32_t), 0);
    if (t == NULL)
    {
        return NULL;
    }

    t->fnPayloadU = &faketcpheaderclientUpStreamPayload;
    t->fnPayloadD = &faketcpheaderclientDownStreamPayload;

    faketcpheaderclient_tstate_t *state = tunnelGetState(t);
    state->wire                         = wire;
    faketcpheaderWireInitState(&state->wire, state_count != 0 ? state->values : NULL);
    atomicLogRateLimiterInitialize(&state->drop_log_limiter);
    return t;
}

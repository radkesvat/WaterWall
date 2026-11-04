#include "structure.h"

tunnel_t *faketcpheaderserverCreate(node_t *node)
{
    faketcpheader_wire_config_t wire;
    if (! faketcpheaderWireLoadSettings(node->node_settings_json, "FakeTcpHeaderServer", &wire))
    {
        return NULL;
    }
    /* Settings bound the seed/counter array to 1024 entries. It shares the
     * tunnel's allocation and lifetime; fixed random_port retains its seeds. */
    const size_t sequence_bytes =
        faketcpheaderWireNeedsSequences(&wire) ? (size_t) wire.client_port_count * sizeof(atomic_u32_t) : 0;
    tunnel_t *t = packettunnelCreate(node, sizeof(faketcpheaderserver_tstate_t) + sequence_bytes, 0);
    if (t == NULL)
    {
        return NULL;
    }

    t->fnPayloadU = &faketcpheaderserverUpStreamPayload;
    t->fnPayloadD = &faketcpheaderserverDownStreamPayload;

    faketcpheaderserver_tstate_t *state = tunnelGetState(t);
    state->wire                         = wire;
    faketcpheaderWireInitSequences(&state->wire, faketcpheaderWireNeedsSequences(&wire) ? state->sequences : NULL);
    atomicLogRateLimiterInitialize(&state->drop_log_limiter);
    return t;
}

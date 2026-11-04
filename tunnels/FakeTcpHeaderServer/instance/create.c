#include "structure.h"

#include "loggers/network_logger.h"

static void faketcpheaderserverDestroy(tunnel_t *t, const ww_lifecycle_context_t *context)
{
    discard                       context;
    faketcpheaderserver_tstate_t *state = tunnelGetState(t);
    faketcpheaderEncryptionDestroy(&state->encryption);
    tunnelDestroy(t);
}

static void faketcpheaderserverChain(tunnel_t *t, tunnel_chain_t *chain)
{
    /* Config map iteration may visit this node before its predecessor. */
    if (t->prev == NULL)
    {
        assert(chain->tunnels.len == 0);
        tunnelchainDestroy(chain);
        return;
    }
    if (faketcpheaderEncryptionIsNode(tunnelGetNode(t->prev)))
    {
        LOGF("FakeTcpHeaderServer: password already inserts encryption; remove the adjacent Encryption node");
        startupFailureRecord(1);
        return;
    }
    faketcpheaderserver_tstate_t *state = tunnelGetState(t);
    if (tunnelInsertBefore(t, state->encryption.tunnel, chain))
    {
        tunnelDefaultOnChain(t, chain);
    }
}

tunnel_t *faketcpheaderserverCreate(node_t *node)
{
    faketcpheader_wire_config_t wire;
    if (! faketcpheaderWireLoadSettings(node->node_settings_json, "FakeTcpHeaderServer", &wire))
    {
        return NULL;
    }
    /* At most 1024 ports, with sequence, ACK, and flag-position slots as needed.
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
    if (wire.encryption_enabled)
    {
        if (! faketcpheaderEncryptionCreate(&state->encryption, node, kFakeTcpHeaderWireServer))
        {
            faketcpheaderserverDestroy(t, wwLifecycleStartupRollback());
            return NULL;
        }
        t->onChain   = faketcpheaderserverChain;
        t->onDestroy = faketcpheaderserverDestroy;
    }
    faketcpheaderWireInitState(&state->wire, state_count != 0 ? state->values : NULL);
    atomicLogRateLimiterInitialize(&state->drop_log_limiter);
    return t;
}

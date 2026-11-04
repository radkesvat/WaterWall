#include "structure.h"

#include "loggers/network_logger.h"

static void faketcpheaderclientDestroy(tunnel_t *t, const ww_lifecycle_context_t *context)
{
    discard                       context;
    faketcpheaderclient_tstate_t *state = tunnelGetState(t);
    faketcpheaderEncryptionDestroy(&state->encryption);
    tunnelDestroy(t);
}

static void faketcpheaderclientChain(tunnel_t *t, tunnel_chain_t *chain)
{
    faketcpheaderclient_tstate_t *state = tunnelGetState(t);
    node_t                       *node  = tunnelGetNode(t);
    if (node->hash_next != 0)
    {
        node_t *next = nodemanagerGetConfigNodeByHash(node->node_manager_config, node->hash_next);
        if (faketcpheaderEncryptionIsNode(next))
        {
            LOGF("FakeTcpHeaderClient: password already inserts encryption; remove the adjacent Encryption node");
            startupFailureRecord(1);
            return;
        }
    }
    tunnel_t *child = state->encryption.tunnel;
    assert(child != NULL && t->next == NULL && child->prev == NULL && child->next == NULL && child->chain == NULL);
    tunnelBind(t, child);
    tunnelchainInsert(chain, t);
    if (! startupFailurePending())
    {
        child->onChain(child, chain);
    }
}

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
    if (wire.encryption_enabled)
    {
        if (! faketcpheaderEncryptionCreate(&state->encryption, node, kFakeTcpHeaderWireClient))
        {
            faketcpheaderclientDestroy(t, wwLifecycleStartupRollback());
            return NULL;
        }
        t->onChain   = faketcpheaderclientChain;
        t->onDestroy = faketcpheaderclientDestroy;
    }
    faketcpheaderWireInitState(&state->wire, state_count != 0 ? state->values : NULL);
    atomicLogRateLimiterInitialize(&state->drop_log_limiter);
    return t;
}

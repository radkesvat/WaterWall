#include "WireGuardServer/structure.h"
#include "loggers/network_logger.h"

enum
{
    kDefaultMaxUnauthenticatedIngress = 1024,
    kDefaultMaxPendingRekeyBytes      = 4U * 1024U * 1024U
};

static void absorb(tunnel_t *t, line_t *line)
{
    discard t;
    discard line;
}

bool wireguardserverReadLimits(server_t *state, const cJSON *settings)
{
    int64_t ingress = kDefaultMaxUnauthenticatedIngress;
    int64_t pending = kDefaultMaxPendingRekeyBytes;
    if (jsonGetObjectIntegerInRange(settings, "max-unauthenticated-ingress", 1, INT_MAX, &ingress) ==
            kJsonValueInvalid ||
        jsonGetObjectIntegerInRange(settings, "max-pending-rekey-bytes", 0, UINT32_MAX, &pending) == kJsonValueInvalid)
        return false;
    state->max_unauthenticated_ingress = (unsigned) ingress;
    state->max_pending_rekey_bytes     = (size_t) pending;
    return true;
}

tunnel_t *wireguardserverTunnelCreate(node_t *node)
{
    tunnel_t *t = tunnelCreate(node, sizeof(server_t), sizeof(server_line_t));
    if (t == NULL)
        return NULL;
    server_t *state = tunnelGetState(t);
    state->tunnel   = t;
    atomic_init(&state->ingress_count, 0);
    wireguardDispatchInit(&state->dispatch);
    if (! mutexTryInit(&state->bindings_lock))
    {
        tunnelDestroy(t);
        return NULL;
    }
    const cJSON *settings = node->node_settings_json;
    const cJSON *mode     = cJSON_GetObjectItemCaseSensitive(settings, "mode");
    const cJSON *key      = cJSON_GetObjectItemCaseSensitive(settings, "privatekey");
    const cJSON *auth     = cJSON_GetObjectItemCaseSensitive(settings, "auth-client-node-name");
    const cJSON *peers    = cJSON_GetObjectItemCaseSensitive(settings, "peers");
    if (! wireguardserverReadLimits(state, settings) || ! jsonObjectFieldStringsAreExact(settings, "mode") ||
        ! jsonObjectFieldStringsAreExact(settings, "privatekey") ||
        ! jsonObjectFieldStringsAreExact(settings, "auth-client-node-name") || ! cJSON_IsString(mode) ||
        (strcmp(mode->valuestring, "packet") != 0 && strcmp(mode->valuestring, "connection") != 0) ||
        ! cJSON_IsString(key) || node->hash_next == 0)
        goto fail;
    state->connection = strcmp(mode->valuestring, "connection") == 0;
    if (! wireguardCommonInit(
            &state->engine,
            key->valuestring,
            state,
            (wireguard_callbacks_t) {.output          = wireguardserverOutput,
                                     .inner           = wireguardserverInner,
                                     .can_initiate    = wireguardserverCanInitiate,
                                     .key_unavailable = wireguardserverKeyUnavailable,
                                     .authenticated   = wireguardserverAuthenticated,
                                     .candidate       = state->connection ? wireguardserverCandidate : NULL}) ||
        ! wireguardCommonConfigureMtu(&state->engine, settings))
        goto fail;
    if (state->connection)
    {
        if (! cJSON_IsString(auth) || auth->valuestring[0] == '\0' || peers != NULL ||
            cJSON_GetObjectItemCaseSensitive(settings, "presharedkey") != NULL)
            goto fail;
        state->auth_node = nodemanagerGetConfigNodeByName(node->node_manager_config, auth->valuestring);
        if (state->auth_node == NULL || strcmp(state->auth_node->type, "AuthenticationClient") != 0 ||
            ! wireguardserverCreatePipeline(state, node))
            goto fail;
    }
    else
    {
        if (auth != NULL || ! cJSON_IsArray(peers) || cJSON_GetArraySize(peers) < 1)
            goto fail;
        const cJSON *entry;
        cJSON_ArrayForEach(entry, peers)
        {
            size_t id;
            if (cJSON_GetObjectItemCaseSensitive(entry, "endpoint") != NULL ||
                ! wireguardCommonAddConfiguredPeer(&state->engine, entry, &id) ||
                wireguardserverCreateBinding(state, peerLookupByPeerIndex(&state->engine, id), NULL) == NULL)
                goto fail;
        }
    }
    t->fnInitU          = wireguardserverTunnelUpStreamInit;
    t->fnInitD          = absorb;
    t->fnEstU           = absorb;
    t->fnEstD           = absorb;
    t->fnPayloadU       = wireguardserverTunnelUpStreamPayload;
    t->fnPayloadD       = wireguardserverTunnelDownStreamPayload;
    t->fnFinU           = wireguardserverTunnelUpStreamFinish;
    t->fnFinD           = wireguardserverTunnelDownStreamFinish;
    t->fnPauseU         = wireguardserverTunnelUpStreamPause;
    t->fnResumeU        = wireguardserverTunnelUpStreamResume;
    t->fnPauseD         = absorb;
    t->fnResumeD        = absorb;
    t->onChain          = wireguardserverTunnelOnChain;
    t->onPrepare        = wireguardserverTunnelOnPrepare;
    t->onStart          = wireguardserverTunnelOnStart;
    t->onQuiesceRequest = wireguardserverTunnelOnQuiesceRequest;
    t->onWorkerQuiesce  = wireguardserverTunnelOnWorkerQuiesce;
    t->onWorkerStop     = wireguardserverTunnelOnWorkerStop;
    t->onDestroy        = wireguardserverTunnelDestroy;
    return t;
fail:
    LOGF("WireGuardServer: invalid mode, key, mtu, peer ranges, or authentication configuration");
    wireguardserverTunnelDestroy(t, wwLifecycleStartupRollback());
    return NULL;
}

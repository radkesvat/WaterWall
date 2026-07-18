#include "structure.h"

#include "loggers/network_logger.h"

static void configureTunnelCallbacks(tunnel_t *t)
{
    t->fnInitU    = &realityclientTunnelUpStreamInit;
    t->fnEstU     = &realityclientTunnelUpStreamEst;
    t->fnFinU     = &realityclientTunnelUpStreamFinish;
    t->fnPayloadU = &realityclientTunnelUpStreamPayload;
    t->fnPauseU   = &realityclientTunnelUpStreamPause;
    t->fnResumeU  = &realityclientTunnelUpStreamResume;

    t->fnInitD    = &realityclientTunnelDownStreamInit;
    t->fnEstD     = &realityclientTunnelDownStreamEst;
    t->fnFinD     = &realityclientTunnelDownStreamFinish;
    t->fnPayloadD = &realityclientTunnelDownStreamPayload;
    t->fnPauseD   = &realityclientTunnelDownStreamPause;
    t->fnResumeD  = &realityclientTunnelDownStreamResume;

    t->onChain   = &realityclientTunnelOnChain;
    t->onPrepare = &realityclientTunnelOnPrepair;
    t->onStart   = &realityclientTunnelOnStart;
    t->onStop    = &realityclientTunnelOnStop;
    t->onDestroy = &realityclientTunnelDestroy;
}

static bool parseAlgorithmFromSettings(const cJSON *settings, uint32_t *algorithm)
{
    const char  *setting_name = "algorithm";
    const cJSON *item         = cJSON_GetObjectItemCaseSensitive(settings, setting_name);
    if (item == NULL)
    {
        setting_name = "method";
        item         = cJSON_GetObjectItemCaseSensitive(settings, setting_name);
    }

    if (item == NULL)
    {
        *algorithm = kRealityClientAlgorithmChaCha20Poly1305;
        return true;
    }

    if (! cJSON_IsString(item) || item->valuestring == NULL || item->valuestring[0] == '\0')
    {
        LOGF("RealityClient: '%s' must be a supported non-empty string", setting_name);
        return false;
    }

    if (stricmp(item->valuestring, "chacha20poly1305") == 0 ||
        stricmp(item->valuestring, "chacha20-poly1305") == 0)
    {
        *algorithm = kRealityClientAlgorithmChaCha20Poly1305;
        return true;
    }
    if (stricmp(item->valuestring, "aes256gcm") == 0 || stricmp(item->valuestring, "aes-256-gcm") == 0 ||
        stricmp(item->valuestring, "aes-gcm") == 0)
    {
        *algorithm = kRealityClientAlgorithmAes256Gcm;
        return true;
    }

    LOGF("RealityClient: '%s' is unsupported. Use chacha20-poly1305 or aes-gcm", setting_name);
    return false;
}

static bool parseKdfIterations(const cJSON *settings, uint32_t *iterations)
{
    const cJSON *item = cJSON_GetObjectItemCaseSensitive(settings, "kdf-iterations");
    if (item == NULL)
    {
        *iterations = kRealityClientDefaultKdfIterations;
        return true;
    }

    if (! cJSON_IsNumber(item) || item->valuedouble != (double) item->valueint ||
        item->valuedouble < kRealityV2MinKdfIterations || item->valuedouble > kRealityV2MaxKdfIterations)
    {
        LOGF("RealityClient: 'kdf-iterations' must be an integer in range [1, 1000000]");
        return false;
    }

    *iterations = (uint32_t) item->valueint;
    return true;
}

static bool initializeInternalTlsClient(tunnel_t *t, node_t *node)
{
    realityclient_tstate_t *ts = tunnelGetState(t);

    ts->tls_settings = cJSON_Duplicate(node->node_settings_json, true);
    if (ts->tls_settings == NULL)
    {
        LOGF("RealityClient: failed to duplicate TLS settings");
        return false;
    }

    ts->tls_node                     = nodeTlsClientGet();
    ts->tls_node.name                = nodeMakeChildName(node, ".internal-tls-client");
    if (ts->tls_node.name == NULL)
    {
        LOGF("RealityClient: failed to configure internal TlsClient node");
        return false;
    }
    ts->tls_node.hash_name           = calcHashBytes(ts->tls_node.name, stringLength(ts->tls_node.name));
    ts->tls_node.next                = stringDuplicate(node->next);
    ts->tls_node.hash_next           = node->hash_next;
    ts->tls_node.node_settings_json  = ts->tls_settings;
    ts->tls_node.node_manager_config = node->node_manager_config;
    ts->tls_node.flags               = kNodeFlagNone;

    ts->tls_tunnel = tlsclientTunnelCreate(&ts->tls_node);
    if (ts->tls_tunnel == NULL)
    {
        LOGF("RealityClient: failed to create internal TlsClient");
        return false;
    }

    tlsclientTunnelEnableHandshakeTakeover(ts->tls_tunnel);
    return true;
}

static bool realityclientTunnelstateInitialize(tunnel_t *t, node_t *node)
{
    realityclient_tstate_t *ts             = tunnelGetState(t);
    const cJSON            *settings       = node->node_settings_json;
    char                   *password       = NULL;
    char                   *salt           = NULL;
    bool                    result         = false;

    memoryZeroAligned32(ts, tunnelGetCorrectAlignedStateSize(sizeof(*ts)));

    if (node->hash_next == 0)
    {
        LOGF("RealityClient: a next node is required");
        goto cleanup;
    }

    if (! checkJsonIsObjectAndHasChild(settings))
    {
        LOGF("RealityClient: 'settings' object is empty or invalid");
        goto cleanup;
    }

    if (cJSON_GetObjectItemCaseSensitive(settings, "max-frame-size") != NULL)
    {
        LOGF("RealityClient: 'max-frame-size' is obsolete; Reality v2 selects native TLS record sizing automatically");
        goto cleanup;
    }

    if (! parseAlgorithmFromSettings(settings, &ts->algorithm))
    {
        goto cleanup;
    }

    if (! getStringFromJsonObject(&password, settings, "password") ||
        stringLength(password) < kRealityV2MinCredentialByteLength ||
        stringLength(password) > kRealityV2MaxPasswordByteLength)
    {
        LOGF("RealityClient: 'password' must contain 1..32 bytes");
        goto cleanup;
    }

    const cJSON *salt_item = cJSON_GetObjectItemCaseSensitive(settings, "salt");
    if (salt_item == NULL)
    {
        salt = stringDuplicate("waterwall-reality");
    }
    else if (! getStringFromJsonObject(&salt, settings, "salt") ||
             stringLength(salt) < kRealityV2MinCredentialByteLength ||
             stringLength(salt) > kRealityV2MaxSaltByteLength)
    {
        LOGF("RealityClient: 'salt' must contain 1..32 bytes");
        goto cleanup;
    }

    if (! parseKdfIterations(settings, &ts->kdf_iterations))
    {
        goto cleanup;
    }

    if (ts->algorithm == kRealityClientAlgorithmAes256Gcm && ! aes256gcmIsAvailable())
    {
        LOGF("RealityClient: AES-GCM selected but it is unavailable in the active crypto backend");
        goto cleanup;
    }

    if (! realityV2DeriveRootKey(password, salt, ts->kdf_iterations, ts->root_key))
    {
        LOGF("RealityClient: failed to derive key from password");
        goto cleanup;
    }

    if (! initializeInternalTlsClient(t, node))
    {
        goto cleanup;
    }

    result = true;

cleanup:
    if (password != NULL)
    {
        memoryZero(password, stringLength(password));
        memoryFree(password);
    }
    memoryFree(salt);

    if (! result)
    {
        realityclientTunnelstateDestroy(ts);
    }

    return result;
}

tunnel_t *realityclientTunnelCreate(node_t *node)
{
    tunnel_t *t = tunnelCreate(node, sizeof(realityclient_tstate_t), sizeof(realityclient_lstate_t));
    configureTunnelCallbacks(t);

    if (! realityclientTunnelstateInitialize(t, node))
    {
        tunnelDestroy(t);
        return NULL;
    }

    return t;
}

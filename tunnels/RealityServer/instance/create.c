#include "structure.h"

#include "loggers/network_logger.h"

static void configureTunnelCallbacks(tunnel_t *t)
{
    t->fnInitU    = &realityserverTunnelUpStreamInit;
    t->fnEstU     = &realityserverTunnelUpStreamEst;
    t->fnFinU     = &realityserverTunnelUpStreamFinish;
    t->fnPayloadU = &realityserverTunnelUpStreamPayload;
    t->fnPauseU   = &realityserverTunnelUpStreamPause;
    t->fnResumeU  = &realityserverTunnelUpStreamResume;

    t->fnInitD    = &realityserverTunnelDownStreamInit;
    t->fnEstD     = &realityserverTunnelDownStreamEst;
    t->fnFinD     = &realityserverTunnelDownStreamFinish;
    t->fnPayloadD = &realityserverTunnelDownStreamPayload;
    t->fnPauseD   = &realityserverTunnelDownStreamPause;
    t->fnResumeD  = &realityserverTunnelDownStreamResume;

    t->onChain   = &realityserverTunnelOnChain;
    t->onPrepare = &realityserverTunnelOnPrepair;
    t->onStart   = &realityserverTunnelOnStart;
    t->onStop    = &realityserverTunnelOnStop;
    t->onDestroy = &realityserverTunnelDestroy;
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
        *algorithm = kRealityServerAlgorithmChaCha20Poly1305;
        return true;
    }

    if (! cJSON_IsString(item) || item->valuestring == NULL || item->valuestring[0] == '\0')
    {
        LOGF("RealityServer: '%s' must be a supported non-empty string", setting_name);
        return false;
    }

    if (stricmp(item->valuestring, "chacha20poly1305") == 0 || stricmp(item->valuestring, "chacha20-poly1305") == 0)
    {
        *algorithm = kRealityServerAlgorithmChaCha20Poly1305;
        return true;
    }
    if (stricmp(item->valuestring, "aes256gcm") == 0 || stricmp(item->valuestring, "aes-256-gcm") == 0 ||
        stricmp(item->valuestring, "aes-gcm") == 0)
    {
        *algorithm = kRealityServerAlgorithmAes256Gcm;
        return true;
    }

    LOGF("RealityServer: '%s' is unsupported. Use chacha20-poly1305 or aes-gcm", setting_name);
    return false;
}

static bool parseTls12GcmNoncePolicy(const cJSON *settings, uint8_t *policy)
{
    const cJSON *item = cJSON_GetObjectItemCaseSensitive(settings, "tls12-gcm-server-nonce-policy");
    if (item == NULL)
    {
        *policy = kRealityServerGcmNoncePolicyAuto;
        return true;
    }

    if (! cJSON_IsString(item) || item->valuestring == NULL || item->valuestring[0] == '\0')
    {
        LOGF("RealityServer: 'tls12-gcm-server-nonce-policy' must be a non-empty string: auto, sequence, counter, or "
             "random");
        return false;
    }

    if (stricmp(item->valuestring, "auto") == 0)
    {
        *policy = kRealityServerGcmNoncePolicyAuto;
        return true;
    }
    if (stricmp(item->valuestring, "sequence") == 0)
    {
        *policy = kRealityServerGcmNoncePolicySequence;
        return true;
    }
    if (stricmp(item->valuestring, "counter") == 0)
    {
        *policy = kRealityServerGcmNoncePolicyCounter;
        return true;
    }
    if (stricmp(item->valuestring, "random") == 0)
    {
        *policy = kRealityServerGcmNoncePolicyRandom;
        return true;
    }

    LOGF("RealityServer: 'tls12-gcm-server-nonce-policy' must be auto, sequence, counter, or random");
    return false;
}

static bool parseIntegerItem(const cJSON *item, uint32_t default_value, uint32_t minimum, uint32_t maximum,
                             uint32_t *value)
{
    if (item == NULL)
    {
        *value = default_value;
        return true;
    }

    if (! cJSON_IsNumber(item) || item->valuedouble != (double) item->valueint || item->valuedouble < minimum ||
        item->valuedouble > maximum)
    {
        return false;
    }

    *value = (uint32_t) item->valueint;
    return true;
}

static bool realityserverTunnelstateInitialize(realityserver_tstate_t *ts, node_t *node)
{
    const cJSON *settings         = node->node_settings_json;
    char        *password         = NULL;
    char        *salt             = NULL;
    char        *destination_name = NULL;
    bool         result           = false;

    memoryZeroAligned32(ts, tunnelGetCorrectAlignedStateSize(sizeof(*ts)));

    if (node->hash_next == 0)
    {
        LOGF("RealityServer: a next node is required for authorized traffic");
        goto cleanup;
    }

    if (! checkJsonIsObjectAndHasChild(settings))
    {
        LOGF("RealityServer: 'settings' object is empty or invalid");
        goto cleanup;
    }

    if (cJSON_GetObjectItemCaseSensitive(settings, "max-frame-size") != NULL)
    {
        LOGF("RealityServer: 'max-frame-size' is obsolete; Reality v2 selects native TLS record sizing automatically");
        goto cleanup;
    }

    if (! parseAlgorithmFromSettings(settings, &ts->algorithm))
    {
        goto cleanup;
    }

    if (! parseTls12GcmNoncePolicy(settings, &ts->tls12_gcm_server_nonce_policy))
    {
        goto cleanup;
    }

    if (! getStringFromJsonObject(&password, settings, "password") ||
        stringLength(password) < kRealityV2MinCredentialByteLength ||
        stringLength(password) > kRealityV2MaxPasswordByteLength)
    {
        LOGF("RealityServer: 'password' must contain 1..32 bytes");
        goto cleanup;
    }

    if (! getStringFromJsonObject(&destination_name, settings, "destination") || stringLength(destination_name) == 0)
    {
        LOGF("RealityServer: 'destination' must name the visitor target node");
        goto cleanup;
    }

    ts->destination_node = nodemanagerGetConfigNodeByName(node->node_manager_config, destination_name);
    if (ts->destination_node == NULL)
    {
        LOGF("RealityServer: destination node \"%s\" was not found", destination_name);
        goto cleanup;
    }

    const cJSON *salt_item = cJSON_GetObjectItemCaseSensitive(settings, "salt");
    if (salt_item == NULL)
    {
        salt = stringDuplicate("waterwall-reality");
    }
    else if (! getStringFromJsonObject(&salt, settings, "salt") ||
             stringLength(salt) < kRealityV2MinCredentialByteLength || stringLength(salt) > kRealityV2MaxSaltByteLength)
    {
        LOGF("RealityServer: 'salt' must contain 1..32 bytes");
        goto cleanup;
    }

    const cJSON *kdf_item = cJSON_GetObjectItemCaseSensitive(settings, "kdf-iterations");
    if (! parseIntegerItem(kdf_item,
                           kRealityServerDefaultKdfIterations,
                           kRealityV2MinKdfIterations,
                           kRealityV2MaxKdfIterations,
                           &ts->kdf_iterations))
    {
        LOGF("RealityServer: 'kdf-iterations' must be an integer in range [1, 1000000]");
        goto cleanup;
    }

    const char  *sniffing_name = "sniffing-attempts";
    const cJSON *sniffing_item = cJSON_GetObjectItemCaseSensitive(settings, sniffing_name);
    if (sniffing_item == NULL)
    {
        sniffing_name = "sniffing-counter";
        sniffing_item = cJSON_GetObjectItemCaseSensitive(settings, sniffing_name);
    }
    if (! parseIntegerItem(sniffing_item, kRealityServerDefaultSniffingAttempts, 1, 1024, &ts->sniffing_attempts))
    {
        LOGF("RealityServer: '%s' must be an integer in range [1, 1024]", sniffing_name);
        goto cleanup;
    }

    if (ts->algorithm == kRealityServerAlgorithmAes256Gcm && ! wCryptoAes256GcmIsAvailable())
    {
        LOGF("RealityServer: AES-GCM selected but it is unavailable in the active crypto backend");
        goto cleanup;
    }

    if (! realityV2DeriveRootKey(password, salt, ts->kdf_iterations, ts->root_key))
    {
        LOGF("RealityServer: failed to derive key from password");
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
    memoryFree(destination_name);

    if (! result)
    {
        realityserverTunnelstateDestroy(ts);
    }

    return result;
}

tunnel_t *realityserverTunnelCreate(node_t *node)
{
    tunnel_t *t = tunnelCreate(node, sizeof(realityserver_tstate_t), sizeof(realityserver_lstate_t));
    configureTunnelCallbacks(t);

    realityserver_tstate_t *ts = tunnelGetState(t);
    if (! realityserverTunnelstateInitialize(ts, node))
    {
        tunnelDestroy(t);
        return NULL;
    }

    return t;
}

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

static uint32_t parseAlgorithmFromSettings(const cJSON *settings)
{
    char    *algorithm = NULL;
    uint32_t result    = kRealityServerAlgorithmChaCha20Poly1305;

    if (! getStringFromJsonObject(&algorithm, settings, "algorithm"))
    {
        getStringFromJsonObject(&algorithm, settings, "method");
    }

    if (algorithm == NULL)
    {
        return result;
    }

    stringLowerCase(algorithm);

    if (stringCompare(algorithm, "chacha20poly1305") == 0 || stringCompare(algorithm, "chacha20-poly1305") == 0)
    {
        result = kRealityServerAlgorithmChaCha20Poly1305;
    }
    else if (stringCompare(algorithm, "aes256gcm") == 0 || stringCompare(algorithm, "aes-256-gcm") == 0 ||
             stringCompare(algorithm, "aes-gcm") == 0)
    {
        result = kRealityServerAlgorithmAes256Gcm;
    }
    else
    {
        result = 0;
    }

    memoryFree(algorithm);
    return result;
}

static uint8_t parseTls12GcmNoncePolicy(const cJSON *settings)
{
    char   *value  = NULL;
    uint8_t result = kRealityServerGcmNoncePolicyAuto;

    if (! getStringFromJsonObject(&value, settings, "tls12-gcm-server-nonce-policy"))
    {
        return result;
    }

    stringLowerCase(value);
    if (stringCompare(value, "auto") == 0)
    {
        result = kRealityServerGcmNoncePolicyAuto;
    }
    else if (stringCompare(value, "sequence") == 0)
    {
        result = kRealityServerGcmNoncePolicySequence;
    }
    else if (stringCompare(value, "counter") == 0)
    {
        result = kRealityServerGcmNoncePolicyCounter;
    }
    else if (stringCompare(value, "random") == 0)
    {
        result = kRealityServerGcmNoncePolicyRandom;
    }
    else
    {
        result = 0;
    }

    memoryFree(value);
    return result;
}

static bool deriveKeyFromPassword(const char *password, const char *salt, uint32_t iterations, uint8_t out_key[32])
{
    size_t password_len = stringLength(password);
    size_t salt_len     = stringLength(salt);

    if (password_len == 0)
    {
        return false;
    }

    if (iterations == 0)
    {
        iterations = 1;
    }

    if (-1 ==
        blake2s(out_key, 32, (const unsigned char *) salt, salt_len, (const unsigned char *) password, password_len))
    {
        return false;
    }

    for (uint32_t i = 1; i < iterations; ++i)
    {
        uint8_t  iter_block[36] = {0};
        uint32_t iter_be        = htobe32(i);

        memoryCopy(iter_block, out_key, 32);
        memoryCopy(iter_block + 32, &iter_be, sizeof(iter_be));

        if (-1 == blake2s(out_key, 32, (const unsigned char *) password, password_len, iter_block, sizeof(iter_block)))
        {
            memoryZero(iter_block, sizeof(iter_block));
            return false;
        }

        memoryZero(iter_block, sizeof(iter_block));
    }

    return true;
}

static bool realityserverTunnelstateInitialize(realityserver_tstate_t *ts, node_t *node)
{
    const cJSON *settings          = node->node_settings_json;
    char        *password          = NULL;
    char        *salt              = NULL;
    char        *destination_name  = NULL;
    int          kdf_iterations    = kRealityServerDefaultKdfIterations;
    int          sniffing_attempts = kRealityServerDefaultSniffingAttempts;
    bool         result            = false;

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

    ts->algorithm = parseAlgorithmFromSettings(settings);
    if (ts->algorithm != kRealityServerAlgorithmChaCha20Poly1305 && ts->algorithm != kRealityServerAlgorithmAes256Gcm)
    {
        LOGF("RealityServer: 'algorithm'/'method' is unsupported. Use chacha20-poly1305 or aes-gcm");
        goto cleanup;
    }

    ts->tls12_gcm_server_nonce_policy = parseTls12GcmNoncePolicy(settings);
    if (ts->tls12_gcm_server_nonce_policy == 0)
    {
        LOGF("RealityServer: 'tls12-gcm-server-nonce-policy' must be auto, sequence, counter, or random");
        goto cleanup;
    }

    if (! getStringFromJsonObject(&password, settings, "password") || stringLength(password) == 0)
    {
        LOGF("RealityServer: 'password' must be a non-empty string");
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

    getStringFromJsonObjectOrDefault(&salt, settings, "salt", "waterwall-reality");

    getIntFromJsonObject(&kdf_iterations, settings, "kdf-iterations");
    if (kdf_iterations <= 0 || kdf_iterations > 1000000)
    {
        LOGF("RealityServer: 'kdf-iterations' must be in range [1, 1000000]");
        goto cleanup;
    }

    if (! getIntFromJsonObject(&sniffing_attempts, settings, "sniffing-attempts"))
    {
        getIntFromJsonObject(&sniffing_attempts, settings, "sniffing-counter");
    }
    if (sniffing_attempts <= 0 || sniffing_attempts > 1024)
    {
        LOGF("RealityServer: 'sniffing-attempts' must be in range [1, 1024]");
        goto cleanup;
    }

    if (ts->algorithm == kRealityServerAlgorithmAes256Gcm && ! aes256gcmIsAvailable())
    {
        LOGF("RealityServer: AES-GCM selected but it is unavailable in the active crypto backend");
        goto cleanup;
    }

    ts->kdf_iterations    = (uint32_t) kdf_iterations;
    ts->sniffing_attempts = (uint32_t) sniffing_attempts;

    if (! deriveKeyFromPassword(password, salt, ts->kdf_iterations, ts->root_key))
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

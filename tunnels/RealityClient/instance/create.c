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
    t->onDestroy = &realityclientTunnelDestroy;
}

static uint32_t parseAlgorithmFromSettings(const cJSON *settings)
{
    char    *algorithm = NULL;
    uint32_t result    = kRealityClientAlgorithmChaCha20Poly1305;

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
        result = kRealityClientAlgorithmChaCha20Poly1305;
    }
    else if (stringCompare(algorithm, "aes256gcm") == 0 || stringCompare(algorithm, "aes-256-gcm") == 0 ||
             stringCompare(algorithm, "aes-gcm") == 0)
    {
        result = kRealityClientAlgorithmAes256Gcm;
    }
    else
    {
        result = 0;
    }

    memoryFree(algorithm);
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

    if (-1 == blake2s(out_key, 32, (const unsigned char *) salt, salt_len, (const unsigned char *) password,
                      password_len))
    {
        return false;
    }

    for (uint32_t i = 1; i < iterations; ++i)
    {
        uint8_t  iter_block[36] = {0};
        uint32_t iter_be        = htobe32(i);

        memoryCopy(iter_block, out_key, 32);
        memoryCopy(iter_block + 32, &iter_be, sizeof(iter_be));

        if (-1 == blake2s(out_key, 32, (const unsigned char *) password, password_len, iter_block,
                          sizeof(iter_block)))
        {
            wCryptoZero(iter_block, sizeof(iter_block));
            return false;
        }

        wCryptoZero(iter_block, sizeof(iter_block));
    }

    return true;
}

static char *makeInternalNodeName(const char *parent_name)
{
    const char *base = parent_name != NULL ? parent_name : "RealityClient";
    return stringConcat(base, ".internal-tls-client");
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
    ts->tls_node.name                = makeInternalNodeName(node->name);
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
    realityclient_tstate_t *ts       = tunnelGetState(t);
    const cJSON            *settings = node->node_settings_json;
    char                   *password = NULL;
    char                   *salt     = NULL;
    int                     kdf_iterations = kRealityClientDefaultKdfIterations;
    int                     max_frame_size = kRealityClientMaxFramePayload;
    bool                    result         = false;

    memoryZeroAligned32(ts, sizeof(*ts));

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

    ts->algorithm = parseAlgorithmFromSettings(settings);
    if (ts->algorithm != kRealityClientAlgorithmChaCha20Poly1305 && ts->algorithm != kRealityClientAlgorithmAes256Gcm)
    {
        LOGF("RealityClient: 'algorithm'/'method' is unsupported. Use chacha20-poly1305 or aes-gcm");
        goto cleanup;
    }

    if (! getStringFromJsonObject(&password, settings, "password") || stringLength(password) == 0)
    {
        LOGF("RealityClient: 'password' must be a non-empty string");
        goto cleanup;
    }

    getStringFromJsonObjectOrDefault(&salt, settings, "salt", "waterwall-reality");

    getIntFromJsonObject(&kdf_iterations, settings, "kdf-iterations");
    if (kdf_iterations <= 0 || kdf_iterations > 1000000)
    {
        LOGF("RealityClient: 'kdf-iterations' must be in range [1, 1000000]");
        goto cleanup;
    }

    getIntFromJsonObject(&max_frame_size, settings, "max-frame-size");
    if (max_frame_size <= 0 || max_frame_size > kRealityClientMaxFramePayload)
    {
        LOGF("RealityClient: 'max-frame-size' must be in range [1, %d]", kRealityClientMaxFramePayload);
        goto cleanup;
    }

    if (ts->algorithm == kRealityClientAlgorithmAes256Gcm && ! aes256gcmIsAvailable())
    {
        LOGF("RealityClient: AES-GCM selected but it is unavailable in the active crypto backend");
        goto cleanup;
    }

    ts->kdf_iterations    = (uint32_t) kdf_iterations;
    ts->max_frame_payload = (uint32_t) max_frame_size;

    if (! deriveKeyFromPassword(password, salt, ts->kdf_iterations, ts->key))
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
        wCryptoZero(password, stringLength(password));
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

#include "structure.h"

#include "loggers/network_logger.h"

static uint32_t normalizeAlgorithm(dynamic_value_t algorithm_dv)
{
    switch (algorithm_dv.status)
    {
    case kDvsEmpty:
        return kEncryptionAlgorithmChaCha20Poly1305;

    case kDvsFirstOption:
    case kDvsSecondOption:
    case kDvsThirdOption:
    case kDvsFourthOption:
        return kEncryptionAlgorithmChaCha20Poly1305;

    case kDvsFifthOption:
    case (kDvsFifthOption + 1):
    case (kDvsFifthOption + 2):
    case (kDvsFifthOption + 3):
        return kEncryptionAlgorithmAes256Gcm;

    case kDvsConstant:
        if (algorithm_dv.integer == kEncryptionAlgorithmChaCha20Poly1305 ||
            algorithm_dv.integer == kEncryptionAlgorithmAes256Gcm)
        {
            return algorithm_dv.integer;
        }
        return kDvsEmpty;

    default:
        return kDvsEmpty;
    }
}

static uint32_t parseAlgorithmFromSettings(const cJSON *settings)
{
    const cJSON    *algorithm_json = cJSON_GetObjectItemCaseSensitive(settings, "algorithm");
    dynamic_value_t algorithm_dv   = parseDynamicNumericValueFromJsonObject(settings,
                                                                          "algorithm",
                                                                          8,
                                                                          "chacha20-poly1305",
                                                                          "chacha20poly1305",
                                                                          "chacha20",
                                                                          "chacha",
                                                                          "aes-gcm",
                                                                          "aes256gcm",
                                                                          "aes-256-gcm",
                                                                          "aes256-gcm");

    if (algorithm_dv.status != kDvsEmpty)
    {
        return normalizeAlgorithm(algorithm_dv);
    }

    if (algorithm_json != NULL)
    {
        return kDvsEmpty;
    }

    const cJSON *method_json = cJSON_GetObjectItemCaseSensitive(settings, "method");
    if (method_json != NULL)
    {
        algorithm_dv = parseDynamicNumericValueFromJsonObject(settings,
                                                              "method",
                                                              8,
                                                              "chacha20-poly1305",
                                                              "chacha20poly1305",
                                                              "chacha20",
                                                              "chacha",
                                                              "aes-gcm",
                                                              "aes256gcm",
                                                              "aes-256-gcm",
                                                              "aes256-gcm");

        if (algorithm_dv.status == kDvsEmpty)
        {
            return kDvsEmpty;
        }

        return normalizeAlgorithm(algorithm_dv);
    }

    return kEncryptionAlgorithmChaCha20Poly1305;
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

    if (wCryptoBlake2s(
            out_key, 32, (const unsigned char *) salt, salt_len, (const unsigned char *) password, password_len) !=
        kWCryptoOk)
    {
        wCryptoZero(out_key, 32);
        return false;
    }

    for (uint32_t i = 1; i < iterations; i++)
    {
        uint8_t  iter_block[36] = {0};
        uint32_t iter_be        = htobe32(i);

        memoryCopy(iter_block, out_key, 32);
        memoryCopy(iter_block + 32, &iter_be, sizeof(iter_be));

        if (wCryptoBlake2s(
                out_key, 32, (const unsigned char *) password, password_len, iter_block, sizeof(iter_block)) !=
            kWCryptoOk)
        {
            wCryptoZero(iter_block, sizeof(iter_block));
            wCryptoZero(out_key, 32);
            return false;
        }

        wCryptoZero(iter_block, sizeof(iter_block));
    }

    return true;
}

static bool encryptionserverTunnelstateInitialize(encryptionserver_tstate_t *ts, const cJSON *settings)
{
    char    *password       = NULL;
    char    *salt           = NULL;
    int      kdf_iterations = kEncryptionDefaultKdfIterations;
    int      max_frame_size = kEncryptionDefaultMaxFramePayload;
    uint32_t algorithm;
    bool     result = false;

    memoryZeroAligned32(ts, tunnelGetCorrectAlignedStateSize(sizeof(*ts)));

    if (! checkJsonIsObjectAndHasChild(settings))
    {
        LOGF("EncryptionServer: 'settings' object is empty or invalid");
        goto cleanup;
    }

    algorithm = parseAlgorithmFromSettings(settings);
    if (algorithm != kEncryptionAlgorithmChaCha20Poly1305 && algorithm != kEncryptionAlgorithmAes256Gcm)
    {
        LOGF("EncryptionServer: 'algorithm'/'method' is unsupported. Use chacha20-poly1305 or aes-gcm");
        goto cleanup;
    }

    if (! getStringFromJsonObject(&password, settings, "password"))
    {
        LOGF("EncryptionServer: 'password' not set");
        goto cleanup;
    }

    if (stringLength(password) == 0)
    {
        LOGF("EncryptionServer: 'password' must not be empty");
        goto cleanup;
    }

    getStringFromJsonObjectOrDefault(&salt, settings, "salt", "waterwall-encryption");

    getIntFromJsonObject(&kdf_iterations, settings, "kdf-iterations");
    if (kdf_iterations <= 0 || kdf_iterations > 1000000)
    {
        LOGF("EncryptionServer: 'kdf-iterations' must be in range [1, 1000000]");
        goto cleanup;
    }

    getIntFromJsonObject(&max_frame_size, settings, "max-frame-size");
    if (max_frame_size <= 0 || max_frame_size > kEncryptionHardMaxFramePayload)
    {
        LOGF("EncryptionServer: 'max-frame-size' must be in range [1, %d]", kEncryptionHardMaxFramePayload);
        goto cleanup;
    }

    if (algorithm == kEncryptionAlgorithmAes256Gcm && ! wCryptoAes256GcmIsAvailable())
    {
        LOGF("EncryptionServer: AES-GCM selected but it is unavailable in the active crypto backend");
        goto cleanup;
    }

    ts->algorithm         = algorithm;
    ts->kdf_iterations    = (uint32_t) kdf_iterations;
    ts->max_frame_payload = (uint32_t) max_frame_size;

    if (! deriveKeyFromPassword(password, salt, ts->kdf_iterations, ts->key))
    {
        LOGF("EncryptionServer: failed to derive key from password");
        goto cleanup;
    }

    result = true;

cleanup:
    if (password != NULL)
    {
        memoryZero(password, stringLength(password));
        memoryFree(password);
    }

    if (salt != NULL)
    {
        memoryFree(salt);
    }

    if (! result)
    {
        encryptionserverTunnelstateDestroy(ts);
    }

    return result;
}

tunnel_t *encryptionserverTunnelCreate(node_t *node)
{
    tunnel_t *t = tunnelCreate(node, sizeof(encryptionserver_tstate_t), sizeof(encryptionserver_lstate_t));

    t->fnInitU    = &encryptionserverTunnelUpStreamInit;
    t->fnEstU     = &encryptionserverTunnelUpStreamEst;
    t->fnFinU     = &encryptionserverTunnelUpStreamFinish;
    t->fnPayloadU = &encryptionserverTunnelUpStreamPayload;
    t->fnPauseU   = &encryptionserverTunnelUpStreamPause;
    t->fnResumeU  = &encryptionserverTunnelUpStreamResume;

    t->fnInitD    = &encryptionserverTunnelDownStreamInit;
    t->fnEstD     = &encryptionserverTunnelDownStreamEst;
    t->fnFinD     = &encryptionserverTunnelDownStreamFinish;
    t->fnPayloadD = &encryptionserverTunnelDownStreamPayload;
    t->fnPauseD   = &encryptionserverTunnelDownStreamPause;
    t->fnResumeD  = &encryptionserverTunnelDownStreamResume;

    t->onPrepare = &encryptionserverTunnelOnPrepair;
    t->onStart   = &encryptionserverTunnelOnStart;
    t->onStop    = &encryptionserverTunnelOnStop;
    t->onDestroy = &encryptionserverTunnelDestroy;

    encryptionserver_tstate_t *ts       = tunnelGetState(t);
    const cJSON               *settings = node->node_settings_json;

    if (! encryptionserverTunnelstateInitialize(ts, settings))
    {
        tunnelDestroy(t);
        return NULL;
    }

    return t;
}

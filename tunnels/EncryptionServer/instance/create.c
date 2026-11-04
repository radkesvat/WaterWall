#include "structure.h"

#include "loggers/network_logger.h"

static uint32_t normalizeAlgorithm(dynamic_value_t algorithm_dv)
{
    switch (algorithm_dv.status)
    {
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

    case (kDvsFifthOption + 4):
        return kEncryptionAlgorithmXChaCha20Poly1305;

    case kDvsConstant:
        if (algorithm_dv.integer == kEncryptionAlgorithmChaCha20Poly1305 ||
            algorithm_dv.integer == kEncryptionAlgorithmAes256Gcm ||
            algorithm_dv.integer == kEncryptionAlgorithmXChaCha20Poly1305)
        {
            return algorithm_dv.integer;
        }
        return kDvsEmpty;

    default:
        return kDvsEmpty;
    }
}

static uint32_t parseAlgorithmFromSettings(const cJSON *settings, bool packet_mode)
{
    const cJSON    *algorithm_json = cJSON_GetObjectItemCaseSensitive(settings, "algorithm");
    dynamic_value_t algorithm_dv   = parseDynamicNumericValueFromJsonObject(settings,
                                                                          "algorithm",
                                                                          9,
                                                                          "chacha20-poly1305",
                                                                          "chacha20poly1305",
                                                                          "chacha20",
                                                                          "chacha",
                                                                          "aes-gcm",
                                                                          "aes256gcm",
                                                                          "aes-256-gcm",
                                                                          "aes256-gcm",
                                                                          "xchacha20-poly1305");

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
                                                              9,
                                                              "chacha20-poly1305",
                                                              "chacha20poly1305",
                                                              "chacha20",
                                                              "chacha",
                                                              "aes-gcm",
                                                              "aes256gcm",
                                                              "aes-256-gcm",
                                                              "aes256-gcm",
                                                              "xchacha20-poly1305");

        if (algorithm_dv.status == kDvsEmpty)
        {
            return kDvsEmpty;
        }

        return normalizeAlgorithm(algorithm_dv);
    }

    return packet_mode ? kEncryptionAlgorithmXChaCha20Poly1305 : kEncryptionAlgorithmChaCha20Poly1305;
}

static bool deriveKeyFromPassword(const char *password, const char *salt, uint32_t iterations, bool packet_mode,
                                  uint8_t out_key[32])
{
    size_t password_len = stringLength(password);
    size_t salt_len     = stringLength(salt);

    assert(password_len > 0 && iterations > 0);
    sha256_hash_t packet_password_key = {0};
    if (packet_mode &&
        wCryptoSHA256(&packet_password_key, (const unsigned char *) password, password_len) != kWCryptoOk)
        return false;
    const unsigned char *iteration_key     = packet_mode ? packet_password_key.bytes : (const unsigned char *) password;
    const size_t         iteration_key_len = packet_mode ? sizeof(packet_password_key.bytes) : password_len;

    if (wCryptoBlake2s(
            out_key, 32, (const unsigned char *) salt, salt_len, (const unsigned char *) password, password_len) !=
        kWCryptoOk)
    {
        wCryptoZero(out_key, 32);
        wCryptoZero(&packet_password_key, sizeof(packet_password_key));
        return false;
    }

    for (uint32_t i = 1; i < iterations; i++)
    {
        uint8_t  iter_block[36] = {0};
        uint32_t iter_be        = htobe32(i);

        memoryCopy(iter_block, out_key, 32);
        memoryCopy(iter_block + 32, &iter_be, sizeof(iter_be));

        if (wCryptoBlake2s(out_key, 32, iteration_key, iteration_key_len, iter_block, sizeof(iter_block)) != kWCryptoOk)
        {
            wCryptoZero(iter_block, sizeof(iter_block));
            wCryptoZero(out_key, 32);
            wCryptoZero(&packet_password_key, sizeof(packet_password_key));
            return false;
        }

        wCryptoZero(iter_block, sizeof(iter_block));
    }

    wCryptoZero(&packet_password_key, sizeof(packet_password_key));
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

    const cJSON *packet_mode = cJSON_GetObjectItemCaseSensitive(settings, "packet-mode");
    if (packet_mode != NULL && ! cJSON_IsBool(packet_mode))
    {
        LOGF("EncryptionServer: 'packet-mode' must be a boolean");
        goto cleanup;
    }
    ts->packet_mode = cJSON_IsTrue(packet_mode);
    algorithm       = parseAlgorithmFromSettings(settings, ts->packet_mode);
    if ((ts->packet_mode && algorithm != kEncryptionAlgorithmXChaCha20Poly1305) ||
        (! ts->packet_mode && algorithm != kEncryptionAlgorithmChaCha20Poly1305 &&
         algorithm != kEncryptionAlgorithmAes256Gcm))
    {
        LOGF("EncryptionServer: packet mode requires xchacha20-poly1305; stream mode requires chacha20-poly1305 or "
             "aes-gcm");
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

    if (ts->packet_mode && cJSON_GetObjectItemCaseSensitive(settings, "max-frame-size") != NULL)
    {
        LOGF("EncryptionServer: 'max-frame-size' applies only to stream mode");
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

    if (! deriveKeyFromPassword(password, salt, ts->kdf_iterations, ts->packet_mode, ts->key))
    {
        LOGF("EncryptionServer: failed to derive key from password");
        goto cleanup;
    }

    if (ts->packet_mode)
    {
        uint8_t base_key[32];
        memoryCopy(base_key, ts->key, sizeof(base_key));
        const bool derived = encryptionPacketDeriveKeys(base_key, ts->key, ts->packet_download_key);
        wCryptoZero(base_key, sizeof(base_key));
        if (! derived)
        {
            LOGF("EncryptionServer: failed to derive packet direction keys");
            goto cleanup;
        }
        atomicLogRateLimiterInitialize(&ts->packet_drop_log_limiter);
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
        encryptionserverTunnelstateDestroy(ts);
    }

    return result;
}

tunnel_t *encryptionserverTunnelCreate(node_t *node)
{
    const cJSON *settings       = node->node_settings_json;
    const cJSON *packet_setting = cJSON_GetObjectItemCaseSensitive(settings, "packet-mode");
    const bool   packet_mode    = cJSON_IsTrue(packet_setting);
    if (packet_mode)
    {
        node->layer_group           = kNodeLayer3;
        node->layer_group_prev_node = kNodeLayer3;
        node->layer_group_next_node = kNodeLayer3;
        node->required_padding_left = kEncryptionPacketNonceSize;
    }
    tunnel_t *t = packet_mode
                      ? packettunnelCreate(node, sizeof(encryptionserver_tstate_t), 0)
                      : tunnelCreate(node, sizeof(encryptionserver_tstate_t), sizeof(encryptionserver_lstate_t));
    if (t == NULL)
        return NULL;
    encryptionserver_tstate_t *ts = tunnelGetState(t);
    if (! encryptionserverTunnelstateInitialize(ts, settings))
    {
        tunnelDestroy(t);
        return NULL;
    }
    if (packet_mode)
    {
        t->fnPayloadU = &encryptionserverPacketUpStreamPayload;
        t->fnPayloadD = &encryptionserverPacketDownStreamPayload;
    }
    else
    {
        t->fnInitU    = &encryptionserverTunnelUpStreamInit;
        t->fnFinU     = &encryptionserverTunnelUpStreamFinish;
        t->fnPayloadU = &encryptionserverTunnelUpStreamPayload;
        t->fnFinD     = &encryptionserverTunnelDownStreamFinish;
        t->fnPayloadD = &encryptionserverTunnelDownStreamPayload;
    }
    t->onDestroy = &encryptionserverTunnelDestroy;
    return t;
}

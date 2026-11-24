#include "WireGuardCommon/engine.h"

#include "loggers/network_logger.h"

static bool decodeKey(const cJSON *value, uint8_t key[32])
{
    return cJSON_IsString(value) && value->valuestring != NULL &&
           strlen(value->valuestring) == BASE64_ENCODE_OUT_SIZE(32) &&
           wwBase64DecodeCanonical(value->valuestring, (unsigned int) strlen(value->valuestring), key, 32) == 32;
}

bool wireguardCommonInit(wireguard_device_t *device, const char *private_key, void *context,
                         wireguard_callbacks_t callbacks)
{
    uint8_t    key[32] = {0};
    const bool valid =
        private_key != NULL && strlen(private_key) == BASE64_ENCODE_OUT_SIZE(32) &&
        wwBase64DecodeCanonical(private_key, (unsigned int) strlen(private_key), key, sizeof(key)) == 32 &&
        wireguardInit() == kWCryptoOk && wireguardDeviceInit(device, key);
    wCryptoZero(key, sizeof(key));
    if (valid)
    {
        device->context   = context;
        device->callbacks = callbacks;
    }
    else
    {
        *device = (wireguard_device_t) {0};
    }
    return valid;
}

bool wireguardCommonConfigureMtu(wireguard_device_t *device, const cJSON *settings)
{
    int64_t                   mtu    = min(CORE_DEFAULT_MTU, WIREGUARDIF_MTU);
    const json_value_status_t status = jsonGetObjectIntegerInRange(settings, "mtu", 68, UINT16_MAX, &mtu);
    if (status == kJsonValueInvalid || mtu < 68)
    {
        LOGF("WireGuard: settings.mtu must be an integer between 68 and 65535%s",
             status == kJsonValueMissing ? "; inherited core misc.mtu is too small; set an explicit node mtu" : "");
        return false;
    }
    device->padding_mtu = (uint16_t) mtu;
    return true;
}

bool wireguardCommonAddConfiguredPeer(wireguard_device_t *device, const cJSON *settings, size_t *index)
{
    const cJSON *public_key = cJSON_GetObjectItemCaseSensitive(settings, "publickey");
    const cJSON *psk        = cJSON_GetObjectItemCaseSensitive(settings, "presharedkey");
    const cJSON *allowed    = cJSON_GetObjectItemCaseSensitive(settings, "allowedips");
    const cJSON *keepalive  = cJSON_GetObjectItemCaseSensitive(settings, "persistentkeepalive");
    uint8_t      key[32] = {0}, preshared[32] = {0};
    bool         result = false;
    if (! jsonObjectFieldStringsAreExact(settings, "publickey") ||
        ! jsonObjectFieldStringsAreExact(settings, "presharedkey") ||
        ! jsonObjectFieldStringsAreExact(settings, "allowedips") || ! decodeKey(public_key, key) ||
        (psk != NULL && ! decodeKey(psk, preshared)) || ! cJSON_IsString(allowed) || allowed->valuestring == NULL ||
        allowed->valuestring[0] == '\0' ||
        (keepalive != NULL &&
         (! cJSON_IsNumber(keepalive) || keepalive->valuedouble < 0 || keepalive->valuedouble > UINT16_MAX ||
          keepalive->valuedouble != (double) keepalive->valueint)))
        goto finish;

    wireguard_peer_t *peer = wireguardPeerCreate(device, key, psk != NULL ? preshared : NULL);
    if (peer == NULL)
        goto finish;
    *index                   = peer->id;
    peer->keepalive_interval = keepalive != NULL ? (uint16_t) keepalive->valueint : 0;
    char    *ranges          = stringNewWithoutSpace(allowed->valuestring);
    char    *cursor          = ranges;
    unsigned count           = 0;
    while (cursor != NULL)
    {
        char *comma = strchr(cursor, ',');
        if (comma != NULL)
            *comma = '\0';
        ip_addr_t ip, mask;
        if (count == WIREGUARD_MAX_SRC_IPS || ! verifyIPCdir(cursor) ||
            parseIPWithSubnetMask(cursor, &ip, &mask) == ERR_ARG ||
            wireguardifAddAllowedIp(device, *index, &ip, &mask) != ERR_OK)
            break;
        ++count;
        cursor = comma != NULL ? comma + 1 : NULL;
    }
    result = cursor == NULL && count > 0;
    memoryFree(ranges);
    if (! result)
        discard wireguardifRemovePeer(device, *index);
finish:
    wCryptoZero(key, sizeof(key));
    wCryptoZero(preshared, sizeof(preshared));
    if (! result)
        LOGE("WireGuard: invalid peer key, allowedips, keepalive or duplicate peer");
    return result;
}

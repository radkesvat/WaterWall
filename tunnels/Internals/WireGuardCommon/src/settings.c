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
    return valid;
}

bool wireguardCommonRangesOverlap(const wireguard_allowed_ip_t *a, const wireguard_allowed_ip_t *b)
{
    if (! a->valid || ! b->valid || a->ip.type != b->ip.type)
        return false;
    if (IP_IS_V4(&a->ip))
    {
        const uint32_t mask = ip_2_ip4(&a->mask)->addr & ip_2_ip4(&b->mask)->addr;
        return (ip_2_ip4(&a->ip)->addr & mask) == (ip_2_ip4(&b->ip)->addr & mask);
    }
    for (int i = 0; i < 4; ++i)
    {
        const uint32_t mask = ip_2_ip6(&a->mask)->addr[i] & ip_2_ip6(&b->mask)->addr[i];
        if ((ip_2_ip6(&a->ip)->addr[i] & mask) != (ip_2_ip6(&b->ip)->addr[i] & mask))
            return false;
    }
    return true;
}

bool wireguardCommonAddConfiguredPeer(wireguard_device_t *device, const cJSON *settings, uint8_t *index)
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
          keepalive->valuedouble != (double) keepalive->valueint)) ||
        peerLookupByPubkey(device, key) != NULL)
        goto finish;

    wireguard_peer_t *peer = peerAlloc(device);
    if (peer == NULL || ! wireguardPeerInit(device, peer, key, psk != NULL ? preshared : NULL))
        goto finish;
    *index                   = wireguardPeerIndex(device, peer);
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
        LOGE("WireGuard: invalid peer key, allowedips, keepalive, duplicate key or peer capacity exceeded");
    return result;
}

#include "structure.h"

#include "loggers/network_logger.h"

static void rawsocketSetFullIpv4Mask(ip_addr_t *mask)
{
    mask->type            = IPADDR_TYPE_V4;
    mask->u_addr.ip4.addr = lwip_htonl(0xFFFFFFFFU);
}

static bool rawsocketParseIpv4CaptureRange(ipmask_t *dest, const char *value, const char *json_path)
{
    ip4_addr_t ip4;
    uint32_t   mask_host = 0xFFFFFFFFU;

    if (value == NULL || value[0] == '\0')
    {
        LOGF("JSON Error: %s (string field) : expected an IPv4 address or IPv4 CIDR range", json_path);
        return false;
    }

    if (stringChr(value, '/') == NULL)
    {
        if (ip4AddrAddressToNetwork(value, &ip4) == 0)
        {
            LOGF("JSON Error: %s (string field) : expected a single IPv4 address or IPv4 CIDR range", json_path);
            return false;
        }

        dest->ip.type       = IPADDR_TYPE_V4;
        dest->ip.u_addr.ip4 = ip4;
        rawsocketSetFullIpv4Mask(&dest->mask);
        return true;
    }

    char ip_part[40];
    int  prefix_len = -1;
    char extra      = '\0';

    if (sscanf(value, "%39[^/]/%d%c", ip_part, &prefix_len, &extra) != 2 || prefix_len < 0 || prefix_len > 32)
    {
        LOGF("JSON Error: %s (string field) : expected an IPv4 CIDR range with prefix 0..32", json_path);
        return false;
    }

    if (ip4AddrAddressToNetwork(ip_part, &ip4) == 0)
    {
        LOGF("JSON Error: %s (string field) : expected an IPv4 CIDR range, IPv6 is not supported", json_path);
        return false;
    }

    if (prefix_len == 0)
    {
        mask_host = 0;
    }
    else if (prefix_len < 32)
    {
        mask_host = 0xFFFFFFFFU << (32U - (uint32_t) prefix_len);
    }

    dest->ip.type              = IPADDR_TYPE_V4;
    dest->ip.u_addr.ip4.addr   = lwip_htonl(lwip_ntohl(ip4.addr) & mask_host);
    dest->mask.type            = IPADDR_TYPE_V4;
    dest->mask.u_addr.ip4.addr = lwip_htonl(mask_host);

    return true;
}

static bool rawsocketLoadCaptureRanges(rawsocket_tstate_t *state, const cJSON *settings)
{
    const cJSON *ranges_json = cJSON_GetObjectItemCaseSensitive(settings, "capture-ips");
    if (ranges_json == NULL)
    {
        ranges_json = cJSON_GetObjectItemCaseSensitive(settings, "listen-ips");
    }

    if (ranges_json != NULL)
    {
        if (! cJSON_IsArray(ranges_json) || cJSON_GetArraySize(ranges_json) <= 0)
        {
            LOGF("JSON Error: RawSocket->settings->capture-ips (array field) : expected a non-empty array of IPv4 "
                 "addresses or IPv4 CIDR ranges");
            return false;
        }

        const int range_count = cJSON_GetArraySize(ranges_json);
        size_t    ranges_size;
        if (! memoryTryComputeArraySize((size_t) range_count, sizeof(ipmask_t), &ranges_size))
        {
            LOGF("JSON Error: RawSocket->settings->capture-ips (array field) : range array is too large");
            return false;
        }
        ipmask_t *ranges = memoryAllocateZero(ranges_size);
        if (ranges == NULL)
        {
            LOGE("RawSocket: failed to allocate capture ranges");
            return false;
        }

        for (int i = 0; i < range_count; ++i)
        {
            const cJSON *range_json = cJSON_GetArrayItem(ranges_json, i);
            char         json_path[128];
            stringNPrintf(json_path, sizeof(json_path), "RawSocket->settings->capture-ips[%d]", i);

            if (! cJSON_IsString(range_json) || range_json->valuestring == NULL)
            {
                LOGF("JSON Error: %s (string field) : each entry must be an IPv4 address or IPv4 CIDR range",
                     json_path);
                memoryFree(ranges);
                return false;
            }

            if (! rawsocketParseIpv4CaptureRange(&ranges[i], range_json->valuestring, json_path))
            {
                memoryFree(ranges);
                return false;
            }
        }
        state->capture_ranges      = ranges;
        state->capture_range_count = (uint32_t) range_count;
        return true;
    }

    const cJSON *legacy_capture_ip = cJSON_GetObjectItemCaseSensitive(settings, "capture-ip");
    if (! cJSON_IsString(legacy_capture_ip) || legacy_capture_ip->valuestring == NULL)
    {
        LOGF("JSON Error: RawSocket->settings->capture-ips (array field) : expected a non-empty array of IPv4 "
             "addresses or IPv4 CIDR ranges");
        return false;
    }

    ipmask_t *range = memoryAllocateZero(sizeof(*range));
    if (range == NULL)
    {
        LOGE("RawSocket: failed to allocate the legacy capture range");
        return false;
    }
    if (! rawsocketParseIpv4CaptureRange(range, legacy_capture_ip->valuestring, "RawSocket->settings->capture-ip"))
    {
        memoryFree(range);
        return false;
    }
    state->capture_ranges      = range;
    state->capture_range_count = 1;
    return true;
}

static char *rawsocketDuplicateSettingOrDefault(const cJSON *settings, const char *key, const char *fallback)
{
    const cJSON *value  = cJSON_GetObjectItemCaseSensitive(settings, key);
    const char  *source = cJSON_IsString(value) && value->valuestring != NULL ? value->valuestring : fallback;
    return stringDuplicate(source);
}

tunnel_t *rawsocketCreate(node_t *node)
{
    tunnel_t *t = packettunnelCreate(node, sizeof(rawsocket_tstate_t), 0);
    if (! t)
    {
        return NULL;
    }

    t->onStart   = &rawsocketOnStart;
    t->onStop    = &rawsocketOnStop;
    t->onDestroy = &rawsocketDestroy;

    const packet_lifecycle_anchor_direction_t direction =
        node->hash_next != 0 ? kPacketLifecycleAnchorPublishUpstream : kPacketLifecycleAnchorPublishDownstream;
    if (! packettunnelConfigureLifecycleAnchor(t, "RawSocket", rawsocketWriteStreamPayload, direction))
    {
        tunnelDestroy(t);
        return NULL;
    }

    rawsocket_tstate_t *state    = tunnelGetState(t);
    const cJSON        *settings = node->node_settings_json;

    // not forced
    state->capture_device_name =
        rawsocketDuplicateSettingOrDefault(settings, "capture-device-name", "unnamed-capture-device");
    state->raw_device_name = rawsocketDuplicateSettingOrDefault(settings, "raw-device-name", "unnamed-raw-device");
    if (state->capture_device_name == NULL || state->raw_device_name == NULL)
    {
        LOGE("RawSocket: failed to allocate device names");
        rawsocketDestroy(t);
        return NULL;
    }

    dynamic_value_t fmode =
        parseDynamicNumericValueFromJsonObject(settings, "capture-filter-mode", 2, "source-ip", "dest-ip");
    if (fmode.status < kDvsSourceIp)
    {
        LOGF("JSON Error: RawSocket->settings->capture-filter-mode (string field) : mode is not specified or invalid");
        rawsocketDestroy(t);
        return NULL;
    }

    if (fmode.status == kDvsSourceIp)
    {
        ;
    }
    else
    {
        LOGF("RawSocket cannot yet capture outgoing, use tun device for that");
        rawsocketDestroy(t);
        return NULL;
    }

    if (! rawsocketLoadCaptureRanges(state, settings))
    {
        rawsocketDestroy(t);
        return NULL;
    }

    getIntFromJsonObjectOrDefault((&state->firewall_mark), settings, "mark", 0);
    return t;
}

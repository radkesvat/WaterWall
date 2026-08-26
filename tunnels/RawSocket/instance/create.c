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
    const char  *field_name  = "capture-ips";
    const cJSON *ranges_json = cJSON_GetObjectItemCaseSensitive(settings, field_name);
    if (ranges_json == NULL)
    {
        field_name  = "listen-ips";
        ranges_json = cJSON_GetObjectItemCaseSensitive(settings, field_name);
    }
    if (ranges_json == NULL)
    {
        field_name  = "capture-ip";
        ranges_json = cJSON_GetObjectItemCaseSensitive(settings, field_name);
    }
    if (ranges_json == NULL)
    {
        return true;
    }

    const bool is_array = cJSON_IsArray(ranges_json);
    int        range_count;
    if (cJSON_IsString(ranges_json) && ranges_json->valuestring != NULL)
    {
        range_count = 1;
    }
    else if (is_array)
    {
        range_count = cJSON_GetArraySize(ranges_json);
    }
    else
    {
        LOGF("JSON Error: RawSocket->settings->%s (string or array field) : expected an IPv4 address, IPv4 CIDR "
             "range, or an array of them",
             field_name);
        return false;
    }

    if (range_count == 0)
    {
        return true;
    }

    size_t ranges_size;
    if (range_count < 0 || ! memoryTryComputeArraySize((size_t) range_count, sizeof(ipmask_t), &ranges_size))
    {
        LOGF("JSON Error: RawSocket->settings->%s (string or array field) : range array is too large", field_name);
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
        const cJSON *range_json = is_array ? cJSON_GetArrayItem(ranges_json, i) : ranges_json;
        char         json_path[128];

        if (is_array)
        {
            stringNPrintf(json_path, sizeof(json_path), "RawSocket->settings->%s[%d]", field_name, i);
        }
        else
        {
            stringNPrintf(json_path, sizeof(json_path), "RawSocket->settings->%s", field_name);
        }

        if (! cJSON_IsString(range_json) || range_json->valuestring == NULL)
        {
            LOGF("JSON Error: %s (string field) : each entry must be an IPv4 address or IPv4 CIDR range", json_path);
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

    t->onStart          = &rawsocketOnStart;
    t->onQuiesceRequest = &rawsocketOnQuiesceRequest;
    t->onQuiesceWait    = &rawsocketOnQuiesceWait;
    t->onDestroy        = &rawsocketDestroy;

    const packet_lifecycle_anchor_direction_t direction =
        node->hash_next != 0 ? kPacketLifecycleAnchorPublishUpstream : kPacketLifecycleAnchorPublishDownstream;
    if (! packettunnelConfigureLifecycleAnchor(t, "RawSocket", rawsocketWriteStreamPayload, direction))
    {
        tunnelDestroy(t);
        return NULL;
    }

    rawsocket_tstate_t *state    = tunnelGetState(t);
    const cJSON        *settings = node->node_settings_json;

    if (! rawsocketLoadCaptureRanges(state, settings))
    {
        rawsocketDestroy(t, wwLifecycleStartupRollback());
        return NULL;
    }

    const cJSON *skip_sysctl = cJSON_GetObjectItemCaseSensitive(settings, "skip-sysctl");
    if (skip_sysctl != NULL && ! cJSON_IsBool(skip_sysctl))
    {
        LOGF("JSON Error: RawSocket->settings->skip-sysctl (boolean field) : expected true or false");
        rawsocketDestroy(t, wwLifecycleStartupRollback());
        return NULL;
    }
    state->skip_sysctl = cJSON_IsTrue(skip_sysctl);

    state->raw_device_name = rawsocketDuplicateSettingOrDefault(settings, "raw-device-name", "unnamed-raw-device");
    if (state->capture_range_count > 0)
    {
        state->capture_device_name =
            rawsocketDuplicateSettingOrDefault(settings, "capture-device-name", "unnamed-capture-device");
    }
    if (state->raw_device_name == NULL || (state->capture_range_count > 0 && state->capture_device_name == NULL))
    {
        LOGE("RawSocket: failed to allocate device names");
        rawsocketDestroy(t, wwLifecycleStartupRollback());
        return NULL;
    }

    if (state->capture_range_count > 0)
    {
        dynamic_value_t fmode =
            parseDynamicNumericValueFromJsonObject(settings, "capture-filter-mode", 2, "source-ip", "dest-ip");
        if (fmode.status < kDvsSourceIp)
        {
            LOGF("JSON Error: RawSocket->settings->capture-filter-mode (string field) : mode is not specified or "
                 "invalid");
            rawsocketDestroy(t, wwLifecycleStartupRollback());
            return NULL;
        }

        if (fmode.status != kDvsSourceIp)
        {
            LOGF("RawSocket cannot yet capture outgoing, use tun device for that");
            rawsocketDestroy(t, wwLifecycleStartupRollback());
            return NULL;
        }
    }

    getIntFromJsonObjectOrDefault((&state->firewall_mark), settings, "mark", 0);
    return t;
}

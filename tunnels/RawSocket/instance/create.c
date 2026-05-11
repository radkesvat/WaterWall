#include "structure.h"

#include "loggers/network_logger.h"

static void rawsocketSetFullIpv4Mask(ip_addr_t *mask)
{
    mask->type                = IPADDR_TYPE_V4;
    mask->u_addr.ip4.addr     = lwip_htonl(0xFFFFFFFFU);
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

        dest->ip.type            = IPADDR_TYPE_V4;
        dest->ip.u_addr.ip4      = ip4;
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

    dest->ip.type             = IPADDR_TYPE_V4;
    dest->ip.u_addr.ip4.addr  = lwip_htonl(lwip_ntohl(ip4.addr) & mask_host);
    dest->mask.type           = IPADDR_TYPE_V4;
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
            LOGF("JSON Error: RawSocket->settings->capture-ips (array field) : expected a non-empty array of IPv4 addresses or IPv4 CIDR ranges");
            return false;
        }

        const int range_count = cJSON_GetArraySize(ranges_json);
        state->capture_ranges = memoryAllocate((size_t) range_count * sizeof(*(state->capture_ranges)));
        state->capture_range_count = (uint32_t) range_count;

        for (int i = 0; i < range_count; ++i)
        {
            const cJSON *range_json = cJSON_GetArrayItem(ranges_json, i);
            char         json_path[128];
            stringNPrintf(json_path, sizeof(json_path), "RawSocket->settings->capture-ips[%d]", i);

            if (! cJSON_IsString(range_json) || range_json->valuestring == NULL)
            {
                LOGF("JSON Error: %s (string field) : each entry must be an IPv4 address or IPv4 CIDR range",
                     json_path);
                return false;
            }

            if (! rawsocketParseIpv4CaptureRange(&(state->capture_ranges[i]), range_json->valuestring, json_path))
            {
                return false;
            }
        }
        return true;
    }

    char *legacy_capture_ip = NULL;
    if (! getStringFromJsonObject(&legacy_capture_ip, settings, "capture-ip"))
    {
        LOGF("JSON Error: RawSocket->settings->capture-ips (array field) : expected a non-empty array of IPv4 addresses or IPv4 CIDR ranges");
        return false;
    }

    state->capture_ranges = memoryAllocate(sizeof(*(state->capture_ranges)));
    state->capture_range_count = 1;
    const bool ok = rawsocketParseIpv4CaptureRange(&(state->capture_ranges[0]), legacy_capture_ip,
                                                   "RawSocket->settings->capture-ip");
    memoryFree(legacy_capture_ip);
    return ok;
}

tunnel_t *rawsocketCreate(node_t *node)
{
    tunnel_t *t = tunnelCreate(node, sizeof(rawsocket_tstate_t), sizeof(rawsocket_lstate_t));

    t->fnInitU    = &rawsocketUpStreamInit;
    t->fnEstU     = &rawsocketUpStreamEst;
    t->fnFinU     = &rawsocketUpStreamFinish;
    t->fnPayloadU = &rawsocketUpStreamPayload;
    t->fnPauseU   = &rawsocketUpStreamPause;
    t->fnResumeU  = &rawsocketUpStreamResume;

    t->fnInitD    = &rawsocketDownStreamInit;
    t->fnEstD     = &rawsocketDownStreamEst;
    t->fnFinD     = &rawsocketDownStreamFinish;
    t->fnPayloadD = &rawsocketDownStreamPayload;
    t->fnPauseD   = &rawsocketDownStreamPause;
    t->fnResumeD  = &rawsocketDownStreamResume;

    t->onPrepare = &rawsocketOnPrepair;
    t->onStart   = &rawsocketOnStart;
    t->onDestroy = &rawsocketDestroy;

    rawsocket_tstate_t *state    = tunnelGetState(t);
    const cJSON        *settings = node->node_settings_json;

    // not forced
    getStringFromJsonObjectOrDefault(&(state->capture_device_name), settings, "capture-device-name",
                                     "unnamed-capture-device");
    getStringFromJsonObjectOrDefault(&(state->raw_device_name), settings, "raw-device-name", "unnamed-raw-device");

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
    state->write_direction_upstream = (node->hash_next != 0x0);

    return t;
}

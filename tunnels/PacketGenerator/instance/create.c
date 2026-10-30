#include "structure.h"

#include "loggers/network_logger.h"

static bool packetgeneratorProtocolModeUsesPorts(uint8_t protocol_mode)
{
    return protocol_mode == kPacketGeneratorProtocolTcp || protocol_mode == kPacketGeneratorProtocolUdp ||
           protocol_mode == kPacketGeneratorProtocolAll;
}

static bool packetgeneratorParseIpv4String(uint32_t *dest, const char *ipbuf, const char *json_path)
{
    ip4_addr_t parsed_ipv4;

    if (ipbuf == NULL || ipbuf[0] == '\0')
    {
        LOGF("JSON Error: %s (string field) : expected a single IPv4 address", json_path);
        return false;
    }

    if (ip4AddrAddressToNetwork(ipbuf, &parsed_ipv4) == 0)
    {
        LOGF("JSON Error: %s (string field) : expected a single IPv4 address", json_path);
        return false;
    }

    *dest = parsed_ipv4.addr;
    return true;
}

static bool packetgeneratorParseSourceRange(packetgenerator_source_range_t *range, const char *cidr,
                                            const char *json_path)
{
    ip_addr_t ip;
    ip_addr_t subnet_mask;
    uint8_t   prefix_length = 0;

    if (cidr == NULL || cidr[0] == '\0')
    {
        LOGF("JSON Error: %s (string field) : expected an IPv4 CIDR range", json_path);
        return false;
    }

    if (! verifyIPCdir(cidr))
    {
        LOGF("JSON Error: %s (string field) : invalid IPv4 CIDR range", json_path);
        return false;
    }

    if (parseIPWithSubnetMaskAndPrefix(cidr, &ip, &subnet_mask, &prefix_length) != 4)
    {
        LOGF("JSON Error: %s (string field) : expected an IPv4 CIDR range", json_path);
        return false;
    }

    range->base_host     = lwip_ntohl(ip.u_addr.ip4.addr) & lwip_ntohl(subnet_mask.u_addr.ip4.addr);
    range->prefix_length = prefix_length;
    range->count         = 1ULL << (32U - prefix_length);
    return true;
}

static bool packetgeneratorLoadSourceRanges(packetgenerator_tstate_t *state, const cJSON *settings)
{
    const char  *field_name = "source-ipv4-range";
    const cJSON *range_json = cJSON_GetObjectItemCaseSensitive(settings, field_name);
    if (range_json == NULL)
    {
        range_json = cJSON_GetObjectItemCaseSensitive(settings, "source-ip4-range");
    }

    if (range_json == NULL)
    {
        LOGF("JSON Error: PacketGenerator->settings->source-ipv4-range (string or array field) : expected one or more "
             "IPv4 "
             "CIDR ranges");
        return false;
    }

    const cJSON *items       = range_json;
    int          range_count = 0;

    if (cJSON_IsString(range_json) && range_json->valuestring != NULL)
    {
        range_count = 1;
    }
    else if (cJSON_IsArray(range_json))
    {
        range_count = cJSON_GetArraySize(range_json);
    }

    if (range_count <= 0)
    {
        LOGF("JSON Error: PacketGenerator->settings->source-ipv4-range (string or array field) : expected one or more "
             "IPv4 "
             "CIDR ranges");
        return false;
    }

    size_t source_ranges_size;
    if (! memoryTryComputeArraySize((size_t) range_count, sizeof(*(state->source_ranges)), &source_ranges_size))
    {
        LOGF("PacketGenerator: source range metadata size is not representable");
        return false;
    }

    state->source_ranges      = memoryAllocateZero(source_ranges_size);
    state->source_range_count = (uint32_t) range_count;

    uint64_t total_source_count = 0;

    for (int i = 0; i < range_count; ++i)
    {
        const cJSON *item = NULL;
        char         json_path[128];
        char        *cidr = NULL;

        if (cJSON_IsArray(items))
        {
            item = cJSON_GetArrayItem(items, i);
            stringNPrintf(json_path, sizeof(json_path), "PacketGenerator->settings->source-ipv4-range[%d]", i);
            if (! cJSON_IsString(item) || item->valuestring == NULL)
            {
                LOGF("JSON Error: %s (string field) : expected an IPv4 CIDR range", json_path);
                return false;
            }
            cidr = item->valuestring;
        }
        else
        {
            item = items;
            cidr = item->valuestring;
            stringCopy(json_path, "PacketGenerator->settings->source-ipv4-range");
        }

        if (! packetgeneratorParseSourceRange(&state->source_ranges[i], cidr, json_path))
        {
            return false;
        }

        if (state->source_ranges[i].count > (UINT64_MAX - total_source_count))
        {
            LOGF("PacketGenerator: total source range size overflow");
            return false;
        }

        total_source_count += state->source_ranges[i].count;
    }

    if (total_source_count > UINT32_MAX)
    {
        LOGF("PacketGenerator: total source count exceeds the supported range");
        return false;
    }

    state->source_count = (uint32_t) total_source_count;
    return true;
}

static bool packetgeneratorLoadDestIpv4(packetgenerator_tstate_t *state, const cJSON *settings)
{
    char *ipbuf = NULL;

    if (! getStringFromJsonObject(&ipbuf, settings, "dest-ipv4"))
    {
        LOGF("JSON Error: PacketGenerator->settings->dest-ipv4 (string field) : expected a single IPv4 address");
        return false;
    }

    const bool ok =
        packetgeneratorParseIpv4String(&state->dest_addr_network, ipbuf, "PacketGenerator->settings->dest-ipv4");
    memoryFree(ipbuf);

    if (! ok)
    {
        return false;
    }

    state->dest_addr_host = lwip_ntohl(state->dest_addr_network);
    return true;
}

static bool packetgeneratorLoadProtocolMode(packetgenerator_tstate_t *state, const cJSON *settings)
{
    char *mode = NULL;

    if (! getStringFromJsonObject(&mode, settings, "protocol-number"))
    {
        LOGF("JSON Error: PacketGenerator->settings->protocol-number (string field) : expected TCP, UDP, ICMP, or ALL");
        return false;
    }

    if (stringCompare(mode, "TCP") == 0 || stringCompare(mode, "tcp") == 0)
    {
        state->protocol_mode = kPacketGeneratorProtocolTcp;
    }
    else if (stringCompare(mode, "UDP") == 0 || stringCompare(mode, "udp") == 0)
    {
        state->protocol_mode = kPacketGeneratorProtocolUdp;
    }
    else if (stringCompare(mode, "ICMP") == 0 || stringCompare(mode, "icmp") == 0)
    {
        state->protocol_mode = kPacketGeneratorProtocolIcmp;
    }
    else if (stringCompare(mode, "ALL") == 0 || stringCompare(mode, "all") == 0)
    {
        state->protocol_mode = kPacketGeneratorProtocolAll;
    }
    else
    {
        LOGF("JSON Error: PacketGenerator->settings->protocol-number (string field) : expected TCP, UDP, ICMP, or ALL");
        memoryFree(mode);
        return false;
    }

    memoryFree(mode);
    return true;
}

static bool packetgeneratorLoadPacketsPerIp(packetgenerator_tstate_t *state, const cJSON *settings)
{
    int packets_per_ip = 1;

    getIntFromJsonObjectOrDefault(&packets_per_ip, settings, "packets-per-ip", 1);

    if (packets_per_ip <= 0)
    {
        LOGF("JSON Error: PacketGenerator->settings->packets-per-ip (int field) : expected a positive packet count");
        return false;
    }

    state->packets_per_ip = (uint32_t) packets_per_ip;
    return true;
}

static bool packetgeneratorLoadDuration(packetgenerator_tstate_t *state, const cJSON *settings)
{
    int duration_ms = 0;

    if (! getIntFromJsonObject(&duration_ms, settings, "duration-ms") || duration_ms <= 0)
    {
        LOGF("JSON Error: PacketGenerator->settings->duration-ms (int field) : expected a positive millisecond value");
        return false;
    }

    state->duration_ms = (uint32_t) duration_ms;
    return true;
}

static bool packetgeneratorLoadDestPort(packetgenerator_tstate_t *state, const cJSON *settings)
{
    const bool   required = packetgeneratorProtocolModeUsesPorts(state->protocol_mode);
    const cJSON *item     = cJSON_GetObjectItemCaseSensitive(settings, "dest-port");

    if (item == NULL)
    {
        if (required)
        {
            LOGF("JSON Error: PacketGenerator->settings->dest-port (int field) : required for TCP, UDP, or ALL");
            return false;
        }

        state->dest_port = 0;
        return true;
    }

    int64_t val = 0;
    if (! jsonGetIntegerInRange(item, 0, UINT16_MAX, &val))
    {
        LOGF("JSON Error: PacketGenerator->settings->dest-port (int field) : expected a value between 0 and %u",
             (unsigned int) UINT16_MAX);
        return false;
    }

    if (required && val == 0)
    {
        LOGF("JSON Error: PacketGenerator->settings->dest-port (int field) : expected a non-zero port for TCP, UDP, or "
             "ALL");
        return false;
    }

    state->dest_port = (uint16_t) val;
    return true;
}

static bool packetgeneratorLoadSrcPort(packetgenerator_tstate_t *state, const cJSON *settings)
{
    const bool   required = packetgeneratorProtocolModeUsesPorts(state->protocol_mode);
    const cJSON *item     = cJSON_GetObjectItemCaseSensitive(settings, "src-port");

    if (item == NULL)
    {
        if (required)
        {
            LOGF("JSON Error: PacketGenerator->settings->src-port (int-or-string field) : required for TCP, UDP, or "
                 "ALL");
            return false;
        }

        state->src_port_random = false;
        state->src_port        = 0;
        return true;
    }

    if (cJSON_IsString(item) && item->valuestring != NULL)
    {
        if (stringCompare(item->valuestring, "random") == 0 || stringCompare(item->valuestring, "RANDOM") == 0)
        {
            state->src_port_random = true;
            state->src_port        = 0;
            return true;
        }

        LOGF("JSON Error: PacketGenerator->settings->src-port (int-or-string field) : expected a port number or "
             "\"random\"");
        return false;
    }

    int64_t val = 0;
    if (! jsonGetIntegerInRange(item, 0, UINT16_MAX, &val))
    {
        LOGF(
            "JSON Error: PacketGenerator->settings->src-port (int-or-string field) : expected a value between 0 and %u",
            (unsigned int) UINT16_MAX);
        return false;
    }

    if (required && val == 0)
    {
        LOGF("JSON Error: PacketGenerator->settings->src-port (int-or-string field) : expected a non-zero port or "
             "\"random\" for TCP, UDP, or ALL");
        return false;
    }

    state->src_port_random = false;
    state->src_port        = (uint16_t) val;
    return true;
}

tunnel_t *packetgeneratorTunnelCreate(node_t *node)
{
    tunnel_t *t = adapterCreate(node, sizeof(packetgenerator_tstate_t), 0, kAdapterChainHead);
    if (! t)
    {
        return NULL;
    }

    t->fnInitD    = &packetgeneratorTunnelDownStreamInit;
    t->fnEstD     = &packetgeneratorTunnelDownStreamEst;
    t->fnFinD     = &packetgeneratorTunnelDownStreamFinish;
    t->fnPayloadD = &packetgeneratorTunnelDownStreamPayload;
    t->fnPauseD   = &packetgeneratorTunnelDownStreamPause;
    t->fnResumeD  = &packetgeneratorTunnelDownStreamResume;

    t->onPrepare = &packetgeneratorTunnelOnPrepair;
    t->onStart   = &packetgeneratorTunnelOnStart;

    t->onWorkerQuiesce = &packetgeneratorTunnelOnWorkerQuiesce;
    t->onDestroy       = &packetgeneratorTunnelDestroy;

    packetgenerator_tstate_t *state    = tunnelGetState(t);
    const cJSON           *settings = node->node_settings_json;

    if (! checkJsonIsObjectAndHasChild(settings))
    {
        LOGF("JSON Error: PacketGenerator->settings (object field) : The object was empty or invalid");
        packetgeneratorTunnelDestroy(t, wwLifecycleStartupRollback());
        return NULL;
    }

    state->packets_per_ip = 1;

    if (! packetgeneratorLoadSourceRanges(state, settings) || ! packetgeneratorLoadDestIpv4(state, settings) ||
        ! packetgeneratorLoadProtocolMode(state, settings) || ! packetgeneratorLoadPacketsPerIp(state, settings) ||
        ! packetgeneratorLoadDuration(state, settings) || ! packetgeneratorLoadDestPort(state, settings) ||
        ! packetgeneratorLoadSrcPort(state, settings))
    {
        packetgeneratorTunnelDestroy(t, wwLifecycleStartupRollback());
        return NULL;
    }

    return t;
}

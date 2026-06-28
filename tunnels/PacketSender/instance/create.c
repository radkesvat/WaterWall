#include "structure.h"

#include "loggers/network_logger.h"

static bool packetsenderProtocolModeUsesPorts(uint8_t protocol_mode)
{
    return protocol_mode == kPacketSenderProtocolTcp || protocol_mode == kPacketSenderProtocolUdp ||
           protocol_mode == kPacketSenderProtocolAll;
}

static bool packetsenderParseIpv4String(uint32_t *dest, const char *ipbuf, const char *json_path)
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

static bool packetsenderParseSourceRange(packetsender_source_range_t *range, const char *cidr, const char *json_path)
{
    ip_addr_t ip;
    ip_addr_t subnet_mask;
    int       prefix_length = -1;

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

    if (parseIPWithSubnetMask(cidr, &ip, &subnet_mask) != 4 || sscanf(cidr, "%*[^/]/%d", &prefix_length) != 1 ||
        prefix_length < 0 || prefix_length > 32)
    {
        LOGF("JSON Error: %s (string field) : expected an IPv4 CIDR range", json_path);
        return false;
    }

    range->base_host     = lwip_ntohl(ip.u_addr.ip4.addr) & lwip_ntohl(subnet_mask.u_addr.ip4.addr);
    range->prefix_length = (uint8_t) prefix_length;
    range->count         = 1ULL << (32U - (uint32_t) prefix_length);
    return true;
}

static bool packetsenderLoadSourceRanges(packetsender_tstate_t *state, const cJSON *settings)
{
    const cJSON *range_json = cJSON_GetObjectItemCaseSensitive(settings, "source-ip4-range");

    if (range_json == NULL)
    {
        LOGF("JSON Error: PacketSender->settings->source-ip4-range (string or array field) : expected one or more IPv4 "
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
        LOGF("JSON Error: PacketSender->settings->source-ip4-range (string or array field) : expected one or more IPv4 "
             "CIDR ranges");
        return false;
    }

    state->source_ranges      = memoryAllocateZero((size_t) range_count * sizeof(*(state->source_ranges)));
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
            stringNPrintf(json_path, sizeof(json_path), "PacketSender->settings->source-ip4-range[%d]", i);
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
            stringCopy(json_path, "PacketSender->settings->source-ip4-range");
        }

        if (! packetsenderParseSourceRange(&state->source_ranges[i], cidr, json_path))
        {
            return false;
        }

        if (state->source_ranges[i].count > (UINT64_MAX - total_source_count))
        {
            LOGF("PacketSender: total source range size overflow");
            return false;
        }

        total_source_count += state->source_ranges[i].count;
    }

    if (total_source_count > UINT32_MAX)
    {
        LOGF("PacketSender: total source count exceeds the supported range");
        return false;
    }

    state->source_count = (uint32_t) total_source_count;
    return true;
}

static bool packetsenderLoadDestIpv4(packetsender_tstate_t *state, const cJSON *settings)
{
    char *ipbuf = NULL;

    if (! getStringFromJsonObject(&ipbuf, settings, "dest-ipv4"))
    {
        LOGF("JSON Error: PacketSender->settings->dest-ipv4 (string field) : expected a single IPv4 address");
        return false;
    }

    const bool ok = packetsenderParseIpv4String(&state->dest_addr_network, ipbuf, "PacketSender->settings->dest-ipv4");
    memoryFree(ipbuf);

    if (! ok)
    {
        return false;
    }

    state->dest_addr_host = lwip_ntohl(state->dest_addr_network);
    return true;
}

static bool packetsenderLoadProtocolMode(packetsender_tstate_t *state, const cJSON *settings)
{
    char *mode = NULL;

    if (! getStringFromJsonObject(&mode, settings, "protocol-number"))
    {
        LOGF("JSON Error: PacketSender->settings->protocol-number (string field) : expected TCP, UDP, ICMP, or ALL");
        return false;
    }

    if (stringCompare(mode, "TCP") == 0 || stringCompare(mode, "tcp") == 0)
    {
        state->protocol_mode = kPacketSenderProtocolTcp;
    }
    else if (stringCompare(mode, "UDP") == 0 || stringCompare(mode, "udp") == 0)
    {
        state->protocol_mode = kPacketSenderProtocolUdp;
    }
    else if (stringCompare(mode, "ICMP") == 0 || stringCompare(mode, "icmp") == 0)
    {
        state->protocol_mode = kPacketSenderProtocolIcmp;
    }
    else if (stringCompare(mode, "ALL") == 0 || stringCompare(mode, "all") == 0)
    {
        state->protocol_mode = kPacketSenderProtocolAll;
    }
    else
    {
        LOGF("JSON Error: PacketSender->settings->protocol-number (string field) : expected TCP, UDP, ICMP, or ALL");
        memoryFree(mode);
        return false;
    }

    memoryFree(mode);
    return true;
}

static bool packetsenderLoadPacketsPerIp(packetsender_tstate_t *state, const cJSON *settings)
{
    int packets_per_ip = 1;

    getIntFromJsonObjectOrDefault(&packets_per_ip, settings, "packets-per-ip", 1);

    if (packets_per_ip <= 0)
    {
        LOGF("JSON Error: PacketSender->settings->packets-per-ip (int field) : expected a positive packet count");
        return false;
    }

    state->packets_per_ip = (uint32_t) packets_per_ip;
    return true;
}

static bool packetsenderLoadDuration(packetsender_tstate_t *state, const cJSON *settings)
{
    int duration_ms = 0;

    if (! getIntFromJsonObject(&duration_ms, settings, "duration-ms") || duration_ms <= 0)
    {
        LOGF("JSON Error: PacketSender->settings->duration-ms (int field) : expected a positive millisecond value");
        return false;
    }

    state->duration_ms = (uint32_t) duration_ms;
    return true;
}

static bool packetsenderLoadDestPort(packetsender_tstate_t *state, const cJSON *settings)
{
    const bool   required = packetsenderProtocolModeUsesPorts(state->protocol_mode);
    const cJSON *item     = cJSON_GetObjectItemCaseSensitive(settings, "dest-port");

    if (item == NULL)
    {
        if (required)
        {
            LOGF("JSON Error: PacketSender->settings->dest-port (int field) : required for TCP, UDP, or ALL");
            return false;
        }

        state->dest_port = 0;
        return true;
    }

    if (! cJSON_IsNumber(item) || item->valueint < 0 || item->valueint > UINT16_MAX)
    {
        LOGF("JSON Error: PacketSender->settings->dest-port (int field) : expected a value between 0 and %u",
             (unsigned int) UINT16_MAX);
        return false;
    }

    if (required && item->valueint == 0)
    {
        LOGF("JSON Error: PacketSender->settings->dest-port (int field) : expected a non-zero port for TCP, UDP, or "
             "ALL");
        return false;
    }

    state->dest_port = (uint16_t) item->valueint;
    return true;
}

static bool packetsenderLoadSrcPort(packetsender_tstate_t *state, const cJSON *settings)
{
    const bool   required = packetsenderProtocolModeUsesPorts(state->protocol_mode);
    const cJSON *item     = cJSON_GetObjectItemCaseSensitive(settings, "src-port");

    if (item == NULL)
    {
        if (required)
        {
            LOGF("JSON Error: PacketSender->settings->src-port (int-or-string field) : required for TCP, UDP, or ALL");
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

        LOGF("JSON Error: PacketSender->settings->src-port (int-or-string field) : expected a port number or "
             "\"random\"");
        return false;
    }

    if (! cJSON_IsNumber(item) || item->valueint < 0 || item->valueint > UINT16_MAX)
    {
        LOGF("JSON Error: PacketSender->settings->src-port (int-or-string field) : expected a value between 0 and %u",
             (unsigned int) UINT16_MAX);
        return false;
    }

    if (required && item->valueint == 0)
    {
        LOGF("JSON Error: PacketSender->settings->src-port (int-or-string field) : expected a non-zero port or "
             "\"random\" for TCP, UDP, or ALL");
        return false;
    }

    state->src_port_random = false;
    state->src_port        = (uint16_t) item->valueint;
    return true;
}

tunnel_t *packetsenderTunnelCreate(node_t *node)
{
    tunnel_t *t = adapterCreate(node, sizeof(packetsender_tstate_t), 0, false);

    t->fnInitD    = &packetsenderTunnelDownStreamInit;
    t->fnEstD     = &packetsenderTunnelDownStreamEst;
    t->fnFinD     = &packetsenderTunnelDownStreamFinish;
    t->fnPayloadD = &packetsenderTunnelDownStreamPayload;
    t->fnPauseD   = &packetsenderTunnelDownStreamPause;
    t->fnResumeD  = &packetsenderTunnelDownStreamResume;

    t->onPrepare    = &packetsenderTunnelOnPrepair;
    t->onStart      = &packetsenderTunnelOnStart;
    t->onStop       = &packetsenderTunnelOnStop;
    t->onWorkerStop = &packetsenderTunnelOnWorkerStop;
    t->onDestroy    = &packetsenderTunnelDestroy;

    packetsender_tstate_t *state    = tunnelGetState(t);
    const cJSON           *settings = node->node_settings_json;

    if (! checkJsonIsObjectAndHasChild(settings))
    {
        LOGF("JSON Error: PacketSender->settings (object field) : The object was empty or invalid");
        packetsenderTunnelDestroy(t);
        return NULL;
    }

    state->packets_per_ip = 1;

    if (! packetsenderLoadSourceRanges(state, settings) || ! packetsenderLoadDestIpv4(state, settings) ||
        ! packetsenderLoadProtocolMode(state, settings) || ! packetsenderLoadPacketsPerIp(state, settings) ||
        ! packetsenderLoadDuration(state, settings) || ! packetsenderLoadDestPort(state, settings) ||
        ! packetsenderLoadSrcPort(state, settings))
    {
        packetsenderTunnelDestroy(t);
        return NULL;
    }

    return t;
}

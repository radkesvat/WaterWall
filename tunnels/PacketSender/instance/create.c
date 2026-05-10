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

    if (ip4AddrAddressToNetwork(ipbuf, &parsed_ipv4) == 0)
    {
        LOGF("JSON Error: %s (string field) : expected a single IPv4 address", json_path);
        return false;
    }

    *dest = parsed_ipv4.addr;
    return true;
}

static bool packetsenderLoadSourceRange(packetsender_tstate_t *state, const cJSON *settings)
{
    char *cidr = NULL;

    if (! getStringFromJsonObject(&cidr, settings, "source-ip4-range"))
    {
        LOGF("JSON Error: PacketSender->settings->source-ip4-range (string field) : expected an IPv4 CIDR range");
        return false;
    }

    if (! verifyIPCdir(cidr))
    {
        LOGF("JSON Error: PacketSender->settings->source-ip4-range (string field) : invalid IPv4 CIDR range");
        memoryFree(cidr);
        return false;
    }

    ip_addr_t ip;
    ip_addr_t subnet_mask;
    int       prefix_length = -1;

    if (parseIPWithSubnetMask(cidr, &ip, &subnet_mask) != 4 ||
        sscanf(cidr, "%*[^/]/%d", &prefix_length) != 1 || prefix_length < 0 || prefix_length > 32)
    {
        LOGF("JSON Error: PacketSender->settings->source-ip4-range (string field) : expected an IPv4 CIDR range");
        memoryFree(cidr);
        return false;
    }

    state->source_base_host      = lwip_ntohl(ip.u_addr.ip4.addr) & lwip_ntohl(subnet_mask.u_addr.ip4.addr);
    state->source_prefix_length  = (uint8_t) prefix_length;
    state->source_count          = 1ULL << (32U - (uint32_t) prefix_length);

    memoryFree(cidr);
    return true;
}

static bool packetsenderLoadDestIpv4(packetsender_tstate_t *state, const cJSON *settings)
{
    char *ipbuf = NULL;

    if (! getStringFromJsonObject(&ipbuf, settings, "dest-ip4"))
    {
        LOGF("JSON Error: PacketSender->settings->dest-ip4 (string field) : expected a single IPv4 address");
        return false;
    }

    const bool ok = packetsenderParseIpv4String(&state->dest_addr_network, ipbuf,
                                                "PacketSender->settings->dest-ip4");
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
        LOGF("JSON Error: PacketSender->settings->dest-port (int field) : expected a non-zero port for TCP, UDP, or ALL");
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

        LOGF("JSON Error: PacketSender->settings->src-port (int-or-string field) : expected a port number or \"random\"");
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
        LOGF("JSON Error: PacketSender->settings->src-port (int-or-string field) : expected a non-zero port or \"random\" for TCP, UDP, or ALL");
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

    t->onPrepare = &packetsenderTunnelOnPrepair;
    t->onStart   = &packetsenderTunnelOnStart;
    t->onDestroy = &packetsenderTunnelDestroy;

    packetsender_tstate_t *state    = tunnelGetState(t);
    const cJSON           *settings = node->node_settings_json;

    if (! checkJsonIsObjectAndHasChild(settings))
    {
        LOGF("JSON Error: PacketSender->settings (object field) : The object was empty or invalid");
        packetsenderTunnelDestroy(t);
        return NULL;
    }

    if (! packetsenderLoadSourceRange(state, settings) || ! packetsenderLoadDestIpv4(state, settings) ||
        ! packetsenderLoadProtocolMode(state, settings) || ! packetsenderLoadDuration(state, settings) ||
        ! packetsenderLoadDestPort(state, settings) || ! packetsenderLoadSrcPort(state, settings))
    {
        packetsenderTunnelDestroy(t);
        return NULL;
    }

    return t;
}

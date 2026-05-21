#include "structure.h"

#include "loggers/network_logger.h"

static bool testerclientLoadUint8Setting(uint8_t *dest, const cJSON *settings, const char *key, int default_value,
                                         const char *json_path)
{
    int value = default_value;
    getIntFromJsonObjectOrDefault(&value, settings, key, default_value);

    if (value < 0 || value > UINT8_MAX)
    {
        LOGF("JSON Error: %s (int field) : expected a value between 0 and %u", json_path, (unsigned int) UINT8_MAX);
        return false;
    }

    *dest = (uint8_t) value;
    return true;
}

static uint8_t testerclientPacketIpv4ProtocolForTransport(testerclient_packet_ipv4_transport_e transport)
{
    switch (transport)
    {
    case kTesterClientPacketIpv4TransportTcp:
        return IP_PROTO_TCP;
    case kTesterClientPacketIpv4TransportUdp:
        return IP_PROTO_UDP;
    case kTesterClientPacketIpv4TransportIcmp:
        return IP_PROTO_ICMP;
    default:
        return kTesterClientPacketIpv4ProtocolDefault;
    }
}

static bool testerclientLoadPacketIpv4TransportSetting(testerclient_packet_ipv4_transport_e *dest,
                                                       const cJSON *packet_ipv4)
{
    char *transport = NULL;

    *dest = kTesterClientPacketIpv4TransportNone;

    if (! getStringFromJsonObject(&transport, packet_ipv4, "transport"))
    {
        return true;
    }

    if (stringCompare(transport, "tcp") == 0)
    {
        *dest = kTesterClientPacketIpv4TransportTcp;
    }
    else if (stringCompare(transport, "udp") == 0)
    {
        *dest = kTesterClientPacketIpv4TransportUdp;
    }
    else if (stringCompare(transport, "icmp") == 0)
    {
        *dest = kTesterClientPacketIpv4TransportIcmp;
    }
    else if (stringCompare(transport, "raw") == 0 || stringCompare(transport, "none") == 0)
    {
        *dest = kTesterClientPacketIpv4TransportNone;
    }
    else
    {
        LOGF("JSON Error: TesterClient->settings->packet-ipv4->transport (string field) : expected tcp, udp, icmp, raw, or none");
        memoryFree(transport);
        return false;
    }

    memoryFree(transport);
    return true;
}

static bool testerclientParseIpv4String(uint32_t *dest, const char *ipbuf, const char *json_path)
{
    ip4_addr_t parsed_ipv4;

    if (ip4AddrAddressToNetwork(ipbuf, &parsed_ipv4) == 0)
    {
        LOGF("JSON Error: %s (string field) : expected a single IPv4 address", json_path);
        return false;
    }

    *dest = ip4AddrGetU32(&parsed_ipv4);
    return true;
}

static bool testerclientLoadRequiredIpv4Setting(uint32_t *dest, const cJSON *settings, const char *key,
                                                const char *json_path)
{
    char *ipbuf = NULL;
    if (! getStringFromJsonObject(&ipbuf, settings, key))
    {
        LOGF("JSON Error: %s (string field) : expected an IPv4 address", json_path);
        return false;
    }

    const bool ok = testerclientParseIpv4String(dest, ipbuf, json_path);
    memoryFree(ipbuf);
    return ok;
}

static bool testerclientLoadPacketIpv4Settings(testerclient_tstate_t *ts, const cJSON *settings)
{
    const cJSON *packet_ipv4 = cJSON_GetObjectItemCaseSensitive(settings, "packet-ipv4");

    ts->packet_ipv4_mode     = false;
    ts->packet_ipv4_protocol = kTesterClientPacketIpv4ProtocolDefault;
    ts->packet_ipv4_ttl      = kTesterClientPacketIpv4TtlDefault;
    ts->packet_ipv4_transport = kTesterClientPacketIpv4TransportNone;
    atomicStoreRelaxed(&ts->packet_ipv4_identification, 0);

    if (packet_ipv4 == NULL)
    {
        return true;
    }

    if (! ts->packet_mode)
    {
        LOGF("TesterClient: settings->packet-ipv4 requires packet-mode=true");
        return false;
    }

    if (! checkJsonIsObjectAndHasChild(packet_ipv4))
    {
        LOGF("JSON Error: TesterClient->settings->packet-ipv4 (object field) : The object was empty or invalid");
        return false;
    }

    int  protocol_value = kTesterClientPacketIpv4ProtocolDefault;
    bool has_protocol   = getIntFromJsonObject(&protocol_value, packet_ipv4, "protocol");

    if (protocol_value < 0 || protocol_value > UINT8_MAX)
    {
        LOGF("JSON Error: TesterClient->settings->packet-ipv4->protocol (int field) : expected a value between 0 and %u",
             (unsigned int) UINT8_MAX);
        return false;
    }

    ts->packet_ipv4_protocol = (uint8_t) protocol_value;

    if (! testerclientLoadRequiredIpv4Setting(&ts->packet_ipv4_source_addr, packet_ipv4, "source-ip",
                                              "TesterClient->settings->packet-ipv4->source-ip") ||
        ! testerclientLoadRequiredIpv4Setting(&ts->packet_ipv4_dest_addr, packet_ipv4, "dest-ip",
                                              "TesterClient->settings->packet-ipv4->dest-ip") ||
        ! testerclientLoadUint8Setting(&ts->packet_ipv4_ttl, packet_ipv4, "ttl", kTesterClientPacketIpv4TtlDefault,
                                       "TesterClient->settings->packet-ipv4->ttl") ||
        ! testerclientLoadPacketIpv4TransportSetting(&ts->packet_ipv4_transport, packet_ipv4))
    {
        return false;
    }

    if (ts->packet_ipv4_transport != kTesterClientPacketIpv4TransportNone)
    {
        uint8_t transport_protocol = testerclientPacketIpv4ProtocolForTransport(ts->packet_ipv4_transport);

        if (has_protocol && ts->packet_ipv4_protocol != transport_protocol)
        {
            LOGF("TesterClient: settings->packet-ipv4->protocol must match packet-ipv4->transport");
            return false;
        }

        ts->packet_ipv4_protocol = transport_protocol;
    }

    ts->packet_ipv4_mode = true;
    return true;
}

tunnel_t *testerclientTunnelCreate(node_t *node)
{
    tunnel_t *t = tunnelCreate(node, sizeof(testerclient_tstate_t), sizeof(testerclient_lstate_t));

    t->fnInitU    = &testerclientTunnelUpStreamInit;
    t->fnEstU     = &testerclientTunnelUpStreamEst;
    t->fnFinU     = &testerclientTunnelUpStreamFinish;
    t->fnPayloadU = &testerclientTunnelUpStreamPayload;
    t->fnPauseU   = &testerclientTunnelUpStreamPause;
    t->fnResumeU  = &testerclientTunnelUpStreamResume;

    t->fnInitD    = &testerclientTunnelDownStreamInit;
    t->fnEstD     = &testerclientTunnelDownStreamEst;
    t->fnFinD     = &testerclientTunnelDownStreamFinish;
    t->fnPayloadD = &testerclientTunnelDownStreamPayload;
    t->fnPauseD   = &testerclientTunnelDownStreamPause;
    t->fnResumeD  = &testerclientTunnelDownStreamResume;

    t->onPrepare = &testerclientTunnelOnPrepair;
    t->onStart   = &testerclientTunnelOnStart;
    t->onDestroy = &testerclientTunnelDestroy;

    testerclient_tstate_t *ts       = tunnelGetState(t);
    const cJSON           *settings = node->node_settings_json;
    int                    packet_start_delay_ms = 0;
    int                    chunk_count = kTesterClientChunkCount;

    getBoolFromJsonObjectOrDefault(&ts->allow_early_response, settings, "allow-early-response", false);
    getBoolFromJsonObjectOrDefault(&ts->packet_mode, settings, "packet-mode", false);
    getBoolFromJsonObjectOrDefault(&ts->packet_start_immediately, settings, "packet-start-immediately", false);
    getIntFromJsonObjectOrDefault(&packet_start_delay_ms, settings, "packet-start-delay-ms", 0);
    getIntFromJsonObjectOrDefault(&chunk_count, settings, "chunk-count", kTesterClientChunkCount);

    if (packet_start_delay_ms < 0)
    {
        LOGF("JSON Error: TesterClient->settings->packet-start-delay-ms (int field) : expected a non-negative value");
        testerclientTunnelDestroy(t);
        return NULL;
    }

    ts->packet_start_delay_ms = (uint32_t) packet_start_delay_ms;

    if (chunk_count <= 0 || chunk_count > kTesterClientChunkCount)
    {
        LOGF("JSON Error: TesterClient->settings->chunk-count (int field) : expected a value between 1 and %u",
             (unsigned int) kTesterClientChunkCount);
        testerclientTunnelDestroy(t);
        return NULL;
    }

    ts->chunk_count = (uint8_t) chunk_count;

    if ((ts->packet_start_immediately || ts->packet_start_delay_ms > 0) && ! ts->packet_mode)
    {
        LOGF("TesterClient: packet-start-immediately and packet-start-delay-ms require packet-mode=true");
        testerclientTunnelDestroy(t);
        return NULL;
    }

    if (! testerclientLoadPacketIpv4Settings(ts, settings))
    {
        testerclientTunnelDestroy(t);
        return NULL;
    }

    return t;
}

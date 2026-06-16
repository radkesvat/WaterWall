#include "structure.h"

#include "loggers/network_logger.h"

static bool testerserverLoadUint8Setting(uint8_t *dest, const cJSON *settings, const char *key, int default_value,
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

static uint8_t testerserverPacketIpv4ProtocolForTransport(testerserver_packet_ipv4_transport_e transport)
{
    switch (transport)
    {
    case kTesterServerPacketIpv4TransportTcp:
        return IP_PROTO_TCP;
    case kTesterServerPacketIpv4TransportUdp:
        return IP_PROTO_UDP;
    case kTesterServerPacketIpv4TransportIcmp:
        return IP_PROTO_ICMP;
    default:
        return kTesterServerPacketIpv4ProtocolDefault;
    }
}

static uint16_t testerserverPacketIpv4MinimumPacketSize(const testerserver_tstate_t *ts)
{
    switch (ts->packet_ipv4_transport)
    {
    case kTesterServerPacketIpv4TransportTcp:
        return (uint16_t) (sizeof(struct ip_hdr) + sizeof(struct tcp_hdr) + 1U);
    case kTesterServerPacketIpv4TransportUdp:
        return (uint16_t) (sizeof(struct ip_hdr) + sizeof(struct udp_hdr) + 1U);
    case kTesterServerPacketIpv4TransportIcmp:
        return (uint16_t) (sizeof(struct ip_hdr) + sizeof(struct icmp_echo_hdr) + 1U);
    default:
        return (uint16_t) (sizeof(struct ip_hdr) + 1U);
    }
}

static bool testerserverLoadPacketIpv4TransportSetting(testerserver_packet_ipv4_transport_e *dest,
                                                       const cJSON                          *packet_ipv4)
{
    char *transport = NULL;

    *dest = kTesterServerPacketIpv4TransportNone;

    if (! getStringFromJsonObject(&transport, packet_ipv4, "transport"))
    {
        return true;
    }

    if (stringCompare(transport, "tcp") == 0)
    {
        *dest = kTesterServerPacketIpv4TransportTcp;
    }
    else if (stringCompare(transport, "udp") == 0)
    {
        *dest = kTesterServerPacketIpv4TransportUdp;
    }
    else if (stringCompare(transport, "icmp") == 0)
    {
        *dest = kTesterServerPacketIpv4TransportIcmp;
    }
    else if (stringCompare(transport, "raw") == 0 || stringCompare(transport, "none") == 0)
    {
        *dest = kTesterServerPacketIpv4TransportNone;
    }
    else
    {
        LOGF("JSON Error: TesterServer->settings->packet-ipv4->transport (string field) : expected tcp, udp, icmp, "
             "raw, or none");
        memoryFree(transport);
        return false;
    }

    memoryFree(transport);
    return true;
}

static bool testerserverParseIpv4String(uint32_t *dest, const char *ipbuf, const char *json_path)
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

static bool testerserverLoadRequiredIpv4Setting(uint32_t *dest, const cJSON *settings, const char *key,
                                                const char *json_path)
{
    char *ipbuf = NULL;
    if (! getStringFromJsonObject(&ipbuf, settings, key))
    {
        LOGF("JSON Error: %s (string field) : expected an IPv4 address", json_path);
        return false;
    }

    const bool ok = testerserverParseIpv4String(dest, ipbuf, json_path);
    memoryFree(ipbuf);
    return ok;
}

static bool testerserverLoadPacketIpv4Settings(testerserver_tstate_t *ts, const cJSON *settings)
{
    const cJSON *packet_ipv4 = cJSON_GetObjectItemCaseSensitive(settings, "packet-ipv4");

    ts->packet_ipv4_mode      = false;
    ts->packet_ipv4_protocol  = kTesterServerPacketIpv4ProtocolDefault;
    ts->packet_ipv4_ttl       = kTesterServerPacketIpv4TtlDefault;
    ts->packet_ipv4_transport = kTesterServerPacketIpv4TransportNone;
    atomicStoreRelaxed(&ts->packet_ipv4_identification, 0);

    if (packet_ipv4 == NULL)
    {
        return true;
    }

    if (! ts->packet_mode)
    {
        LOGF("TesterServer: settings->packet-ipv4 requires packet-mode=true");
        return false;
    }

    if (! checkJsonIsObjectAndHasChild(packet_ipv4))
    {
        LOGF("JSON Error: TesterServer->settings->packet-ipv4 (object field) : The object was empty or invalid");
        return false;
    }

    int  protocol_value = kTesterServerPacketIpv4ProtocolDefault;
    bool has_protocol   = getIntFromJsonObject(&protocol_value, packet_ipv4, "protocol");

    if (protocol_value < 0 || protocol_value > UINT8_MAX)
    {
        LOGF(
            "JSON Error: TesterServer->settings->packet-ipv4->protocol (int field) : expected a value between 0 and %u",
            (unsigned int) UINT8_MAX);
        return false;
    }

    ts->packet_ipv4_protocol = (uint8_t) protocol_value;

    if (! testerserverLoadRequiredIpv4Setting(
            &ts->packet_ipv4_source_addr, packet_ipv4, "source-ip", "TesterServer->settings->packet-ipv4->source-ip") ||
        ! testerserverLoadRequiredIpv4Setting(
            &ts->packet_ipv4_dest_addr, packet_ipv4, "dest-ip", "TesterServer->settings->packet-ipv4->dest-ip") ||
        ! testerserverLoadUint8Setting(&ts->packet_ipv4_ttl,
                                       packet_ipv4,
                                       "ttl",
                                       kTesterServerPacketIpv4TtlDefault,
                                       "TesterServer->settings->packet-ipv4->ttl") ||
        ! testerserverLoadPacketIpv4TransportSetting(&ts->packet_ipv4_transport, packet_ipv4))
    {
        return false;
    }

    if (ts->packet_ipv4_transport != kTesterServerPacketIpv4TransportNone)
    {
        uint8_t transport_protocol = testerserverPacketIpv4ProtocolForTransport(ts->packet_ipv4_transport);

        if (has_protocol && ts->packet_ipv4_protocol != transport_protocol)
        {
            LOGF("TesterServer: settings->packet-ipv4->protocol must match packet-ipv4->transport");
            return false;
        }

        ts->packet_ipv4_protocol = transport_protocol;
    }

    ts->packet_ipv4_mode = true;
    return true;
}

tunnel_t *testerserverTunnelCreate(node_t *node)
{
    tunnel_t *t = tunnelCreate(node, sizeof(testerserver_tstate_t), sizeof(testerserver_lstate_t));

    t->fnInitU    = &testerserverTunnelUpStreamInit;
    t->fnEstU     = &testerserverTunnelUpStreamEst;
    t->fnFinU     = &testerserverTunnelUpStreamFinish;
    t->fnPayloadU = &testerserverTunnelUpStreamPayload;
    t->fnPauseU   = &testerserverTunnelUpStreamPause;
    t->fnResumeU  = &testerserverTunnelUpStreamResume;

    t->fnInitD    = &testerserverTunnelDownStreamInit;
    t->fnEstD     = &testerserverTunnelDownStreamEst;
    t->fnFinD     = &testerserverTunnelDownStreamFinish;
    t->fnPayloadD = &testerserverTunnelDownStreamPayload;
    t->fnPauseD   = &testerserverTunnelDownStreamPause;
    t->fnResumeD  = &testerserverTunnelDownStreamResume;

    t->onPrepare = &testerserverTunnelOnPrepair;
    t->onStart   = &testerserverTunnelOnStart;
    t->onStop    = &testerserverTunnelOnStop;
    t->onDestroy = &testerserverTunnelDestroy;

    testerserver_tstate_t *ts               = tunnelGetState(t);
    const cJSON           *settings         = node->node_settings_json;
    int                    chunk_count            = kTesterServerChunkCount;
    int                    max_payload_size       = 0;
    int                    split_payload_delay_ms = kTesterServerSplitPayloadDelayMs;
    int                    split_payload_burst    = kTesterServerSplitPayloadBurst;

    getBoolFromJsonObjectOrDefault(&ts->packet_mode, settings, "packet-mode", false);
    getBoolFromJsonObjectOrDefault(&ts->packet_stateless, settings, "packet-stateless", false);
    getBoolFromJsonObjectOrDefault(&ts->packet_init_on_start, settings, "packet-init-on-start", false);
    getBoolFromJsonObjectOrDefault(&ts->streaming_response, settings, "streaming-response", false);
    getIntFromJsonObjectOrDefault(&chunk_count, settings, "chunk-count", kTesterServerChunkCount);
    getIntFromJsonObjectOrDefault(&max_payload_size, settings, "max-payload-size", 0);
    getIntFromJsonObjectOrDefault(
        &split_payload_delay_ms, settings, "split-payload-delay-ms", kTesterServerSplitPayloadDelayMs);
    getIntFromJsonObjectOrDefault(&split_payload_burst, settings, "split-payload-burst",
                                  kTesterServerSplitPayloadBurst);

    if (nodeHasNext(node) && ! ts->packet_mode)
    {
        LOGF("TesterServer: using a next node is supported only when packet-mode=true");
        testerserverTunnelDestroy(t);
        return NULL;
    }

    if (chunk_count <= 0 || chunk_count > kTesterServerChunkCount)
    {
        LOGF("JSON Error: TesterServer->settings->chunk-count (int field) : expected a value between 1 and %u",
             (unsigned int) kTesterServerChunkCount);
        testerserverTunnelDestroy(t);
        return NULL;
    }

    ts->chunk_count = (uint8_t) chunk_count;

    if (max_payload_size < 0)
    {
        LOGF("JSON Error: TesterServer->settings->max-payload-size (int field) : expected a non-negative value");
        testerserverTunnelDestroy(t);
        return NULL;
    }

    ts->max_payload_size = (uint32_t) max_payload_size;

    if (split_payload_delay_ms < 0)
    {
        LOGF("JSON Error: TesterServer->settings->split-payload-delay-ms (int field) : expected a non-negative value");
        testerserverTunnelDestroy(t);
        return NULL;
    }

    ts->split_payload_delay_ms = (uint32_t) split_payload_delay_ms;

    if (split_payload_burst < 1)
    {
        LOGF("JSON Error: TesterServer->settings->split-payload-burst (int field) : expected a positive value");
        testerserverTunnelDestroy(t);
        return NULL;
    }

    ts->split_payload_burst = (uint32_t) split_payload_burst;

    if (ts->packet_init_on_start && ! ts->packet_mode)
    {
        LOGF("TesterServer: settings->packet-init-on-start requires packet-mode=true");
        testerserverTunnelDestroy(t);
        return NULL;
    }

    if (ts->packet_stateless && ! ts->packet_mode)
    {
        LOGF("TesterServer: settings->packet-stateless requires packet-mode=true");
        testerserverTunnelDestroy(t);
        return NULL;
    }

    if (ts->max_payload_size > 0 && ts->packet_stateless)
    {
        LOGF("TesterServer: settings->max-payload-size is not supported with packet-stateless=true");
        testerserverTunnelDestroy(t);
        return NULL;
    }

    if (! testerserverLoadPacketIpv4Settings(ts, settings))
    {
        testerserverTunnelDestroy(t);
        return NULL;
    }

    if (ts->packet_ipv4_mode && ts->max_payload_size > 0 &&
        ts->max_payload_size < testerserverPacketIpv4MinimumPacketSize(ts))
    {
        LOGF("TesterServer: settings->max-payload-size is too small for the configured packet-ipv4 headers");
        testerserverTunnelDestroy(t);
        return NULL;
    }

    return t;
}

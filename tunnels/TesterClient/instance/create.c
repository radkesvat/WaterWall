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

    if (! testerclientLoadRequiredIpv4Setting(&ts->packet_ipv4_source_addr, packet_ipv4, "source-ip",
                                              "TesterClient->settings->packet-ipv4->source-ip") ||
        ! testerclientLoadRequiredIpv4Setting(&ts->packet_ipv4_dest_addr, packet_ipv4, "dest-ip",
                                              "TesterClient->settings->packet-ipv4->dest-ip") ||
        ! testerclientLoadUint8Setting(&ts->packet_ipv4_protocol, packet_ipv4, "protocol",
                                       kTesterClientPacketIpv4ProtocolDefault,
                                       "TesterClient->settings->packet-ipv4->protocol") ||
        ! testerclientLoadUint8Setting(&ts->packet_ipv4_ttl, packet_ipv4, "ttl", kTesterClientPacketIpv4TtlDefault,
                                       "TesterClient->settings->packet-ipv4->ttl"))
    {
        return false;
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

    getBoolFromJsonObjectOrDefault(&ts->allow_early_response, settings, "allow-early-response", false);
    getBoolFromJsonObjectOrDefault(&ts->packet_mode, settings, "packet-mode", false);
    getBoolFromJsonObjectOrDefault(&ts->packet_start_immediately, settings, "packet-start-immediately", false);
    getIntFromJsonObjectOrDefault(&packet_start_delay_ms, settings, "packet-start-delay-ms", 0);

    if (packet_start_delay_ms < 0)
    {
        LOGF("JSON Error: TesterClient->settings->packet-start-delay-ms (int field) : expected a non-negative value");
        testerclientTunnelDestroy(t);
        return NULL;
    }

    ts->packet_start_delay_ms = (uint32_t) packet_start_delay_ms;

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

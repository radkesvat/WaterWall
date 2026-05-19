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

    ts->packet_ipv4_mode     = false;
    ts->packet_ipv4_protocol = kTesterServerPacketIpv4ProtocolDefault;
    ts->packet_ipv4_ttl      = kTesterServerPacketIpv4TtlDefault;
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

    if (! testerserverLoadRequiredIpv4Setting(&ts->packet_ipv4_source_addr, packet_ipv4, "source-ip",
                                              "TesterServer->settings->packet-ipv4->source-ip") ||
        ! testerserverLoadRequiredIpv4Setting(&ts->packet_ipv4_dest_addr, packet_ipv4, "dest-ip",
                                              "TesterServer->settings->packet-ipv4->dest-ip") ||
        ! testerserverLoadUint8Setting(&ts->packet_ipv4_protocol, packet_ipv4, "protocol",
                                       kTesterServerPacketIpv4ProtocolDefault,
                                       "TesterServer->settings->packet-ipv4->protocol") ||
        ! testerserverLoadUint8Setting(&ts->packet_ipv4_ttl, packet_ipv4, "ttl", kTesterServerPacketIpv4TtlDefault,
                                       "TesterServer->settings->packet-ipv4->ttl"))
    {
        return false;
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
    t->onDestroy = &testerserverTunnelDestroy;

    testerserver_tstate_t *ts       = tunnelGetState(t);
    const cJSON           *settings = node->node_settings_json;
    int                    chunk_count = kTesterServerChunkCount;

    getBoolFromJsonObjectOrDefault(&ts->packet_mode, settings, "packet-mode", false);
    getBoolFromJsonObjectOrDefault(&ts->packet_init_on_start, settings, "packet-init-on-start", false);
    getBoolFromJsonObjectOrDefault(&ts->streaming_response, settings, "streaming-response", false);
    getIntFromJsonObjectOrDefault(&chunk_count, settings, "chunk-count", kTesterServerChunkCount);

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

    if (ts->packet_init_on_start && ! ts->packet_mode)
    {
        LOGF("TesterServer: settings->packet-init-on-start requires packet-mode=true");
        testerserverTunnelDestroy(t);
        return NULL;
    }

    if (! testerserverLoadPacketIpv4Settings(ts, settings))
    {
        testerserverTunnelDestroy(t);
        return NULL;
    }

    return t;
}

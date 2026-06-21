#include "structure.h"

#include "loggers/network_logger.h"

static uint64_t junkdatagramsenderAllProtocolsMask(void)
{
    size_t                                        count       = 0;
    const junkdatagramsender_module_descriptor_t *descriptors = junkdatagramsenderGetModuleDescriptors(&count);
    uint64_t                                      mask        = 0;

    for (size_t i = 0; i < count; ++i)
    {
        mask |= UINT64_C(1) << (uint32_t) descriptors[i].protocol;
    }
    return mask;
}

static bool junkdatagramsenderProtocolNameMatches(const char *value, const char *name)
{
    return value != NULL && name != NULL && strcasecmp(value, name) == 0;
}

static bool junkdatagramsenderProtocolIsDisabled(const char *value)
{
    return junkdatagramsenderProtocolNameMatches(value, "tftp") ||
           junkdatagramsenderProtocolNameMatches(value, "ssdp") ||
           junkdatagramsenderProtocolNameMatches(value, "radius") ||
           junkdatagramsenderProtocolNameMatches(value, "gtp-u") ||
           junkdatagramsenderProtocolNameMatches(value, "gtpu") ||
           junkdatagramsenderProtocolNameMatches(value, "game-udp-protocols") ||
           junkdatagramsenderProtocolNameMatches(value, "game-udp") ||
           junkdatagramsenderProtocolNameMatches(value, "game") || junkdatagramsenderProtocolNameMatches(value, "coap");
}

static bool junkdatagramsenderProtocolFromName(const char *value, junkdatagramsender_protocol_t *protocol)
{
    if (value == NULL || value[0] == '\0')
    {
        return false;
    }

    if (junkdatagramsenderProtocolNameMatches(value, "dns"))
    {
        *protocol = kJunkDatagramSenderProtocolDns;
        return true;
    }
    if (junkdatagramsenderProtocolNameMatches(value, "dhcp"))
    {
        *protocol = kJunkDatagramSenderProtocolDhcp;
        return true;
    }
    if (junkdatagramsenderProtocolNameMatches(value, "ntp"))
    {
        *protocol = kJunkDatagramSenderProtocolNtp;
        return true;
    }
    if (junkdatagramsenderProtocolNameMatches(value, "quic-http3") ||
        junkdatagramsenderProtocolNameMatches(value, "quic") || junkdatagramsenderProtocolNameMatches(value, "http3") ||
        junkdatagramsenderProtocolNameMatches(value, "http/3") ||
        junkdatagramsenderProtocolNameMatches(value, "quic/http3"))
    {
        *protocol = kJunkDatagramSenderProtocolQuicHttp3;
        return true;
    }
    if (junkdatagramsenderProtocolNameMatches(value, "rtp-rtcp-srtp") ||
        junkdatagramsenderProtocolNameMatches(value, "rtp") || junkdatagramsenderProtocolNameMatches(value, "rtcp") ||
        junkdatagramsenderProtocolNameMatches(value, "srtp"))
    {
        *protocol = kJunkDatagramSenderProtocolRtpRtcpSrtp;
        return true;
    }
    if (junkdatagramsenderProtocolNameMatches(value, "stun-turn-ice") ||
        junkdatagramsenderProtocolNameMatches(value, "stun") || junkdatagramsenderProtocolNameMatches(value, "turn") ||
        junkdatagramsenderProtocolNameMatches(value, "ice"))
    {
        *protocol = kJunkDatagramSenderProtocolStunTurnIce;
        return true;
    }
    if (junkdatagramsenderProtocolNameMatches(value, "mdns"))
    {
        *protocol = kJunkDatagramSenderProtocolMdns;
        return true;
    }
    if (junkdatagramsenderProtocolNameMatches(value, "snmp"))
    {
        *protocol = kJunkDatagramSenderProtocolSnmp;
        return true;
    }
    if (junkdatagramsenderProtocolNameMatches(value, "syslog"))
    {
        *protocol = kJunkDatagramSenderProtocolSyslog;
        return true;
    }
    if (junkdatagramsenderProtocolNameMatches(value, "ipsec-nat-t") ||
        junkdatagramsenderProtocolNameMatches(value, "ipsec-natt") ||
        junkdatagramsenderProtocolNameMatches(value, "natt"))
    {
        *protocol = kJunkDatagramSenderProtocolIpsecNatt;
        return true;
    }
    if (junkdatagramsenderProtocolNameMatches(value, "sip"))
    {
        *protocol = kJunkDatagramSenderProtocolSip;
        return true;
    }
    return false;
}

static bool junkdatagramsenderLoadProtocolSelection(junkdatagramsender_tstate_t *ts, const cJSON *settings)
{
    const cJSON *selected = cJSON_GetObjectItemCaseSensitive(settings, "selected-protocols");

    if (selected == NULL)
    {
        ts->selected_protocol_mask = junkdatagramsenderAllProtocolsMask();
        return true;
    }

    if (! cJSON_IsArray(selected))
    {
        LOGF("JunkDatagramSender: settings.selected-protocols must be an array of lowercase protocol names");
        return false;
    }

    ts->selected_protocol_mask = 0;

    const int count = cJSON_GetArraySize(selected);
    for (int i = 0; i < count; ++i)
    {
        const cJSON *item = cJSON_GetArrayItem(selected, i);
        if (! cJSON_IsString(item) || item->valuestring == NULL)
        {
            LOGF("JunkDatagramSender: settings.selected-protocols[%d] must be a string", i);
            return false;
        }

        if (junkdatagramsenderProtocolNameMatches(item->valuestring, "all"))
        {
            ts->selected_protocol_mask = junkdatagramsenderAllProtocolsMask();
            continue;
        }

        junkdatagramsender_protocol_t protocol = kJunkDatagramSenderProtocolDns;
        if (junkdatagramsenderProtocolIsDisabled(item->valuestring))
        {
            LOGF("JunkDatagramSender: selected protocol \"%s\" is disabled until its packet generator is implemented",
                 item->valuestring);
            return false;
        }
        if (! junkdatagramsenderProtocolFromName(item->valuestring, &protocol))
        {
            LOGF("JunkDatagramSender: unknown selected protocol \"%s\"", item->valuestring);
            return false;
        }

        ts->selected_protocol_mask |= UINT64_C(1) << (uint32_t) protocol;
    }

    if (ts->selected_protocol_mask == 0)
    {
        LOGW("JunkDatagramSender: selected-protocols is empty; this node will only pass traffic through");
    }

    return true;
}

bool junkdatagramsenderLoadSettings(junkdatagramsender_tstate_t *ts, const cJSON *settings)
{
    *ts = (junkdatagramsender_tstate_t) {
        .selected_protocol_mask = junkdatagramsenderAllProtocolsMask(),
        .packet_count_min       = kJunkDatagramSenderDefaultPacketCount,
        .packet_count_max       = kJunkDatagramSenderDefaultPacketCount,
        .keep_sending_max_ms    = 0,
    };

    int packet_min = (int) ts->packet_count_min;
    int packet_max = (int) ts->packet_count_max;
    int keep_ms    = 0;

    getIntFromJsonObjectOrDefault(&packet_min, settings, "packet-count-perline-min", packet_min);
    getIntFromJsonObjectOrDefault(&packet_max, settings, "packet-count-perline-max", packet_max);
    getIntFromJsonObjectOrDefault(&keep_ms, settings, "keep-sending-max-ms", 0);

    if (packet_min < 0)
    {
        LOGW("JunkDatagramSender: packet-count-perline-min was negative; clamping to 0");
        packet_min = 0;
    }
    if (packet_max < 0)
    {
        LOGW("JunkDatagramSender: packet-count-perline-max was negative; clamping to 0");
        packet_max = 0;
    }
    if (packet_max < packet_min)
    {
        LOGW("JunkDatagramSender: packet-count-perline-max is lower than min; clamping max to min");
        packet_max = packet_min;
    }
    if (packet_max > kJunkDatagramSenderMaxPacketsPerLine)
    {
        LOGW("JunkDatagramSender: packet-count-perline-max exceeds %u; clamping",
             (unsigned int) kJunkDatagramSenderMaxPacketsPerLine);
        packet_max = kJunkDatagramSenderMaxPacketsPerLine;
    }
    if (packet_min > packet_max)
    {
        packet_min = packet_max;
    }
    if (keep_ms < 0)
    {
        LOGW("JunkDatagramSender: keep-sending-max-ms was negative; disabling delayed sends");
        keep_ms = 0;
    }

    ts->packet_count_min    = (uint32_t) packet_min;
    ts->packet_count_max    = (uint32_t) packet_max;
    ts->keep_sending_max_ms = (uint32_t) keep_ms;

    return junkdatagramsenderLoadProtocolSelection(ts, settings);
}

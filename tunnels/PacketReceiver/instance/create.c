#include "structure.h"

#include "loggers/network_logger.h"

static bool packetreceiverParseSourceRange(packetreceiver_source_range_t *range, const char *cidr,
                                           const char *json_path)
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

static bool packetreceiverLoadSourceRanges(packetreceiver_tstate_t *state, const cJSON *settings)
{
    const cJSON *range_json = cJSON_GetObjectItemCaseSensitive(settings, "source-ip4-range");

    if (range_json == NULL)
    {
        LOGF("JSON Error: PacketReceiver->settings->source-ip4-range (string or array field) : expected one or more "
             "IPv4 CIDR ranges");
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
        LOGF("JSON Error: PacketReceiver->settings->source-ip4-range (string or array field) : expected one or more "
             "IPv4 CIDR ranges");
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
            stringNPrintf(json_path, sizeof(json_path), "PacketReceiver->settings->source-ip4-range[%d]", i);
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
            stringCopy(json_path, "PacketReceiver->settings->source-ip4-range");
        }

        if (! packetreceiverParseSourceRange(&state->source_ranges[i], cidr, json_path))
        {
            return false;
        }

        if (state->source_ranges[i].count > (UINT64_MAX - total_source_count))
        {
            LOGF("PacketReceiver: total source range size overflow");
            return false;
        }

        total_source_count += state->source_ranges[i].count;
    }

    state->source_count = total_source_count;
    if (state->source_count == 0)
    {
        LOGF("PacketReceiver: source-ip4-range resolved to zero source IPs");
        return false;
    }

    return true;
}

static bool packetreceiverLoadExpectedPacketsPerIp(packetreceiver_tstate_t *state, const cJSON *settings)
{
    int packets_per_ip = 1;

    getIntFromJsonObjectOrDefault(&packets_per_ip, settings, "expected-packets-per-ip", 1);

    if (packets_per_ip <= 0)
    {
        LOGF("JSON Error: PacketReceiver->settings->expected-packets-per-ip (int field) : expected a positive packet "
             "count");
        return false;
    }

    state->expected_packets_per_ip = (uint32_t) packets_per_ip;
    return true;
}

static bool packetreceiverLoadOutputFile(packetreceiver_tstate_t *state, const cJSON *settings)
{
    getStringFromJsonObjectOrDefault(&state->output_file, settings, "output-file", "packet-receiver-report.txt");

    if (state->output_file == NULL || state->output_file[0] == '\0')
    {
        LOGF("JSON Error: PacketReceiver->settings->output-file (string field) : expected a non-empty file path");
        return false;
    }

    return true;
}

static bool packetreceiverLoadReportAfterMs(packetreceiver_tstate_t *state, const cJSON *settings)
{
    int report_after_ms = 1000;

    getIntFromJsonObjectOrDefault(&report_after_ms, settings, "report-after-ms", report_after_ms);

    if (report_after_ms <= 0)
    {
        LOGF("JSON Error: PacketReceiver->settings->report-after-ms (int field) : expected a positive millisecond "
             "value");
        return false;
    }

    state->report_after_ms = (uint32_t) report_after_ms;
    return true;
}

tunnel_t *packetreceiverTunnelCreate(node_t *node)
{
    tunnel_t *t = packettunnelCreate(node, sizeof(packetreceiver_tstate_t), 0);

    if (t == NULL)
    {
        return NULL;
    }

    t->fnInitU    = &packetreceiverTunnelUpStreamInit;
    t->fnEstU     = &packetreceiverTunnelUpStreamEst;
    t->fnFinU     = &packetreceiverTunnelUpStreamFinish;
    t->fnPayloadU = &packetreceiverTunnelUpStreamPayload;
    t->fnPauseU   = &packetreceiverTunnelUpStreamPause;
    t->fnResumeU  = &packetreceiverTunnelUpStreamResume;

    t->fnInitD    = &packetreceiverTunnelDownStreamInit;
    t->fnEstD     = &packetreceiverTunnelDownStreamEst;
    t->fnFinD     = &packetreceiverTunnelDownStreamFinish;
    t->fnPayloadD = &packetreceiverTunnelDownStreamPayload;
    t->fnPauseD   = &packetreceiverTunnelDownStreamPause;
    t->fnResumeD  = &packetreceiverTunnelDownStreamResume;

    t->onPrepare = &packetreceiverTunnelOnPrepair;
    t->onStart   = &packetreceiverTunnelOnStart;
    t->onStop    = &packetreceiverTunnelOnStop;
    t->onDestroy = &packetreceiverTunnelDestroy;

    packetreceiver_tstate_t *state    = tunnelGetState(t);
    const cJSON             *settings = node->node_settings_json;

    mutexInit(&state->state_mutex);

    if (! checkJsonIsObjectAndHasChild(settings))
    {
        LOGF("JSON Error: PacketReceiver->settings (object field) : The object was empty or invalid");
        packetreceiverTunnelDestroy(t);
        return NULL;
    }
    state->expected_packets_per_ip = 1;

    if (! packetreceiverLoadSourceRanges(state, settings) ||
        ! packetreceiverLoadExpectedPacketsPerIp(state, settings) || ! packetreceiverLoadOutputFile(state, settings) ||
        ! packetreceiverLoadReportAfterMs(state, settings))
    {
        packetreceiverTunnelDestroy(t);
        return NULL;
    }

    state->total_expected_packets = state->source_count * (uint64_t) state->expected_packets_per_ip;
    return t;
}

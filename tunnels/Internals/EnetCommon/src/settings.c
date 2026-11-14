#include "EnetCommon/settings.h"

#include "EnetCommon/driver.h"

#include "loggers/network_logger.h"

static bool settingsReadInteger(const cJSON *json, const char *node_type, const char *key, int64_t minimum,
                                int64_t maximum, uint32_t *value)
{
    int64_t parsed = *value;
    if (jsonGetObjectIntegerInRange(json, key, minimum, maximum, &parsed) == kJsonValueInvalid)
    {
        LOGF("JSON Error: %s->settings->%s must be an integer in %lld..%lld",
             node_type,
             key,
             (long long) minimum,
             (long long) maximum);
        return false;
    }
    *value = (uint32_t) parsed;
    return true;
}

bool enetSettingsParse(enet_settings_t *settings, const cJSON *json, const char *node_type)
{
    *settings = (enet_settings_t) {
        .ping_interval_ms       = kEnetPingIntervalDefault,
        .no_recv_timeout_ms     = kEnetNoRecvTimeoutDefault,
        .send_buffer_limit      = kEnetSendBufferDefault,
        .receive_buffer_limit   = kEnetReceiveBufferDefault,
        .carrier_queue_limit    = kEnetCarrierQueueDefault,
        .close_drain_timeout_ms = kEnetCloseDrainDefault,
    };

    /* The core MTU is only the default seed. An inherited value passes the same check as an explicit one. */
    int64_t                   send_mtu = CORE_DEFAULT_MTU;
    const json_value_status_t status =
        jsonGetObjectIntegerInRange(json, "send-mtu", kEnetSendMtuMinimum, UINT16_MAX, &send_mtu);
    if (status == kJsonValueInvalid || send_mtu < kEnetSendMtuMinimum || send_mtu > UINT16_MAX)
    {
        LOGF("JSON Error: %s->settings->send-mtu must be an integer between %d and 65535%s",
             node_type,
             (int) kEnetSendMtuMinimum,
             status == kJsonValueMissing ? "; inherited core misc.mtu is unsupported; set an explicit node send-mtu"
                                         : "");
        return false;
    }
    settings->send_mtu = (uint16_t) send_mtu;
    /* A budget above ENet's maximum is valid and uses that maximum, as KcpClient does with its own. */
    settings->host_mtu = min((uint32_t) send_mtu - kEnetIpv4UdpOverhead, (uint32_t) kEnetDriverHostMtuMax);

    if (! settingsReadInteger(json, node_type, "no-recv-timeout-ms", 1, INT_MAX, &settings->no_recv_timeout_ms) ||
        ! settingsReadInteger(json, node_type, "ping-interval-ms", 1, INT_MAX, &settings->ping_interval_ms) ||
        ! settingsReadInteger(json,
                              node_type,
                              "send-buffer-limit",
                              kEnetDriverSendBufferMin,
                              kEnetDriverSendBufferMax,
                              &settings->send_buffer_limit) ||
        ! settingsReadInteger(json,
                              node_type,
                              "receive-buffer-limit",
                              kEnetDriverReceiveBufferMin,
                              kEnetDriverReceiveBufferMax,
                              &settings->receive_buffer_limit) ||
        ! settingsReadInteger(
            json, node_type, "carrier-queue-limit", 1, kEnetCarrierQueueMaximum, &settings->carrier_queue_limit) ||
        ! settingsReadInteger(
            json, node_type, "close-drain-timeout-ms", 1, INT_MAX, &settings->close_drain_timeout_ms) ||
        ! settingsReadInteger(json, node_type, "incoming-bandwidth", 0, UINT32_MAX, &settings->incoming_bandwidth) ||
        ! settingsReadInteger(json, node_type, "outgoing-bandwidth", 0, UINT32_MAX, &settings->outgoing_bandwidth))
    {
        return false;
    }
    if (settings->ping_interval_ms >= settings->no_recv_timeout_ms)
    {
        LOGF("JSON Error: %s->settings->ping-interval-ms (%u) must be smaller than no-recv-timeout-ms (%u)",
             node_type,
             settings->ping_interval_ms,
             settings->no_recv_timeout_ms);
        return false;
    }
    return true;
}

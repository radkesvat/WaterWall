#include "GnsCommon/settings.h"

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

bool gnsSettingsParse(gns_settings_t *settings, const cJSON *json, const char *node_type)
{
    *settings = (gns_settings_t) {
        .no_recv_timeout_ms     = kGnsNoRecvTimeoutDefault,
        .timeout_initial_ms     = kGnsTimeoutInitialDefault,
        .send_rate              = kGnsSendRateDefault,
        .send_buffer_limit      = kGnsSendBufferDefault,
        .receive_buffer_limit   = kGnsReceiveBufferDefault,
        .carrier_queue_limit    = kGnsCarrierQueueDefault,
        .close_drain_timeout_ms = kGnsCloseDrainDefault,
    };

    /* The core MTU is only the default seed. An inherited value passes the same check as an explicit one. */
    int64_t                   send_mtu = CORE_DEFAULT_MTU;
    const json_value_status_t status =
        jsonGetObjectIntegerInRange(json, "send-mtu", kGnsSendMtuMinimum, UINT16_MAX, &send_mtu);
    if (status == kJsonValueInvalid || send_mtu < kGnsSendMtuMinimum || send_mtu > UINT16_MAX)
    {
        LOGF("JSON Error: %s->settings->send-mtu must be an integer between %d and 65535%s",
             node_type,
             (int) kGnsSendMtuMinimum,
             status == kJsonValueMissing ? "; inherited core misc.mtu is unsupported; set an explicit node send-mtu"
                                         : "");
        return false;
    }
    settings->send_mtu = (uint16_t) send_mtu;
    /* A budget above GNS's maximum is valid and uses that maximum, as KcpClient does with its own. */
    settings->packet_size = min((uint32_t) send_mtu - kGnsIpv4UdpOverhead, (uint32_t) kGnsPacketSizeMaximum);

    if (! settingsReadInteger(json, node_type, "no-recv-timeout-ms", 1, INT_MAX, &settings->no_recv_timeout_ms) ||
        ! settingsReadInteger(json, node_type, "timeout-initial-ms", 1, INT_MAX, &settings->timeout_initial_ms) ||
        ! settingsReadInteger(
            json, node_type, "send-rate", kGnsSendRateMinimum, kGnsSendRateMaximum, &settings->send_rate) ||
        ! settingsReadInteger(json,
                              node_type,
                              "send-buffer-limit",
                              kGnsSendBufferMinimum,
                              kGnsSendBufferMaximum,
                              &settings->send_buffer_limit) ||
        ! settingsReadInteger(json,
                              node_type,
                              "receive-buffer-limit",
                              kGnsReceiveBufferMinimum,
                              kGnsReceiveBufferMaximum,
                              &settings->receive_buffer_limit) ||
        ! settingsReadInteger(
            json, node_type, "carrier-queue-limit", 1, kGnsCarrierQueueMaximum, &settings->carrier_queue_limit) ||
        ! settingsReadInteger(json, node_type, "close-drain-timeout-ms", 1, INT_MAX, &settings->close_drain_timeout_ms))
    {
        return false;
    }

    /* Twice the hold, as for ENet, but never more data than GNS's packet numbering can keep apart. */
    const uint64_t window     = (uint64_t) kGnsWindowPackets * (settings->packet_size - kGnsPacketOverhead);
    settings->send_hard_limit = (uint32_t) min((uint64_t) settings->send_buffer_limit * 2U, window);
    if (settings->send_buffer_limit > settings->send_hard_limit / 2U)
    {
        LOGW("%s: send-buffer-limit %u is more than GNS can keep unacknowledged with send-mtu %u; using %u",
             node_type,
             settings->send_buffer_limit,
             (unsigned) settings->send_mtu,
             settings->send_hard_limit / 2U);
        settings->send_buffer_limit = settings->send_hard_limit / 2U;
    }
    settings->receive_messages_limit =
        max(settings->receive_buffer_limit / kGnsReceiveMessageBytes, (uint32_t) kGnsReceiveMessagesFloor);
    return true;
}

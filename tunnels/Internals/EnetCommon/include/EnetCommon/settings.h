#pragma once

#include "wwapi.h"

/* Settings shared by EnetClient and EnetServer. Each node parses them once in its constructor; they never change
 * afterwards. */
enum
{
    kEnetIpv4UdpOverhead      = 28,  /* IPv4 header plus UDP header; the allowance KcpClient uses for send-mtu */
    kEnetSendMtuMinimum       = 604, /* ENet's smallest host MTU, 576, plus that allowance */
    kEnetNoRecvTimeoutDefault = 30000,
    kEnetPingIntervalDefault  = 10000,
    kEnetSendBufferDefault    = 524288,
    kEnetReceiveBufferDefault = 1048576,
    kEnetCarrierQueueDefault  = 256,
    kEnetCarrierQueueMaximum  = 65535,
    kEnetCloseDrainDefault    = 30000,
};

typedef struct enet_settings_s
{
    uint16_t send_mtu;               /* configured IPv4 packet budget */
    uint32_t host_mtu;               /* ENet host MTU: send_mtu minus 28, capped at ENet's 4096 */
    uint32_t ping_interval_ms;       /* silence after which ENet sends a ping */
    uint32_t no_recv_timeout_ms;     /* T: an unacknowledged command ends the session between T and 2T */
    uint32_t send_buffer_limit;      /* producer hold threshold; the hard cap is twice this */
    uint32_t receive_buffer_limit;   /* decoded bytes ENet may retain; the largest message is half of it */
    uint32_t carrier_queue_limit;    /* outgoing datagrams staged per session before ENet's output is dropped */
    uint32_t close_drain_timeout_ms; /* how long a graceful close may wait for the peer */
    uint32_t incoming_bandwidth;     /* bytes per second, 0 = unlimited */
    uint32_t outgoing_bandwidth;     /* bytes per second, 0 = unlimited */
} enet_settings_t;

/* Reads the node's "settings" object. A missing object or field keeps its default. On the first invalid field it
 * logs a message that names node_type and the field, and returns false. */
bool enetSettingsParse(enet_settings_t *settings, const cJSON *json, const char *node_type);

#pragma once

#include "wwapi.h"

/* Settings shared by GnsClient and GnsServer. Each node parses them once in its constructor; they never change
 * afterwards. */
enum
{
    kGnsIpv4UdpOverhead       = 28,   /* IPv4 header plus UDP header; the allowance KcpClient uses for send-mtu */
    kGnsPacketSizeMinimum     = 200,  /* GNS's smallest MTU_PacketSize */
    kGnsPacketSizeMaximum     = 1300, /* GNS's largest datagram */
    kGnsSendMtuMinimum        = kGnsPacketSizeMinimum + kGnsIpv4UdpOverhead,
    kGnsNoRecvTimeoutDefault  = 30000,
    kGnsTimeoutInitialDefault = 10000,
    kGnsSendRateDefault       = 262144, /* GNS's own default, about 2 Mbit/s */
    kGnsSendRateMinimum       = 1024,
    kGnsSendRateMaximum       = 104857600, /* GNS clamps a higher rate to this */
    kGnsSendBufferDefault     = 524288,
    kGnsSendBufferMinimum     = 4096,
    kGnsSendBufferMaximum     = 0x08000000,
    kGnsReceiveBufferDefault  = 1048576,
    kGnsReceiveBufferMinimum  = 131072,
    kGnsReceiveBufferMaximum  = 0x10000000,
    kGnsReceiveMessagesFloor  = 1000, /* GNS's own RecvBufferMessages */
    kGnsReceiveMessageBytes   = 256,  /* one more waiting message is allowed per this many bytes of the buffer */
    kGnsCarrierQueueDefault   = 256,
    kGnsCarrierQueueMaximum   = 65535,
    kGnsCloseDrainDefault     = 30000,
    kGnsMessageBytesMaximum   = 65536, /* the node never sends a larger native message */

    /* GNS carries 16 bits of each packet number and tracks at most 65,535 unacknowledged segments per connection;
     * passing the second limit ends the process. A packet with new data is either full or carries the end of a
     * message, so these two bounds keep the segments of one connection below 24,192 whatever the peer does. */
    kGnsWindowPackets     = 16000, /* queued plus unacknowledged data never exceeds this many packets' worth */
    kGnsPacketOverhead    = 100,   /* GNS header, encryption tag and segment framing, rounded up */
    kGnsMessagesHold      = 4096,  /* unacknowledged messages from which the producer is held */
    kGnsMessagesHardLimit = 8192,  /* unacknowledged messages at which a payload is refused */
};

typedef struct gns_settings_s
{
    uint16_t send_mtu;               /* configured IPv4 packet budget */
    uint32_t packet_size;            /* GNS MTU_PacketSize: send_mtu minus 28, capped at 1300 */
    uint32_t no_recv_timeout_ms;     /* GNS TimeoutConnected */
    uint32_t timeout_initial_ms;     /* GNS TimeoutInitial */
    uint32_t send_rate;              /* bytes per second; GNS SendRateMin and SendRateMax */
    uint32_t send_buffer_limit;      /* producer hold threshold for queued plus unacknowledged bytes */
    uint32_t send_hard_limit;        /* refusal threshold: twice the hold, at most kGnsWindowPackets packets' worth */
    uint32_t receive_buffer_limit;   /* GNS RecvBufferSize; the largest accepted message is half of it */
    uint32_t receive_messages_limit; /* GNS RecvBufferMessages, derived from the byte limit */
    uint32_t carrier_queue_limit;    /* outgoing datagrams that may wait for the carrier per session */
    uint32_t close_drain_timeout_ms; /* how long a graceful close may wait for the peer */
} gns_settings_t;

/* Reads the node's "settings" object. A missing object or field keeps its default. On the first invalid field it
 * logs a message that names node_type and the field, and returns false. */
bool gnsSettingsParse(gns_settings_t *settings, const cJSON *json, const char *node_type);

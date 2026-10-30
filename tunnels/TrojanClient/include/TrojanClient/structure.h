#pragma once

#include "DomainResolver/interface.h"
#include "ProxyClientCommon/first_payload_window.h"
#include "SocksAddress/address_codec.h"
#include "wwapi.h"

/* Wire command and address tags shared by encoding and parsing. */
enum
{
    kTrojanCommandConnect      = 0x01,
    kTrojanCommandUdpAssociate = 0x03,
    kTrojanAtypIpv4            = 0x01,
    kTrojanAtypDomain          = 0x03,
    kTrojanAtypIpv6            = 0x04
};

typedef enum trojanclient_protocol_e
{
    kTrojanClientProtocolDestContext = 0,
    kTrojanClientProtocolTcp         = 1,
    kTrojanClientProtocolUdp         = 3
} trojanclient_protocol_t;

typedef enum trojanclient_phase_e
{
    kTrojanClientPhaseClosed = 0,
    kTrojanClientPhaseIdle,
    kTrojanClientPhaseEstablished
} trojanclient_phase_t;

typedef enum trojanclient_line_kind_e
{
    kTrojanClientLineKindDirect = 0,
    kTrojanClientLineKindUdpApplication,
    kTrojanClientLineKindUdpCarrier
} trojanclient_line_kind_t;

typedef enum trojanclient_close_origin_e
{
    kTrojanClientCloseInternal = 0,
    kTrojanClientCloseFromPrev,
    kTrojanClientCloseFromNext
} trojanclient_close_origin_t;

enum
{
    kTrojanClientPasswordHexLen      = SHA224_DIGEST_SIZE * 2,
    kTrojanClientCrlfLen             = 2,
    kTrojanClientUdpMaxPacket        = UINT16_MAX,
    kTrojanClientUdpHeaderMaxLen     = 1 + 1 + UINT8_MAX + 2 + 2 + 2,
    /* IPv4 UDP association request plus the largest first datagram header. */
    kTrojanClientInitialPadding      = 68 + kTrojanClientUdpHeaderMaxLen,
    kTrojanClientMaxUdpBufferedBytes = 2 * 1024 * 1024 + kTrojanClientUdpHeaderMaxLen + kTrojanClientUdpMaxPacket
};

typedef struct trojanclient_tstate_s
{
    node_t        domain_resolver_node;
    tunnel_t     *domain_resolver_tunnel;
    struct cJSON *domain_resolver_settings;

    address_context_t       target_addr;
    uint8_t                 password_hex[kTrojanClientPasswordHexLen];
    int                     domain_strategy;
    uint32_t                target_addr_source;
    uint32_t                target_port_source;
    trojanclient_protocol_t protocol;
    uint32_t                first_payload_timeout_ms;
    bool                    verbose;
    bool                    resolve_domains;
} trojanclient_tstate_t;

typedef struct trojanclient_lstate_s
{
    /* This state belongs to line. Direct/application lines are borrowed;
     * TrojanClient owns each UDP carrier. Both association links detach on close. */
    line_t                  *line;
    line_t                  *application_line; // Carrier's borrowed application line.
    line_t                  *carrier_line;     // Application's dependent TCP carrier.
    trojanclient_line_kind_t kind;
    trojanclient_protocol_t  protocol;
    trojanclient_phase_t     phase;

    /* Worker-owned transport, dispatch and parser flags share storage. */
    bool request_sent : 1;
    bool est_notifying : 1;
    bool carrier_paused : 1; // UDP carrier-head permission for the independent idle-header producer.
    bool receiving : 1;
    bool header_ready : 1;

    address_context_t target_addr;

    /* Transport context and the independent first-payload deadline. */
    tunnel_t              *tunnel;
    first_payload_window_t first_payload;

    /* Each FIFO entry is one admitted nested input batch. The outer parser
     * completes these in order and retains only an incomplete wire suffix.
     * No ready output or application payload is queued for Pause or Est. */
    buffer_queue_t pending_down;

    /* UDP decoder on the carrier. The popped head is still owned here;
     * receive_bytes includes queued bytes, this head and the cached header. */
    sbuf_t  *receive_head;
    size_t   receive_bytes;
    uint8_t  header[kTrojanClientUdpHeaderMaxLen];
    uint16_t header_filled;
    uint16_t header_needed;
    uint16_t body_length;
} trojanclient_lstate_t;

enum
{
    kTunnelStateSize = sizeof(trojanclient_tstate_t),
    kLineStateSize   = sizeof(trojanclient_lstate_t)
};

#pragma once

#include "DomainResolver/interface.h"
#include "ProxyClientCommon/first_payload_window.h"
#include "VlessCommon/input.h"
#include "wwapi.h"

typedef enum vlessclient_protocol_e
{
    kVlessClientProtocolDestContext = 0,
    kVlessClientProtocolTcp         = 1,
    kVlessClientProtocolUdp         = 2
} vlessclient_protocol_t;

typedef enum vlessclient_phase_e
{
    kVlessClientPhaseClosed = 0,
    kVlessClientPhaseIdle,
    kVlessClientPhaseEstablished // Transport Est published; protocol readiness is independent.
} vlessclient_phase_t;

typedef enum vlessclient_line_kind_e
{
    kVlessClientLineKindDirect = 0,
    kVlessClientLineKindUdpApplication,
    kVlessClientLineKindUdpCarrier
} vlessclient_line_kind_t;

typedef enum vlessclient_close_origin_e
{
    kVlessClientCloseInternal = 0,
    kVlessClientCloseFromPrev,
    kVlessClientCloseFromNext
} vlessclient_close_origin_t;

enum
{
    kVlessClientMaxOrderBytes       = 2 * 1024 * 1024,
    kVlessClientMaxOrderEntries     = 1024,
    kVlessClientUuidLen             = 16,
    kVlessClientResponseLen         = 2,
    kVlessClientUdpHeaderLen        = kVlessUdpHeaderLen,
    /* Maximum domain request plus the first datagram's length prefix. */
    kVlessClientInitialPadding      = 23 + UINT8_MAX + kVlessClientUdpHeaderLen,
    kVlessClientUdpMaxPacket        = UINT16_MAX,
    kVlessClientResponseMaxLen      = 257,
    kVlessClientMaxTcpWireBytes     = 2097409,
    kVlessClientMaxUdpBufferedBytes = 2162689,
    kVlessClientMaxInputCharge      = 8 * 1024 * 1024,
    kVlessClientMaxInputBuffers     = 1024,
};

typedef struct vlessclient_tstate_s
{
    node_t        domain_resolver_node;
    tunnel_t     *domain_resolver_tunnel;
    struct cJSON *domain_resolver_settings;

    address_context_t      target_addr;
    uint8_t                uuid[kVlessClientUuidLen];
    int                    domain_strategy;
    uint32_t               target_addr_source;
    uint32_t               target_port_source;
    vlessclient_protocol_t protocol;
    uint32_t               first_payload_timeout_ms;
    bool                   verbose;
    bool                   resolve_domains;
} vlessclient_tstate_t;

typedef struct vlessclient_lstate_s
{
    /* This state belongs to line. Direct/application lines are borrowed;
     * VlessClient owns each UDP carrier. Both association links detach on close. */
    line_t                 *line;
    line_t                 *application_line; // Carrier's borrowed application line.
    line_t                 *carrier_line;     // Application's dependent TCP carrier.
    vlessclient_line_kind_t kind;
    vlessclient_phase_t     phase;

    /* Worker-owned transport, dispatch and parser flags share storage. */
    bool request_sent : 1;
    bool est_notifying : 1;
    bool carrier_paused : 1; // UDP carrier-head permission for the independent idle-header producer.
    bool response_complete : 1;
    bool receiving : 1;

    address_context_t target_addr;

    /* Transport context and the independent first-payload deadline. */
    tunnel_t              *tunnel;
    first_payload_window_t first_payload;

    /* Admitted input follows the active head in FIFO order; pressure compaction
     * may coalesce entries. The outer parser completes these batches in order
     * and retains only an incomplete wire suffix. No ready output or application
     * payload is queued for Pause or Est. */
    buffer_reader_t reader;

    /* Response metadata on direct/carrier lines, then UDP metadata on carriers.
     * The reader includes this cache in its retained logical-byte accounting. */
    uint8_t  header[kVlessClientResponseMaxLen];
    uint16_t body_length;
} vlessclient_lstate_t;

enum
{
    kTunnelStateSize = sizeof(vlessclient_tstate_t),
    kLineStateSize   = sizeof(vlessclient_lstate_t)
};

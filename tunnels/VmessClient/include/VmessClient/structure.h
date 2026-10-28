#pragma once
#include "DomainResolver/interface.h"
#include "ProxyClientCommon/first_payload_window.h"
#include "VmessCommon/crypto.h"
#include "wwapi.h"

typedef enum vmessclient_protocol_e
{
    kVmessClientProtocolDestContext = 0,
    kVmessClientProtocolTcp         = 1,
    kVmessClientProtocolUdp         = 2
} vmessclient_protocol_t;
typedef enum vmessclient_phase_e
{
    kVmessClientPhaseClosed = 0,
    kVmessClientPhaseIdle,
    kVmessClientPhaseEstablished
} vmessclient_phase_t;
typedef enum vmessclient_line_kind_e
{
    kVmessClientLineKindDirect = 0,
    kVmessClientLineKindUdpApplication,
    kVmessClientLineKindUdpCarrier
} vmessclient_line_kind_t;
typedef enum vmessclient_close_origin_e
{
    kVmessClientCloseInternal = 0,
    kVmessClientCloseFromPrev,
    kVmessClientCloseFromNext
} vmessclient_close_origin_t;
enum
{
    kVmessClientMaxOrderBytes   = 2 * 1024 * 1024,
    kVmessClientMaxOrderEntries = 1024,
    kVmessClientMaxOrderCharge  = 8 * 1024 * 1024,
    kVmessClientUuidLen         = 16,
    kVmessClientTcpRecordSize   = 16384
};
typedef enum vmessclient_reason_e
{
    kVmessClientReasonNormalClose,
    kVmessClientReasonInvalidTarget,
    kVmessClientReasonMalformedHeader,
    kVmessClientReasonLengthFailure,
    kVmessClientReasonBodyFailure,
    kVmessClientReasonRetainedInput,
    kVmessClientReasonAdmissionRefused,
    kVmessClientReasonUdpOversize,
    kVmessClientReasonUnexpectedSource,
    kVmessClientReasonMalformedPacketAddr,
    kVmessClientReasonPacketAddrNeedsIp,
    kVmessClientReasonStrictExhaustion,
    kVmessClientReasonProviderFailure,
    kVmessClientReasonCount
} vmessclient_reason_t;
typedef struct vmessclient_stats_s
{
    atomic_ullong active_applications, active_carriers;
    atomic_ullong tx_records, rx_records, tx_application_bytes, rx_application_bytes;
    atomic_ullong tx_wire_bytes, rx_wire_bytes, tx_wraps, rx_wraps;
    atomic_ullong reasons[kVmessClientReasonCount], verbose_after_ms, verbose_suppressed;
} vmessclient_stats_t;
typedef struct vmessclient_tstate_s
{
    node_t                 domain_resolver_node;
    tunnel_t              *domain_resolver_tunnel;
    struct cJSON          *domain_resolver_settings;
    address_context_t      target_addr;
    vmess_prepared_key_t   key;
    uint8_t                uuid[kVmessClientUuidLen];
    int                    domain_strategy;
    uint32_t               target_addr_source, target_port_source;
    vmessclient_protocol_t protocol;
    uint32_t               first_payload_timeout_ms;
    uint8_t                security, options;
    bool                   verbose, resolve_domains, send_termination, packetaddr, security_auto;
    vmess_counter_policy_t counter_policy;
    vmessclient_stats_t    stats;
} vmessclient_tstate_t;
typedef struct vmessclient_lstate_s
{
    /* Direct/application lines are borrowed. This node owns only UDP carriers. */
    line_t                 *line, *application_line, *carrier_line;
    tunnel_t               *tunnel;
    vmessclient_line_kind_t kind;
    vmessclient_phase_t     phase;
    address_context_t       target_addr;
    first_payload_window_t  first_payload;
    bool                    request_sent, est_notifying, carrier_paused;
    bool                    response_complete, transmitting, receiving, closing;
    /* Storage belongs to the outer synchronous close frame. */
    struct vmessclient_close_context_s *close_context;
    bool                                prev_finished, next_finished, stats_counted, reason_recorded;
    vmess_packet_addr_t                 packet_target;
    vmess_body_ctx_t                    output_crypto, input_crypto;
    uint8_t                             response_key[16], response_iv[16], response_marker;
    buffer_queue_t                      pending_up, pending_down;
    buffer_budget_t                     upstream_budget, downstream_budget;
    buffer_budget_reservation_t         transmit_reservation, input_reservation, body_reservation;
    sbuf_t                             *transmit_head, *receive_head, *body_buffer;
    uint32_t                            body_length, body_filled;
    uint8_t                             header[293];
    uint16_t                            header_filled, response_length;
} vmessclient_lstate_t;
enum
{
    kTunnelStateSize = sizeof(vmessclient_tstate_t),
    kLineStateSize   = sizeof(vmessclient_lstate_t)
};

#pragma once

#include "DomainResolver/interface.h"
#include "splice_buffer.h"
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
    kVlessClientUuidLen             = 16,
    kVlessClientResponseLen         = 2,
    kVlessClientUdpHeaderLen        = 2,
    kVlessClientUdpMaxPacket        = UINT16_MAX,
    kVlessClientResponseMaxLen      = 257,
    kVlessClientMaxTcpWireBytes     = 2097409,
    kVlessClientMaxUdpBufferedBytes = 2162689,
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
    vlessclient_protocol_t  protocol;
    vlessclient_phase_t     phase;

    /* Worker-owned transport, dispatch and parser flags share storage. */
    bool next_started : 1;
    bool next_established : 1;
    bool request_sent : 1;
    bool est_notifying : 1;
    bool next_paused : 1; // Permission for the independent idle-header producer only.
    bool prev_paused : 1; // Forwarded source permission, never a parser batch gate.
    bool first_payload_due : 1;
    bool response_complete : 1;
    bool receiving : 1;

    address_context_t target_addr;

    /* Transport context and the independent first-payload deadline. */
    tunnel_t *tunnel;
    wtimer_t *first_payload_timer;
    uint64_t  first_payload_deadline_us;

    /* Each FIFO entry is one admitted nested input batch. The outer parser
     * completes these in order and retains only an incomplete wire suffix.
     * No ready output or application payload is queued for Pause or Est. */
    buffer_queue_t pending_down;

    /* Response decoder on direct/carrier lines, then UDP decoder on the carrier. The popped head is still owned here;
     * receive_bytes includes queued bytes, this head and the cached header. */
    sbuf_t  *receive_head;
    size_t   receive_bytes;
    uint8_t  header[kVlessClientResponseMaxLen];
    uint16_t header_filled;
    uint16_t header_needed;
    uint16_t body_length;
} vlessclient_lstate_t;

enum
{
    kTunnelStateSize = sizeof(vlessclient_tstate_t),
    kLineStateSize   = sizeof(vlessclient_lstate_t)
};

WW_EXPORT void         vlessclientTunnelDestroy(tunnel_t *t, const ww_lifecycle_context_t *context);
WW_EXPORT tunnel_t    *vlessclientTunnelCreate(node_t *node);
WW_EXPORT api_result_t vlessclientTunnelApi(tunnel_t *instance, sbuf_t *message);

void vlessclientTunnelOnChain(tunnel_t *t, tunnel_chain_t *chain);

void vlessclientTunnelUpStreamInit(tunnel_t *t, line_t *l);
void vlessclientTunnelUpStreamFinish(tunnel_t *t, line_t *l);
void vlessclientTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void vlessclientTunnelUpStreamPause(tunnel_t *t, line_t *l);
void vlessclientTunnelUpStreamResume(tunnel_t *t, line_t *l);

void vlessclientTunnelDownStreamEst(tunnel_t *t, line_t *l);
void vlessclientTunnelDownStreamFinish(tunnel_t *t, line_t *l);
void vlessclientTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void vlessclientTunnelDownStreamPause(tunnel_t *t, line_t *l);
void vlessclientTunnelDownStreamResume(tunnel_t *t, line_t *l);
bool vlessclientDomainResolverPrepare(tunnel_t *resolver, tunnel_t *client, line_t *l, void *user_lstate);

void vlessclientLinestateInitialize(vlessclient_lstate_t *ls, line_t *l);
void vlessclientLinestateDestroy(vlessclient_lstate_t *ls);

void vlessclientTunnelstateDestroy(vlessclient_tstate_t *ts);
bool vlessclientApplyTargetContext(tunnel_t *t, line_t *l);
void vlessclientStartUdpCarrier(tunnel_t *t, line_t *l, vlessclient_lstate_t *ls);
void vlessclientOnNextEstablished(tunnel_t *t, line_t *l, vlessclient_lstate_t *ls);
void vlessclientCloseLine(tunnel_t *t, line_t *l, vlessclient_close_origin_t origin);

bool vlessclientAssociationAlive(tunnel_t *t, line_t *next_line, line_t *prev_line);
void vlessclientSendDueRequest(tunnel_t *t, line_t *l);
void vlessclientCancelFirstPayloadTimer(vlessclient_lstate_t *ls);
void vlessclientSetNextPaused(tunnel_t *t, line_t *l, bool paused);

void vlessclientSetPrevPaused(tunnel_t *t, line_t *l, bool paused);

/* Shared implementation helpers; callbacks retain their directional admission. */
bool    vlessclientSendInitialRequest(tunnel_t *t, line_t *l, vlessclient_lstate_t *ls, sbuf_t *body);
void    vlessclientWrapUdpPayload(line_t *l, sbuf_t **buf_io);
int     vlessclientReadUdpHeader(vlessclient_lstate_t *ls);
sbuf_t *vlessclientExtractUdpBody(vlessclient_lstate_t *ls);

int     vlessclientReadResponse(vlessclient_lstate_t *ls);
sbuf_t *vlessclientTakeTcpBody(vlessclient_lstate_t *ls);

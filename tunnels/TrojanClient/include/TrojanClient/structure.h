#pragma once

#include "DomainResolver/interface.h"
#include "splice_buffer.h"
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
    kTrojanClientLineKindUdpApp,
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
    kTrojanClientUdpMaxPacket        = 8192,
    kTrojanClientMaxQueuedBuffers    = 1024,
    kTrojanClientMaxPendingBytes     = 1024 * 1024,
    kTrojanClientMaxBufferedBytes    = 1024 * 1024,
    kTrojanClientUdpHeaderMaxLen     = 1 + 1 + UINT8_MAX + 2 + 2 + 2,
    kTrojanClientMaxUdpBufferedBytes = 1024 * 1024 + kTrojanClientUdpHeaderMaxLen + kTrojanClientUdpMaxPacket
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
    bool                    verbose;
    bool                    resolve_domains;
} trojanclient_tstate_t;

typedef struct trojanclient_lstate_s
{
    /* This state belongs to line. Direct/application lines are borrowed;
     * TrojanClient owns each UDP carrier. Both association links detach on close. */
    line_t                  *line;
    line_t                  *app_line;     // Carrier's borrowed application line.
    line_t                  *carrier_line; // Application's dependent TCP carrier.
    trojanclient_line_kind_t kind;
    trojanclient_protocol_t  protocol;
    trojanclient_phase_t     phase;
    address_context_t        target_addr;

    /* Request/Est ordering and reentrancy, on the direct line or UDP carrier. */
    bool next_started;
    bool next_established;
    bool request_sent;
    bool pumping;

    /* Consumer permission and producer notifications are separate state. In UDP
     * mode these flags live on the carrier and govern both associated lines. */
    bool next_paused;     // Next asked us to stop sending upstream payload.
    bool prev_paused;     // Prev asked us to stop sending downstream payload.
    bool prev_pause_sent; // We told prev to pause its upstream producer.
    bool next_pause_sent; // We told next to pause its downstream producer.

    /* Owned upstream FIFO on the direct/application line; UDP datagrams stay
     * unwrapped until forwardQueuedUpstream() sends them on the carrier. */
    buffer_queue_t pending_up;

    /* Owned downstream FIFO: opaque TCP on a direct line, UDP wire input on a carrier. */
    buffer_queue_t pending_down;

    /* UDP decoder on the carrier. The popped head is still owned here;
     * receive_bytes includes queued bytes, this head and the cached header. */
    sbuf_t  *receive_head;
    size_t   receive_bytes;
    uint8_t  header[kTrojanClientUdpHeaderMaxLen];
    uint16_t header_filled;
    uint16_t header_needed;
    uint16_t body_length;
    bool     header_ready;
} trojanclient_lstate_t;

enum
{
    kTunnelStateSize = sizeof(trojanclient_tstate_t),
    kLineStateSize   = sizeof(trojanclient_lstate_t)
};

WW_EXPORT void         trojanclientTunnelDestroy(tunnel_t *t, const ww_lifecycle_context_t *context);
WW_EXPORT tunnel_t    *trojanclientTunnelCreate(node_t *node);
WW_EXPORT api_result_t trojanclientTunnelApi(tunnel_t *instance, sbuf_t *message);

void trojanclientTunnelOnChain(tunnel_t *t, tunnel_chain_t *chain);

void trojanclientTunnelUpStreamInit(tunnel_t *t, line_t *l);
void trojanclientTunnelUpStreamFinish(tunnel_t *t, line_t *l);
void trojanclientTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void trojanclientTunnelUpStreamPause(tunnel_t *t, line_t *l);
void trojanclientTunnelUpStreamResume(tunnel_t *t, line_t *l);

void trojanclientTunnelDownStreamEst(tunnel_t *t, line_t *l);
void trojanclientTunnelDownStreamFinish(tunnel_t *t, line_t *l);
void trojanclientTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void trojanclientTunnelDownStreamPause(tunnel_t *t, line_t *l);
void trojanclientTunnelDownStreamResume(tunnel_t *t, line_t *l);
bool trojanclientDomainResolverPrepare(tunnel_t *resolver, tunnel_t *client, line_t *l,
                                       domainresolver_direction_t direction, void *user_lstate);

void trojanclientLinestateInitialize(trojanclient_lstate_t *ls, line_t *l);
void trojanclientLinestateDestroy(trojanclient_lstate_t *ls);

void trojanclientTunnelstateDestroy(trojanclient_tstate_t *ts);
bool trojanclientApplyTargetContext(tunnel_t *t, line_t *l);
void trojanclientStartUdpCarrier(tunnel_t *t, line_t *l, trojanclient_lstate_t *ls);
void trojanclientOnNextEstablished(tunnel_t *t, line_t *l, trojanclient_lstate_t *ls);
void trojanclientCloseLine(tunnel_t *t, line_t *l, trojanclient_close_origin_t origin);

void trojanclientPump(tunnel_t *t, line_t *next_line);

void trojanclientSetPrevPaused(tunnel_t *t, line_t *l, bool paused);

/* Shared implementation helpers; callbacks retain their directional admission. */
bool    trojanclientSendInitialRequest(tunnel_t *t, line_t *l, trojanclient_lstate_t *ls);
bool    trojanclientWrapUdpPayload(line_t *l, sbuf_t **buf_io, const address_context_t *target);
int     trojanclientReadUdpHeader(trojanclient_lstate_t *ls);
sbuf_t *trojanclientExtractUdpBody(trojanclient_lstate_t *ls);

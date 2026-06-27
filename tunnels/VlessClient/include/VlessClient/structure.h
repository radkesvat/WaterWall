#pragma once

#include "DomainResolver/interface.h"
#include "wwapi.h"

typedef enum vlessclient_protocol_e
{
    kVlessClientProtocolDestContext = 0,
    kVlessClientProtocolTcp         = 1,
    kVlessClientProtocolUdp         = 2
} vlessclient_protocol_t;

typedef enum vlessclient_phase_e
{
    kVlessClientPhaseIdle = 0,
    kVlessClientPhaseWaitResponse,
    kVlessClientPhaseEstablished,
    kVlessClientPhaseClosing
} vlessclient_phase_t;

typedef enum vlessclient_line_kind_e
{
    kVlessClientLineKindDirect = 0,
    kVlessClientLineKindUdpApp,
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
    kVlessClientUuidLen          = 16,
    kVlessClientResponseLen      = 2,
    kVlessClientUdpHeaderLen     = 2,
    kVlessClientUdpMaxPacket     = UINT16_MAX,
    kVlessClientPendingQueueCap  = 8,
    kVlessClientMaxPendingBytes  = 1024 * 1024,
    kVlessClientMaxBufferedBytes = 1024 * 1024
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
    bool                   verbose;
    bool                   resolve_domains;
} vlessclient_tstate_t;

typedef struct vlessclient_domain_resolver_lstate_s
{
    vlessclient_protocol_t protocol;
} vlessclient_domain_resolver_lstate_t;

typedef struct vlessclient_lstate_s
{
    tunnel_t                 *tunnel;
    line_t                   *line;
    line_t                   *app_line;
    line_t                   *carrier_line;
    address_context_t         target_addr;
    buffer_stream_t           in_stream;
    buffer_queue_t            pending_up;
    vlessclient_protocol_t    protocol;
    vlessclient_phase_t       phase;
    vlessclient_line_kind_t   kind;
} vlessclient_lstate_t;

enum
{
    kTunnelStateSize = sizeof(vlessclient_tstate_t),
    kLineStateSize   = sizeof(vlessclient_lstate_t)
};

WW_EXPORT void         vlessclientTunnelDestroy(tunnel_t *t);
WW_EXPORT tunnel_t    *vlessclientTunnelCreate(node_t *node);
WW_EXPORT api_result_t vlessclientTunnelApi(tunnel_t *instance, sbuf_t *message);

void vlessclientTunnelOnChain(tunnel_t *t, tunnel_chain_t *chain);
void vlessclientTunnelOnPrepair(tunnel_t *t);
void vlessclientTunnelOnStart(tunnel_t *t);
void vlessclientTunnelOnStop(tunnel_t *t);

void vlessclientTunnelUpStreamInit(tunnel_t *t, line_t *l);
void vlessclientTunnelUpStreamEst(tunnel_t *t, line_t *l);
void vlessclientTunnelUpStreamFinish(tunnel_t *t, line_t *l);
void vlessclientTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void vlessclientTunnelUpStreamPause(tunnel_t *t, line_t *l);
void vlessclientTunnelUpStreamResume(tunnel_t *t, line_t *l);

void vlessclientTunnelDownStreamInit(tunnel_t *t, line_t *l);
void vlessclientTunnelDownStreamEst(tunnel_t *t, line_t *l);
void vlessclientTunnelDownStreamFinish(tunnel_t *t, line_t *l);
void vlessclientTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void vlessclientTunnelDownStreamPause(tunnel_t *t, line_t *l);
void vlessclientTunnelDownStreamResume(tunnel_t *t, line_t *l);
bool vlessclientDomainResolverPrepare(tunnel_t *resolver, tunnel_t *client, line_t *l,
                                      domainresolver_direction_t direction, void *user_lstate);

void vlessclientLinestateInitialize(vlessclient_lstate_t *ls, tunnel_t *t, line_t *l);
void vlessclientLinestateDestroy(vlessclient_lstate_t *ls);

void vlessclientTunnelstateDestroy(vlessclient_tstate_t *ts);
bool vlessclientApplyTargetContext(tunnel_t *t, line_t *l, vlessclient_protocol_t *protocol_out);
bool vlessclientStartUdpCarrier(tunnel_t *t, line_t *l, vlessclient_lstate_t *ls, bool *line_alive_out);
bool vlessclientForwardUdpAppPayload(tunnel_t *t, line_t *l, vlessclient_lstate_t *ls, sbuf_t *buf);
bool vlessclientHandleUdpCarrierPayload(tunnel_t *t, line_t *l, vlessclient_lstate_t *ls, sbuf_t *buf);
bool vlessclientHandleDirectPayload(tunnel_t *t, line_t *l, vlessclient_lstate_t *ls, sbuf_t *buf);
bool vlessclientOnTransportEstablished(tunnel_t *t, line_t *l, vlessclient_lstate_t *ls);
void vlessclientCloseOwnedLine(tunnel_t *t, line_t *owned_l);
void vlessclientCloseLine(tunnel_t *t, line_t *l, vlessclient_close_origin_t origin);

#pragma once

#include "wwapi.h"

typedef enum trojanclient_protocol_e
{
    kTrojanClientProtocolDestContext = 0,
    kTrojanClientProtocolTcp         = 1,
    kTrojanClientProtocolUdp         = 3
} trojanclient_protocol_t;

typedef enum trojanclient_phase_e
{
    kTrojanClientPhaseIdle = 0,
    kTrojanClientPhaseEstablished,
    kTrojanClientPhaseClosing
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
    kTrojanClientPasswordHexLen   = SHA224_DIGEST_SIZE * 2,
    kTrojanClientCrlfLen          = 2,
    kTrojanClientUdpMaxPacket     = 8192,
    kTrojanClientPendingQueueCap  = 8,
    kTrojanClientMaxPendingBytes  = 1024 * 1024,
    kTrojanClientMaxBufferedBytes = 1024 * 1024,
    kTrojanClientUdpHeaderMaxLen  = 1 + 1 + UINT8_MAX + 2 + 2 + 2
};

typedef struct trojanclient_tstate_s
{
    address_context_t       target_addr;
    uint8_t                 password_hex[kTrojanClientPasswordHexLen];
    uint32_t                target_addr_source;
    uint32_t                target_port_source;
    trojanclient_protocol_t protocol;
    bool                    verbose;
} trojanclient_tstate_t;

typedef struct trojanclient_lstate_s
{
    tunnel_t                *tunnel;
    line_t                  *line;
    line_t                  *app_line;
    line_t                  *carrier_line;
    address_context_t        target_addr;
    buffer_stream_t          in_stream;
    buffer_queue_t           pending_up;
    trojanclient_protocol_t  protocol;
    trojanclient_phase_t     phase;
    trojanclient_line_kind_t kind;
} trojanclient_lstate_t;

enum
{
    kTunnelStateSize = sizeof(trojanclient_tstate_t),
    kLineStateSize   = sizeof(trojanclient_lstate_t)
};

WW_EXPORT void         trojanclientTunnelDestroy(tunnel_t *t);
WW_EXPORT tunnel_t    *trojanclientTunnelCreate(node_t *node);
WW_EXPORT api_result_t trojanclientTunnelApi(tunnel_t *instance, sbuf_t *message);

void trojanclientTunnelOnPrepair(tunnel_t *t);
void trojanclientTunnelOnStart(tunnel_t *t);
void trojanclientTunnelOnStop(tunnel_t *t);

void trojanclientTunnelUpStreamInit(tunnel_t *t, line_t *l);
void trojanclientTunnelUpStreamEst(tunnel_t *t, line_t *l);
void trojanclientTunnelUpStreamFinish(tunnel_t *t, line_t *l);
void trojanclientTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void trojanclientTunnelUpStreamPause(tunnel_t *t, line_t *l);
void trojanclientTunnelUpStreamResume(tunnel_t *t, line_t *l);

void trojanclientTunnelDownStreamInit(tunnel_t *t, line_t *l);
void trojanclientTunnelDownStreamEst(tunnel_t *t, line_t *l);
void trojanclientTunnelDownStreamFinish(tunnel_t *t, line_t *l);
void trojanclientTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void trojanclientTunnelDownStreamPause(tunnel_t *t, line_t *l);
void trojanclientTunnelDownStreamResume(tunnel_t *t, line_t *l);

void trojanclientLinestateInitialize(trojanclient_lstate_t *ls, tunnel_t *t, line_t *l);
void trojanclientLinestateDestroy(trojanclient_lstate_t *ls);

void trojanclientTunnelstateDestroy(trojanclient_tstate_t *ts);
bool trojanclientApplyTargetContext(tunnel_t *t, line_t *l);
bool trojanclientStartUdpCarrier(tunnel_t *t, line_t *l, trojanclient_lstate_t *ls, bool *line_alive_out);
bool trojanclientForwardUdpAppPayload(tunnel_t *t, line_t *l, trojanclient_lstate_t *ls, sbuf_t *buf);
bool trojanclientHandleUdpCarrierPayload(tunnel_t *t, line_t *l, trojanclient_lstate_t *ls, sbuf_t *buf);
bool trojanclientOnTransportEstablished(tunnel_t *t, line_t *l, trojanclient_lstate_t *ls);
void trojanclientCloseOwnedLine(tunnel_t *t, line_t *owned_l);
void trojanclientCloseLine(tunnel_t *t, line_t *l, trojanclient_close_origin_t origin);

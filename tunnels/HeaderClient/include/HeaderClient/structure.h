#pragma once

#include "wwapi.h"

typedef enum headerclient_data_mode_e
{
    kHeaderClientDataModeNone = 0,
    kHeaderClientDataModeConstant,
    kHeaderClientDataModeSourcePort,
    kHeaderClientDataModeProxyProtocolV1,
    kHeaderClientDataModeProxyProtocolV2
} headerclient_data_mode_e;

typedef enum headerclient_phase_e
{
    kHeaderClientPhaseNone = 0,
    kHeaderClientPhaseActive
} headerclient_phase_e;

typedef struct headerclient_tstate_s
{
    headerclient_data_mode_e data_mode;
    uint16_t                 constant_port;
    address_context_t        proxy_frontend_ipv4;
} headerclient_tstate_t;

typedef struct headerclient_lstate_s
{
    headerclient_phase_e phase;
    bool                 header_sent;
} headerclient_lstate_t;

enum
{
    kHeaderClientPortHeaderSize                 = 2,
    kHeaderClientProxyProtocolV1MaxHeaderSize   = 108,
    kHeaderClientProxyProtocolV2BaseHeaderSize  = 16,
    kHeaderClientProxyProtocolV2Ipv4AddressSize = 12,
    kHeaderClientMaxHeaderSize                  = kHeaderClientProxyProtocolV1MaxHeaderSize,
    kTunnelStateSize                            = sizeof(headerclient_tstate_t),
    kLineStateSize                              = sizeof(headerclient_lstate_t)
};

WW_EXPORT void         headerclientTunnelDestroy(tunnel_t *t);
WW_EXPORT tunnel_t    *headerclientTunnelCreate(node_t *node);
WW_EXPORT api_result_t headerclientTunnelApi(tunnel_t *instance, sbuf_t *message);

void headerclientTunnelOnPrepair(tunnel_t *t);
void headerclientTunnelOnStart(tunnel_t *t);
void headerclientTunnelOnStop(tunnel_t *t);

void headerclientTunnelUpStreamInit(tunnel_t *t, line_t *l);
void headerclientTunnelUpStreamEst(tunnel_t *t, line_t *l);
void headerclientTunnelUpStreamFinish(tunnel_t *t, line_t *l);
void headerclientTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void headerclientTunnelUpStreamPause(tunnel_t *t, line_t *l);
void headerclientTunnelUpStreamResume(tunnel_t *t, line_t *l);

void headerclientTunnelDownStreamInit(tunnel_t *t, line_t *l);
void headerclientTunnelDownStreamEst(tunnel_t *t, line_t *l);
void headerclientTunnelDownStreamFinish(tunnel_t *t, line_t *l);
void headerclientTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void headerclientTunnelDownStreamPause(tunnel_t *t, line_t *l);
void headerclientTunnelDownStreamResume(tunnel_t *t, line_t *l);

bool headerclientLoadSettings(headerclient_tstate_t *ts, const cJSON *settings);
void headerclientLinestateInitialize(headerclient_lstate_t *ls);
void headerclientLinestateDestroy(headerclient_lstate_t *ls);

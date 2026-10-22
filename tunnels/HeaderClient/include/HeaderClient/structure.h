#pragma once

#include "wwapi.h"

typedef enum headerclient_data_mode_e
{
    kHeaderClientDataModeNone = 0,
    kHeaderClientDataModeConstant,
    kHeaderClientDataModeSourcePort,
    kHeaderClientDataModeProxyProtocolV1,
    kHeaderClientDataModeProxyProtocolV2,
    kHeaderClientDataModeSourceProtocol,
    kHeaderClientDataModeDestinationProtocol
} headerclient_data_mode_e;

typedef struct headerclient_tstate_s
{
    headerclient_data_mode_e data_mode;
    uint16_t                 constant_port;
    address_context_t        proxy_frontend_ipv4;
} headerclient_tstate_t;

typedef struct headerclient_lstate_s
{
    uint8_t protocol;
} headerclient_lstate_t;

enum
{
    kHeaderClientPortHeaderSize                 = 2,
    kHeaderClientProtocolHeaderSize             = 1,
    kHeaderClientProxyProtocolV1MaxHeaderSize   = 108,
    kHeaderClientProxyProtocolV2BaseHeaderSize  = 16,
    kHeaderClientProxyProtocolV2Ipv4AddressSize = 12,
    kHeaderClientMaxHeaderSize                  = kHeaderClientProxyProtocolV1MaxHeaderSize,
    kTunnelStateSize                            = sizeof(headerclient_tstate_t),
    kLineStateSize                              = sizeof(headerclient_lstate_t)
};

WW_EXPORT tunnel_t    *headerclientTunnelCreate(node_t *node);
WW_EXPORT api_result_t headerclientTunnelApi(tunnel_t *instance, sbuf_t *message);

void headerclientTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void headerclientTunnelUpStreamInit(tunnel_t *t, line_t *l);
void headerclientTunnelUpStreamFinish(tunnel_t *t, line_t *l);
void headerclientTunnelDownStreamFinish(tunnel_t *t, line_t *l);

void headerclientLinestateDestroy(headerclient_lstate_t *ls);

bool headerclientLoadSettings(headerclient_tstate_t *ts, const cJSON *settings);

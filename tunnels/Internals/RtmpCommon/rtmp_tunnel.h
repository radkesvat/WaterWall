#pragma once

#include "wwapi.h"

#include "rtmp_session.h"

typedef enum
{
    kRtmpClientRole,
    kRtmpServerRole,
} rtmp_role_t;

typedef enum
{
    kRtmpOpen,
    kRtmpCloseLocal,
    kRtmpCloseFromPrev,
    kRtmpCloseFromNext,
} rtmp_close_origin_t;

typedef struct
{
    char     app[RTMP_SESSION_APP_MAX + 1];
    char     stream[RTMP_SESSION_STREAM_MAX + 1];
    char     tc_url[RTMP_SESSION_URL_MAX + 1];
    uint32_t block_size;
    uint32_t setup_timeout_ms;
    uint32_t send_timeout_ms;
} rtmp_settings_t;

typedef struct
{
    TunnelFlowRoutinePayload wire_payload;
    TunnelFlowRoutinePayload application_payload;
    void (*carrier_pressure)(tunnel_t *t, line_t *l, bool paused);
    void (*application_pressure)(tunnel_t *t, line_t *l, bool paused);
} rtmp_output_t;

bool rtmpValidateSettingsObject(const node_t *node);
bool rtmpReadCommonSettings(node_t *node, rtmp_settings_t *settings);
bool rtmpReadString(const cJSON *settings, const char *key, const char *fallback, char *target, size_t capacity,
                    const char *role);

tunnel_t *rtmpTunnelCreate(node_t *node, const rtmp_settings_t *settings, rtmp_role_t role,
                           const rtmp_output_t *output);

/* Both nodes borrow the line. A failed Init has already closed its admitted sides. */
bool rtmpInitLine(tunnel_t *t, line_t *l);
void rtmpStartCarrier(tunnel_t *t, line_t *l);
void rtmpNextEstablished(tunnel_t *t, line_t *l);

/* Submission transfers the buffer. Pressure is named for the side issuing the signal. */
void rtmpSubmitApplication(tunnel_t *t, line_t *l, sbuf_t *buf);
void rtmpSubmitCarrier(tunnel_t *t, line_t *l, sbuf_t *buf);
void rtmpSetApplicationPaused(tunnel_t *t, line_t *l, bool paused);
void rtmpSetCarrierPaused(tunnel_t *t, line_t *l, bool paused);
void rtmpApplicationFinish(tunnel_t *t, line_t *l, rtmp_close_origin_t origin);
void rtmpCarrierFinish(tunnel_t *t, line_t *l, rtmp_close_origin_t origin);

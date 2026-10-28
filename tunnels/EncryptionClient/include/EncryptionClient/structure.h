#pragma once

#include "EncryptionCommon/record.h"

typedef struct encryptionclient_tstate_s
{
    uint32_t algorithm;
    uint32_t kdf_iterations;
    uint32_t max_frame_payload;
    uint8_t  key[32];
} encryptionclient_tstate_t;

typedef struct encryptionclient_lstate_s
{
    buffer_stream_t read_stream;
} encryptionclient_lstate_t;

enum
{
    kTunnelStateSize = sizeof(encryptionclient_tstate_t),
    kLineStateSize   = sizeof(encryptionclient_lstate_t),
};

WW_EXPORT void         encryptionclientTunnelDestroy(tunnel_t *t, const ww_lifecycle_context_t *context);
WW_EXPORT tunnel_t    *encryptionclientTunnelCreate(node_t *node);
WW_EXPORT api_result_t encryptionclientTunnelApi(tunnel_t *instance, sbuf_t *message);

void encryptionclientTunnelUpStreamInit(tunnel_t *t, line_t *l);
void encryptionclientTunnelUpStreamFinish(tunnel_t *t, line_t *l);
void encryptionclientTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);

void encryptionclientTunnelDownStreamFinish(tunnel_t *t, line_t *l);
void encryptionclientTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);

void encryptionclientLinestateInitialize(encryptionclient_lstate_t *ls, buffer_pool_t *pool);
void encryptionclientLinestateDestroy(encryptionclient_lstate_t *ls);

void encryptionclientTunnelstateDestroy(encryptionclient_tstate_t *ts);

void encryptionclientCloseLineBidirectional(tunnel_t *t, line_t *l);

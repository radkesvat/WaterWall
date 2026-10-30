#pragma once

#include "EncryptionCommon/record.h"

typedef struct encryptionserver_tstate_s
{
    uint32_t algorithm;
    uint32_t kdf_iterations;
    uint32_t max_frame_payload;
    uint8_t  key[32];
} encryptionserver_tstate_t;

typedef struct encryptionserver_lstate_s
{
    buffer_stream_t read_stream;
} encryptionserver_lstate_t;

enum
{
    kTunnelStateSize = sizeof(encryptionserver_tstate_t),
    kLineStateSize   = sizeof(encryptionserver_lstate_t),
};

WW_EXPORT void         encryptionserverTunnelDestroy(tunnel_t *t, const ww_lifecycle_context_t *context);
WW_EXPORT tunnel_t    *encryptionserverTunnelCreate(node_t *node);
WW_EXPORT api_result_t encryptionserverTunnelApi(tunnel_t *instance, sbuf_t *message);

void encryptionserverTunnelUpStreamInit(tunnel_t *t, line_t *l);
void encryptionserverTunnelUpStreamFinish(tunnel_t *t, line_t *l);
void encryptionserverTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);

void encryptionserverTunnelDownStreamFinish(tunnel_t *t, line_t *l);
void encryptionserverTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);

void encryptionserverLinestateInitialize(encryptionserver_lstate_t *ls, buffer_pool_t *pool);
void encryptionserverLinestateDestroy(encryptionserver_lstate_t *ls);

void encryptionserverTunnelstateDestroy(encryptionserver_tstate_t *ts);

void encryptionserverCloseLineBidirectional(tunnel_t *t, line_t *l);

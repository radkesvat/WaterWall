#pragma once

#include "wwapi.h"

#include "ObfuscatorCommon/codec.h"

typedef struct obfuscatorserver_tstate_s
{
    uint32_t skip; // Headers that remain unobfuscated inside packet payloads

    uint8_t xor_key; // Key for XOR obfuscation, if used
    bool    tls_record_header;
} obfuscatorserver_tstate_t;

typedef struct obfuscatorserver_lstate_s
{
    buffer_stream_t read_stream;
    bool            initialized_from_downstream;
} obfuscatorserver_lstate_t;

enum
{
    kTunnelStateSize = sizeof(obfuscatorserver_tstate_t),
    kLineStateSize   = sizeof(obfuscatorserver_lstate_t)
};

WW_EXPORT tunnel_t    *obfuscatorserverTunnelCreate(node_t *node);
WW_EXPORT api_result_t obfuscatorserverTunnelApi(tunnel_t *instance, sbuf_t *message);

void obfuscatorserverTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);

void obfuscatorserverTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);

void obfuscatorserverLinestateInitialize(obfuscatorserver_lstate_t *ls, line_t *l, bool from_downstream);
void obfuscatorserverLinestateDestroy(obfuscatorserver_lstate_t *ls);

void obfuscatorserverTunnelUpStreamInit(tunnel_t *t, line_t *l);
void obfuscatorserverTunnelDownStreamInit(tunnel_t *t, line_t *l);
void obfuscatorserverTunnelUpStreamFinish(tunnel_t *t, line_t *l);
void obfuscatorserverTunnelDownStreamFinish(tunnel_t *t, line_t *l);
void obfuscatorserverEncodeStream(tunnel_t *t, line_t *l, sbuf_t *buf);
void obfuscatorserverDecodeStream(tunnel_t *t, line_t *l, sbuf_t *buf);

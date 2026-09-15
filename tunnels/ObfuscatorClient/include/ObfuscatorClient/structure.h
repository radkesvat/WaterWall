#pragma once

#include "wwapi.h"

enum obfuscator_methods_e
{
    kObfuscatorMethodXor = kDvsFirstOption,
};

enum obfuscator_skip_parts_e
{
    kObfuscatorSkipNone = kDvsFirstOption,
    kObfuscatorSkipIpv4,
    kObfuscatorSkipTransport
};

typedef struct obfuscatorclient_tstate_s
{
    uint32_t method; // Obfuscation method
    uint32_t skip;   // Headers that remain unobfuscated inside packet payloads

    uint8_t xor_key; // Key for XOR obfuscation, if used
    bool    tls_record_header;
} obfuscatorclient_tstate_t;

typedef struct obfuscatorclient_lstate_s
{
    buffer_stream_t read_stream;
    bool            paused;
} obfuscatorclient_lstate_t;

enum
{
    kTunnelStateSize               = sizeof(obfuscatorclient_tstate_t),
    kLineStateSize                 = sizeof(obfuscatorclient_lstate_t),
    kObfuscatorTlsRecordHeaderSize = 5
};

WW_EXPORT tunnel_t    *obfuscatorclientTunnelCreate(node_t *node);
WW_EXPORT api_result_t obfuscatorclientTunnelApi(tunnel_t *instance, sbuf_t *message);

void obfuscatorclientTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);

void obfuscatorclientTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);

void obfuscatorclientLinestateInitialize(obfuscatorclient_lstate_t *ls, line_t *l);
void obfuscatorclientLinestateDestroy(obfuscatorclient_lstate_t *ls);

void obfuscatorclientXorByte(uint8_t *data, size_t size, uint8_t key);
void obfuscatorclientApplyXor(tunnel_t *t, line_t *l, sbuf_t *buf);
bool obfuscatorclientWrapTlsRecordHeader(line_t *l, sbuf_t **buf_io);
bool obfuscatorclientStripTlsRecordHeader(line_t *l, sbuf_t *buf);

void obfuscatorclientTunnelUpStreamInit(tunnel_t *t, line_t *l);
void obfuscatorclientTunnelDownStreamInit(tunnel_t *t, line_t *l);
void obfuscatorclientTunnelUpStreamFinish(tunnel_t *t, line_t *l);
void obfuscatorclientTunnelDownStreamFinish(tunnel_t *t, line_t *l);
void obfuscatorclientTunnelUpStreamPause(tunnel_t *t, line_t *l);
void obfuscatorclientTunnelUpStreamResume(tunnel_t *t, line_t *l);
void obfuscatorclientEncodeStream(tunnel_t *t, line_t *l, sbuf_t *buf);
void obfuscatorclientDecodeStream(tunnel_t *t, line_t *l, sbuf_t *buf);
void obfuscatorclientDrainStream(tunnel_t *t, line_t *l);

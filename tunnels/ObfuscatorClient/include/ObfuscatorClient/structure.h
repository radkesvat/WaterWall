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
    int unused;
} obfuscatorclient_lstate_t;

enum
{
    kTunnelStateSize               = sizeof(obfuscatorclient_tstate_t),
    kLineStateSize                 = 0,
    kObfuscatorTlsRecordHeaderSize = 5
};

WW_EXPORT tunnel_t    *obfuscatorclientTunnelCreate(node_t *node);
WW_EXPORT api_result_t obfuscatorclientTunnelApi(tunnel_t *instance, sbuf_t *message);

void obfuscatorclientTunnelOnIndex(tunnel_t *t, uint16_t index, uint32_t *mem_offset);
void obfuscatorclientTunnelOnChain(tunnel_t *t, tunnel_chain_t *chain);

void obfuscatorclientTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);

void obfuscatorclientTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);

void obfuscatorclientLinestateInitialize(obfuscatorclient_lstate_t *ls);
void obfuscatorclientLinestateDestroy(obfuscatorclient_lstate_t *ls);

void obfuscatorclientXorByte(uint8_t *data, size_t size, uint8_t key);
void obfuscatorclientApplyXor(tunnel_t *t, line_t *l, sbuf_t *buf);
bool obfuscatorclientWrapTlsRecordHeader(line_t *l, sbuf_t **buf_io);
bool obfuscatorclientStripTlsRecordHeader(line_t *l, sbuf_t *buf);

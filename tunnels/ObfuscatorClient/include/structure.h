#pragma once

#include "wwapi.h"

enum obfuscator_methods_e
{
    kObfuscatorMethodXor  = kDvsFirstOption,

};

typedef struct obfuscatorclient_tstate_s
{
    uint32_t method; // Obfuscation method

    uint8_t  xor_key; // Key for XOR obfuscation, if used
} obfuscatorclient_tstate_t;

typedef struct obfuscatorclient_lstate_s
{
    int unused;
} obfuscatorclient_lstate_t;

enum
{
    kTunnelStateSize = sizeof(obfuscatorclient_tstate_t),
    kLineStateSize   = sizeof(obfuscatorclient_lstate_t)
};

WW_EXPORT void         obfuscatorclientTunnelDestroy(tunnel_t *t);
WW_EXPORT tunnel_t    *obfuscatorclientTunnelCreate(node_t *node);
WW_EXPORT api_result_t obfuscatorclientTunnelApi(tunnel_t *instance, sbuf_t *message);

void obfuscatorclientTunnelOnIndex(tunnel_t *t, uint16_t index, uint16_t *mem_offset);
void obfuscatorclientTunnelOnChain(tunnel_t *t, tunnel_chain_t *chain);
void obfuscatorclientTunnelOnPrepair(tunnel_t *t);
void obfuscatorclientTunnelOnStart(tunnel_t *t);

void obfuscatorclientTunnelUpStreamInit(tunnel_t *t, line_t *l);
void obfuscatorclientTunnelUpStreamEst(tunnel_t *t, line_t *l);
void obfuscatorclientTunnelUpStreamFinish(tunnel_t *t, line_t *l);
void obfuscatorclientTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void obfuscatorclientTunnelUpStreamPause(tunnel_t *t, line_t *l);
void obfuscatorclientTunnelUpStreamResume(tunnel_t *t, line_t *l);

void obfuscatorclientTunnelDownStreamInit(tunnel_t *t, line_t *l);
void obfuscatorclientTunnelDownStreamEst(tunnel_t *t, line_t *l);
void obfuscatorclientTunnelDownStreamFinish(tunnel_t *t, line_t *l);
void obfuscatorclientTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void obfuscatorclientTunnelDownStreamPause(tunnel_t *t, line_t *l);
void obfuscatorclientTunnelDownStreamResume(tunnel_t *t, line_t *l);

void obfuscatorclientLinestateInitialize(obfuscatorclient_lstate_t *ls);
void obfuscatorclientLinestateDestroy(obfuscatorclient_lstate_t *ls);

void obfuscatorclientXorByte(uint8_t *data, size_t size, uint8_t key);

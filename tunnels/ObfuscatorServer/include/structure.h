#pragma once

#include "wwapi.h"

enum obfuscator_methods_e
{
    kObfuscatorMethodXor  = kDvsFifthOption,

};

typedef struct obfuscatorserver_tstate_s
{
    uint32_t method; // Obfuscation method

    uint8_t  xor_key; // Key for XOR obfuscation, if used
} obfuscatorserver_tstate_t;

typedef struct obfuscatorserver_lstate_s
{
    int unused;
} obfuscatorserver_lstate_t;

enum
{
    kTunnelStateSize = sizeof(obfuscatorserver_tstate_t),
    kLineStateSize   = sizeof(obfuscatorserver_lstate_t)
};

WW_EXPORT void         obfuscatorserverTunnelDestroy(tunnel_t *t);
WW_EXPORT tunnel_t    *obfuscatorserverTunnelCreate(node_t *node);
WW_EXPORT api_result_t obfuscatorserverTunnelApi(tunnel_t *instance, sbuf_t *message);

void obfuscatorserverTunnelOnIndex(tunnel_t *t, uint16_t index, uint16_t *mem_offset);
void obfuscatorserverTunnelOnChain(tunnel_t *t, tunnel_chain_t *chain);
void obfuscatorserverTunnelOnPrepair(tunnel_t *t);
void obfuscatorserverTunnelOnStart(tunnel_t *t);

void obfuscatorserverTunnelUpStreamInit(tunnel_t *t, line_t *l);
void obfuscatorserverTunnelUpStreamEst(tunnel_t *t, line_t *l);
void obfuscatorserverTunnelUpStreamFinish(tunnel_t *t, line_t *l);
void obfuscatorserverTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void obfuscatorserverTunnelUpStreamPause(tunnel_t *t, line_t *l);
void obfuscatorserverTunnelUpStreamResume(tunnel_t *t, line_t *l);

void obfuscatorserverTunnelDownStreamInit(tunnel_t *t, line_t *l);
void obfuscatorserverTunnelDownStreamEst(tunnel_t *t, line_t *l);
void obfuscatorserverTunnelDownStreamFinish(tunnel_t *t, line_t *l);
void obfuscatorserverTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void obfuscatorserverTunnelDownStreamPause(tunnel_t *t, line_t *l);
void obfuscatorserverTunnelDownStreamResume(tunnel_t *t, line_t *l);

void obfuscatorserverLinestateInitialize(obfuscatorserver_lstate_t *ls);
void obfuscatorserverLinestateDestroy(obfuscatorserver_lstate_t *ls);

void obfuscatorserverXorByte(uint8_t *data, size_t size, uint8_t key);

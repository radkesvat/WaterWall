#pragma once

#include "wwapi.h"

typedef struct realityclient_tstate_s
{
    uint32_t algorithm;
    uint32_t kdf_iterations;
    uint32_t max_frame_payload;
    uint8_t  key[32];

    node_t    tls_node;
    cJSON    *tls_settings;
    tunnel_t *tls_tunnel;
} realityclient_tstate_t;

typedef struct realityclient_lstate_s
{
    buffer_stream_t read_stream;
    buffer_queue_t  pending_up;
    bool            tls_ready;
} realityclient_lstate_t;

enum realityclient_algorithm_e
{
    kRealityClientAlgorithmChaCha20Poly1305 = kDvsFirstOption,
    kRealityClientAlgorithmAes256Gcm        = kDvsSecondOption,
};

enum realityclient_frame_e
{
    kRealityClientTlsHeaderSize        = 5,
    kRealityClientTlsApplicationData   = 0x17,
    kRealityClientTlsVersionMajor      = 0x03,
    kRealityClientTlsVersionMinor      = 0x03,
    kRealityClientNonceSize            = 12,
    kRealityClientTagSize              = 16,
    kRealityClientFramePrefixSize      = kRealityClientTlsHeaderSize + kRealityClientNonceSize,
    kRealityClientMaxTlsRecordBody     = 16384,
    kRealityClientMaxFramePayload      = kRealityClientMaxTlsRecordBody - kRealityClientNonceSize - kRealityClientTagSize,
    kRealityClientDefaultKdfIterations = 12000,
};

enum
{
    kTunnelStateSize = sizeof(realityclient_tstate_t),
    kLineStateSize   = sizeof(realityclient_lstate_t)
};

WW_EXPORT void         realityclientTunnelDestroy(tunnel_t *t);
WW_EXPORT tunnel_t    *realityclientTunnelCreate(node_t *node);
WW_EXPORT api_result_t realityclientTunnelApi(tunnel_t *instance, sbuf_t *message);

void realityclientTunnelOnIndex(tunnel_t *t, uint16_t index, uint16_t *mem_offset);
void realityclientTunnelOnChain(tunnel_t *t, tunnel_chain_t *chain);
void realityclientTunnelOnPrepair(tunnel_t *t);
void realityclientTunnelOnStart(tunnel_t *t);

void realityclientTunnelUpStreamInit(tunnel_t *t, line_t *l);
void realityclientTunnelUpStreamEst(tunnel_t *t, line_t *l);
void realityclientTunnelUpStreamFinish(tunnel_t *t, line_t *l);
void realityclientTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void realityclientTunnelUpStreamPause(tunnel_t *t, line_t *l);
void realityclientTunnelUpStreamResume(tunnel_t *t, line_t *l);

void realityclientTunnelDownStreamInit(tunnel_t *t, line_t *l);
void realityclientTunnelDownStreamEst(tunnel_t *t, line_t *l);
void realityclientTunnelDownStreamFinish(tunnel_t *t, line_t *l);
void realityclientTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void realityclientTunnelDownStreamPause(tunnel_t *t, line_t *l);
void realityclientTunnelDownStreamResume(tunnel_t *t, line_t *l);

void realityclientLinestateInitialize(realityclient_lstate_t *ls, buffer_pool_t *pool);
void realityclientLinestateDestroy(realityclient_lstate_t *ls);
void realityclientTunnelstateDestroy(realityclient_tstate_t *ts);

int  realityclientEncryptAead(uint32_t algorithm, unsigned char *dst, const unsigned char *src, size_t src_len,
                              const unsigned char *ad, size_t ad_len, const unsigned char *nonce,
                              const unsigned char *key);
int  realityclientDecryptAead(uint32_t algorithm, unsigned char *dst, const unsigned char *src, size_t src_len,
                              const unsigned char *ad, size_t ad_len, const unsigned char *nonce,
                              const unsigned char *key);
bool realityclientEncryptAndSend(tunnel_t *t, line_t *l, sbuf_t *buf);
bool realityclientProcessDownstream(tunnel_t *t, line_t *l, sbuf_t *buf);
void realityclientCloseLineBidirectional(tunnel_t *t, line_t *l);

node_t    nodeTlsClientGet(void);
tunnel_t *tlsclientTunnelCreate(node_t *node);
void      tlsclientTunnelEnableHandshakeTakeover(tunnel_t *t);
bool      tlsclientTunnelIsHandshakeCompleted(tunnel_t *t, line_t *l);
bool      tlsclientTunnelDeinitAfterHandshake(tunnel_t *t, line_t *l, sbuf_t **pending_raw);

#pragma once

#include "wwapi.h"

enum encryptionclient_algorithm_e
{
    kEncryptionAlgorithmChaCha20Poly1305 = kDvsFirstOption,
    kEncryptionAlgorithmAes256Gcm        = kDvsSecondOption,
};

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
    kTunnelStateSize                  = sizeof(encryptionclient_tstate_t),
    kLineStateSize                    = sizeof(encryptionclient_lstate_t),
    kEncryptionTlsHeaderSize          = 5,
    kEncryptionTlsApplicationData     = 0x17,
    kEncryptionTlsVersionMajor        = 0x03,
    kEncryptionTlsVersionMinor        = 0x03,
    kEncryptionNonceSize              = 12, // RFC 8439 and AES-GCM IETF nonce size
    kEncryptionTagSize                = 16,
    kEncryptionFramePrefixSize        = kEncryptionTlsHeaderSize + kEncryptionNonceSize,
    kEncryptionMaxTlsRecordBody       = 16384,
    kEncryptionMaxFramePayload        = kEncryptionMaxTlsRecordBody - kEncryptionNonceSize - kEncryptionTagSize,
    kEncryptionDefaultKdfIterations   = 12000,
    kEncryptionDefaultMaxFramePayload = kEncryptionMaxFramePayload,
    kEncryptionHardMaxFramePayload    = kEncryptionMaxFramePayload,
};

WW_EXPORT void         encryptionclientTunnelDestroy(tunnel_t *t);
WW_EXPORT tunnel_t    *encryptionclientTunnelCreate(node_t *node);
WW_EXPORT api_result_t encryptionclientTunnelApi(tunnel_t *instance, sbuf_t *message);

void encryptionclientTunnelOnIndex(tunnel_t *t, uint16_t index, uint16_t *mem_offset);
void encryptionclientTunnelOnChain(tunnel_t *t, tunnel_chain_t *chain);
void encryptionclientTunnelOnPrepair(tunnel_t *t);
void encryptionclientTunnelOnStart(tunnel_t *t);
void encryptionclientTunnelOnStop(tunnel_t *t);

void encryptionclientTunnelUpStreamInit(tunnel_t *t, line_t *l);
void encryptionclientTunnelUpStreamEst(tunnel_t *t, line_t *l);
void encryptionclientTunnelUpStreamFinish(tunnel_t *t, line_t *l);
void encryptionclientTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void encryptionclientTunnelUpStreamPause(tunnel_t *t, line_t *l);
void encryptionclientTunnelUpStreamResume(tunnel_t *t, line_t *l);

void encryptionclientTunnelDownStreamInit(tunnel_t *t, line_t *l);
void encryptionclientTunnelDownStreamEst(tunnel_t *t, line_t *l);
void encryptionclientTunnelDownStreamFinish(tunnel_t *t, line_t *l);
void encryptionclientTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void encryptionclientTunnelDownStreamPause(tunnel_t *t, line_t *l);
void encryptionclientTunnelDownStreamResume(tunnel_t *t, line_t *l);

void encryptionclientLinestateInitialize(encryptionclient_lstate_t *ls, buffer_pool_t *pool);
void encryptionclientLinestateDestroy(encryptionclient_lstate_t *ls);

void encryptionclientTunnelstateDestroy(encryptionclient_tstate_t *ts);

int encryptionclientEncryptAead(uint32_t algorithm, unsigned char *dst, const unsigned char *src, size_t src_len,
                                const unsigned char *ad, size_t ad_len, const unsigned char *nonce,
                                const unsigned char *key);
int encryptionclientDecryptAead(uint32_t algorithm, unsigned char *dst, const unsigned char *src, size_t src_len,
                                const unsigned char *ad, size_t ad_len, const unsigned char *nonce,
                                const unsigned char *key);

void encryptionclientCloseLineBidirectional(tunnel_t *t, line_t *l);

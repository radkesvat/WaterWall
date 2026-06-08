#pragma once

#include "wwapi.h"

enum encryptionserver_algorithm_e
{
    kEncryptionAlgorithmChaCha20Poly1305 = kDvsFirstOption,
    kEncryptionAlgorithmAes256Gcm        = kDvsSecondOption,
};

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
    kTunnelStateSize                  = sizeof(encryptionserver_tstate_t),
    kLineStateSize                    = sizeof(encryptionserver_lstate_t),
    kEncryptionTlsHeaderSize          = 5,
    kEncryptionTlsApplicationData     = 0x17,
    kEncryptionTlsVersionMajor        = 0x03,
    kEncryptionTlsVersionMinor        = 0x03,
    kEncryptionNonceSize              = 12,
    kEncryptionTagSize                = 16,
    kEncryptionFramePrefixSize        = kEncryptionTlsHeaderSize + kEncryptionNonceSize,
    kEncryptionMaxTlsRecordBody       = 16384,
    kEncryptionMaxFramePayload        = kEncryptionMaxTlsRecordBody - kEncryptionNonceSize - kEncryptionTagSize,
    kEncryptionDefaultKdfIterations   = 12000,
    kEncryptionDefaultMaxFramePayload = kEncryptionMaxFramePayload,
    kEncryptionHardMaxFramePayload    = kEncryptionMaxFramePayload,
};

WW_EXPORT void         encryptionserverTunnelDestroy(tunnel_t *t);
WW_EXPORT tunnel_t    *encryptionserverTunnelCreate(node_t *node);
WW_EXPORT api_result_t encryptionserverTunnelApi(tunnel_t *instance, sbuf_t *message);

void encryptionserverTunnelOnIndex(tunnel_t *t, uint16_t index, uint16_t *mem_offset);
void encryptionserverTunnelOnChain(tunnel_t *t, tunnel_chain_t *chain);
void encryptionserverTunnelOnPrepair(tunnel_t *t);
void encryptionserverTunnelOnStart(tunnel_t *t);
void encryptionserverTunnelOnStop(tunnel_t *t);

void encryptionserverTunnelUpStreamInit(tunnel_t *t, line_t *l);
void encryptionserverTunnelUpStreamEst(tunnel_t *t, line_t *l);
void encryptionserverTunnelUpStreamFinish(tunnel_t *t, line_t *l);
void encryptionserverTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void encryptionserverTunnelUpStreamPause(tunnel_t *t, line_t *l);
void encryptionserverTunnelUpStreamResume(tunnel_t *t, line_t *l);

void encryptionserverTunnelDownStreamInit(tunnel_t *t, line_t *l);
void encryptionserverTunnelDownStreamEst(tunnel_t *t, line_t *l);
void encryptionserverTunnelDownStreamFinish(tunnel_t *t, line_t *l);
void encryptionserverTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void encryptionserverTunnelDownStreamPause(tunnel_t *t, line_t *l);
void encryptionserverTunnelDownStreamResume(tunnel_t *t, line_t *l);

void encryptionserverLinestateInitialize(encryptionserver_lstate_t *ls, buffer_pool_t *pool);
void encryptionserverLinestateDestroy(encryptionserver_lstate_t *ls);

void encryptionserverTunnelstateDestroy(encryptionserver_tstate_t *ts);

int encryptionserverEncryptAead(uint32_t algorithm, unsigned char *dst, const unsigned char *src, size_t src_len,
                                const unsigned char *ad, size_t ad_len, const unsigned char *nonce,
                                const unsigned char *key);
int encryptionserverDecryptAead(uint32_t algorithm, unsigned char *dst, const unsigned char *src, size_t src_len,
                                const unsigned char *ad, size_t ad_len, const unsigned char *nonce,
                                const unsigned char *key);

void encryptionserverCloseLineBidirectional(tunnel_t *t, line_t *l);

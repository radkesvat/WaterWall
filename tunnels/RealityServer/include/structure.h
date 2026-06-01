#pragma once

#include "wwapi.h"

enum realityserver_mode_e
{
    kRealityServerModePending,
    kRealityServerModeAuthorized,
    kRealityServerModeVisitor,
};

enum realityserver_algorithm_e
{
    kRealityServerAlgorithmChaCha20Poly1305 = kDvsFirstOption,
    kRealityServerAlgorithmAes256Gcm        = kDvsSecondOption,
};

typedef struct realityserver_tstate_s
{
    uint32_t algorithm;
    uint32_t kdf_iterations;
    uint32_t max_frame_payload;
    uint32_t sniffing_attempts;
    uint8_t  key[32];

    node_t   *destination_node;
    tunnel_t *destination_tunnel;
} realityserver_tstate_t;

typedef struct realityserver_lstate_s
{
    buffer_stream_t read_stream;
    uint32_t        sniffing_attempts;
    uint8_t         mode;
    bool            protected_init_sent;
    bool            destination_init_sent;
    bool            destination_up_finished;
    bool            closing_destination_for_authorized;
    bool            prev_est_sent;
} realityserver_lstate_t;

enum realityserver_frame_e
{
    kRealityServerTlsHeaderSize        = 5,
    kRealityServerTlsApplicationData   = 0x17,
    kRealityServerTlsVersionMajor      = 0x03,
    kRealityServerTlsVersionMinor      = 0x03,
    kRealityServerNonceSize            = 12,
    kRealityServerTagSize              = 16,
    kRealityServerFramePrefixSize      = kRealityServerTlsHeaderSize + kRealityServerNonceSize,
    kRealityServerMaxTlsRecordBody     = 16384,
    kRealityServerMaxFramePayload      = kRealityServerMaxTlsRecordBody - kRealityServerNonceSize - kRealityServerTagSize,
    kRealityServerDefaultKdfIterations = 12000,
    kRealityServerDefaultSniffingAttempts = 8,
};

enum
{
    kTunnelStateSize = sizeof(realityserver_tstate_t),
    kLineStateSize   = sizeof(realityserver_lstate_t)
};

WW_EXPORT void         realityserverTunnelDestroy(tunnel_t *t);
WW_EXPORT tunnel_t    *realityserverTunnelCreate(node_t *node);
WW_EXPORT api_result_t realityserverTunnelApi(tunnel_t *instance, sbuf_t *message);

void realityserverTunnelOnIndex(tunnel_t *t, uint16_t index, uint16_t *mem_offset);
void realityserverTunnelOnChain(tunnel_t *t, tunnel_chain_t *chain);
void realityserverTunnelOnPrepair(tunnel_t *t);
void realityserverTunnelOnStart(tunnel_t *t);

void realityserverTunnelUpStreamInit(tunnel_t *t, line_t *l);
void realityserverTunnelUpStreamEst(tunnel_t *t, line_t *l);
void realityserverTunnelUpStreamFinish(tunnel_t *t, line_t *l);
void realityserverTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void realityserverTunnelUpStreamPause(tunnel_t *t, line_t *l);
void realityserverTunnelUpStreamResume(tunnel_t *t, line_t *l);

void realityserverTunnelDownStreamInit(tunnel_t *t, line_t *l);
void realityserverTunnelDownStreamEst(tunnel_t *t, line_t *l);
void realityserverTunnelDownStreamFinish(tunnel_t *t, line_t *l);
void realityserverTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void realityserverTunnelDownStreamPause(tunnel_t *t, line_t *l);
void realityserverTunnelDownStreamResume(tunnel_t *t, line_t *l);

void realityserverLinestateInitialize(realityserver_lstate_t *ls, buffer_pool_t *pool);
void realityserverLinestateDestroy(realityserver_lstate_t *ls);
void realityserverTunnelstateDestroy(realityserver_tstate_t *ts);

int  realityserverEncryptAead(uint32_t algorithm, unsigned char *dst, const unsigned char *src, size_t src_len,
                              const unsigned char *ad, size_t ad_len, const unsigned char *nonce,
                              const unsigned char *key);
int  realityserverDecryptAead(uint32_t algorithm, unsigned char *dst, const unsigned char *src, size_t src_len,
                              const unsigned char *ad, size_t ad_len, const unsigned char *nonce,
                              const unsigned char *key);
bool realityserverEncryptAndSendDownstream(tunnel_t *t, line_t *l, sbuf_t *buf);
bool realityserverProcessUpstream(tunnel_t *t, line_t *l, sbuf_t *buf);
void realityserverCloseLineBidirectional(tunnel_t *t, line_t *l);

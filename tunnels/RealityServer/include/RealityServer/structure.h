#pragma once

#include "wwapi.h"
#include "RealityCommon/reality_v2.h"

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
    uint8_t  root_key[kRealityV2KeySize];

    node_t   *destination_node;
    tunnel_t *destination_tunnel;
} realityserver_tstate_t;

enum realityserver_tls_parser_role_e
{
    kRealityServerTlsParserClientHello,
    kRealityServerTlsParserServerHello,
};

typedef struct realityserver_tls_parser_s
{
    uint8_t  record_header[kRealityV2TlsRecordHeaderSize];
    uint8_t  handshake_header[4];
    uint8_t *handshake_body;
    uint32_t record_remaining;
    uint32_t handshake_length;
    uint32_t handshake_received;
    uint8_t  record_header_length;
    uint8_t  record_type;
    uint8_t  handshake_header_length;
    uint8_t  handshake_type;
    uint8_t  role;
    bool     complete;
    bool     failed;
} realityserver_tls_parser_t;

typedef struct realityserver_tls_capture_s
{
    reality_v2_handshake_binding_t binding;
    uint16_t                       client_legacy_version;
    bool                           client_ready;
    bool                           server_ready;
} realityserver_tls_capture_t;

typedef struct realityserver_lstate_s
{
    buffer_stream_t read_stream;
    realityserver_tls_parser_t client_hello_parser;
    realityserver_tls_parser_t server_hello_parser;
    realityserver_tls_capture_t tls_capture;
    uint8_t         session_id[kRealityV2SessionIdSize];
    uint8_t         c2s_key[kRealityV2KeySize];
    uint8_t         s2c_key[kRealityV2KeySize];
    uint8_t         c2s_iv[kRealityV2IvSize];
    uint8_t         s2c_iv[kRealityV2IvSize];
    uint64_t        c2s_recv_seq;
    uint64_t        s2c_send_seq;
    uint32_t        sniffing_attempts;
    uint8_t         mode;
    bool            binding_ready;
    bool            session_keys_ready;
    bool            protected_init_sent;
    bool            destination_init_sent;
    bool            destination_up_finished;
    bool            closing_destination_for_authorized;
    bool            prev_est_sent;
} realityserver_lstate_t;

enum realityserver_frame_e
{
    kRealityServerTlsHeaderSize       = 5,
    kRealityServerTlsChangeCipherSpec = 0x14,
    kRealityServerTlsAlert            = 0x15,
    kRealityServerTlsHandshake        = 0x16,
    kRealityServerTlsApplicationData  = 0x17,
    kRealityServerTlsVersionMajor     = 0x03,
    kRealityServerTlsVersionMinor     = 0x03,
    kRealityServerCoverPrefixSize     = kRealityV2CoverPrefixSize,
    kRealityServerTagSize             = 16,
    kRealityServerFramePrefixSize     = kRealityServerTlsHeaderSize + kRealityServerCoverPrefixSize,
    kRealityServerMaxTlsRecordBody    = 16384,
    kRealityServerMaxFramePayload =
        kRealityServerMaxTlsRecordBody - kRealityServerCoverPrefixSize - kRealityServerTagSize,
    kRealityServerDefaultKdfIterations    = 12000,
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
void realityserverTunnelOnStop(tunnel_t *t);

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

void realityserverTlsParserInitialize(realityserver_tls_parser_t *parser, uint8_t role);
void realityserverTlsParserDestroy(realityserver_tls_parser_t *parser);
bool realityserverTlsParserFeed(realityserver_tls_parser_t *parser, const uint8_t *data, size_t len,
                                realityserver_tls_capture_t *capture);

int  realityserverEncryptAead(uint32_t algorithm, unsigned char *dst, const unsigned char *src, size_t src_len,
                              const unsigned char *ad, size_t ad_len, const unsigned char *nonce,
                              const unsigned char *key);
int  realityserverDecryptAead(uint32_t algorithm, unsigned char *dst, const unsigned char *src, size_t src_len,
                              const unsigned char *ad, size_t ad_len, const unsigned char *nonce,
                              const unsigned char *key);
bool realityserverEncryptAndSendDownstream(tunnel_t *t, line_t *l, sbuf_t *buf);
bool realityserverProcessUpstream(tunnel_t *t, line_t *l, sbuf_t *buf);
bool realityserverObserveDownstreamHandshake(tunnel_t *t, line_t *l, const uint8_t *data, size_t len);
void realityserverCloseLineBidirectional(tunnel_t *t, line_t *l);

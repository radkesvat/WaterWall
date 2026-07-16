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

enum realityserver_gcm_nonce_policy_e
{
    kRealityServerGcmNoncePolicyAuto = 1,
    kRealityServerGcmNoncePolicySequence,
    kRealityServerGcmNoncePolicyCounter,
    kRealityServerGcmNoncePolicyRandom,
};

typedef struct realityserver_tstate_s
{
    uint32_t algorithm;
    uint32_t kdf_iterations;
    uint32_t sniffing_attempts;
    uint8_t  tls12_gcm_server_nonce_policy;
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

typedef struct realityserver_tls12_record_tracker_s
{
    reality_v2_record_profile_t profile;
    uint8_t  record_header[kRealityV2TlsRecordHeaderSize];
    uint8_t  explicit_nonce[kRealityV2Tls12GcmPrefixSize];
    uint64_t next_sequence;
    uint64_t last_record_sequence;
    uint64_t last_explicit_nonce;
    uint32_t record_remaining;
    uint32_t record_body_len;
    uint32_t explicit_nonce_sample_count;
    uint8_t  record_header_length;
    uint8_t  explicit_nonce_length;
    uint8_t  record_type;
    uint8_t  ccs_value;
    bool     protected_epoch;
    bool     current_record_protected;
    bool     last_record_was_protected;
    bool     saw_protected_record;
    bool     sequence_pattern;
    bool     counter_pattern;
    bool     failed;
    bool     frozen;
} realityserver_tls12_record_tracker_t;

typedef struct realityserver_lstate_s
{
    buffer_stream_t read_stream;
    buffer_stream_t downstream_tls_observe_stream;
    realityserver_tls_parser_t client_hello_parser;
    realityserver_tls_parser_t server_hello_parser;
    realityserver_tls_capture_t tls_capture;
    realityserver_tls12_record_tracker_t client_record_tracker;
    realityserver_tls12_record_tracker_t server_record_tracker;
    reality_v2_record_profile_t record_profile;
    uint8_t         session_id[kRealityV2SessionIdSize];
    uint8_t         c2s_key[kRealityV2KeySize];
    uint8_t         s2c_key[kRealityV2KeySize];
    uint8_t         c2s_iv[kRealityV2IvSize];
    uint8_t         s2c_iv[kRealityV2IvSize];
    uint64_t        c2s_recv_seq;
    uint64_t        s2c_send_seq;
    uint64_t        client_tls_sequence_base;
    uint64_t        server_tls_sequence_base;
    uint64_t        server_gcm_counter_next;
    uint32_t        sniffing_attempts;
    uint8_t         mode;
    uint8_t         server_gcm_nonce_policy;
    bool            binding_ready;
    bool            session_keys_ready;
    bool            protected_init_sent;
    bool            destination_init_sent;
    bool            destination_up_finished;
    bool            closing_destination_for_authorized;
    bool            prev_est_sent;
    bool            prev_finished;
    bool            next_finished;
    bool            terminal_closing;
    bool            wire_alert_sent;
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
    kRealityServerTagSize             = kRealityV2TagSize,
    kRealityServerMaxFramePrefixSize  = kRealityServerTlsHeaderSize + kRealityV2MaxVisiblePrefixSize,
    kRealityServerMaxTlsRecordBody    = kRealityV2MaxTlsRecordBody,
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
void realityserverTls12RecordTrackerInitialize(realityserver_tls12_record_tracker_t *tracker);
bool realityserverTls12RecordTrackerSetProfile(realityserver_tls12_record_tracker_t *tracker,
                                               const reality_v2_record_profile_t *profile);
bool realityserverTls12RecordTrackerFeed(realityserver_tls12_record_tracker_t *tracker,
                                         const uint8_t *data, size_t len);
void realityserverTls12RecordTrackerFreeze(realityserver_tls12_record_tracker_t *tracker);
void realityserverTls12RecordTrackerDestroy(realityserver_tls12_record_tracker_t *tracker);
bool realityserverResolveGcmNoncePolicy(uint8_t configured_policy,
                                        const realityserver_tls12_record_tracker_t *server_tracker,
                                        uint8_t *resolved_policy, uint64_t *counter_next);
bool realityserverFreezeTlsCamouflage(realityserver_tstate_t *ts, realityserver_lstate_t *ls);

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
void realityserverFailAuthenticated(tunnel_t *t, line_t *l);
void realityserverHandlePeerAlert(tunnel_t *t, line_t *l, uint8_t alert);
void realityserverHandleUpstreamFinish(tunnel_t *t, line_t *l);
void realityserverHandleDownstreamFinish(tunnel_t *t, line_t *l);

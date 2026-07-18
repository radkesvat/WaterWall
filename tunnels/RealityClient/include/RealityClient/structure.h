#pragma once

#include "wwapi.h"
#include "TlsClient/interface.h"
#include "RealityCommon/reality_v2.h"

typedef struct realityclient_tstate_s
{
    uint32_t algorithm;
    uint32_t kdf_iterations;
    uint8_t  root_key[kRealityV2KeySize];

    node_t    tls_node;
    cJSON    *tls_settings;
    tunnel_t *tls_tunnel;
} realityclient_tstate_t;

typedef enum realityclient_phase_e
{
    kRealityClientPhaseTlsHandshake = 0,
    kRealityClientPhaseTls13AwaitAck,
    kRealityClientPhaseRealityActive,
    kRealityClientPhaseTerminal,
} realityclient_phase_t;

typedef struct realityclient_lstate_s
{
    buffer_stream_t read_stream;
    buffer_stream_t handoff_stream;
    buffer_queue_t  pending_up;
    uint8_t         session_id[kRealityV2SessionIdSize];
    uint8_t         c2s_key[kRealityV2KeySize];
    uint8_t         s2c_key[kRealityV2KeySize];
    uint8_t         c2s_iv[kRealityV2IvSize];
    uint8_t         s2c_iv[kRealityV2IvSize];
    reality_v2_record_profile_t record_profile;
    uint64_t        c2s_send_seq;
    uint64_t        s2c_recv_seq;
    uint64_t        tls12_next_write_sequence;
    uint64_t        tls12_next_read_sequence;
    uint16_t        tls_version;
    uint8_t         phase;
    bool            session_keys_ready;
    bool            tls12_sequences_valid;
    bool            handoff_request_sent;
    bool            handoff_ack_authenticated;
    bool            handoff_confirm_sent;
    bool            handoff_cover_consume_in_progress;
    bool            handoff_completion_in_progress;
    bool            downstream_est_sent;
    bool            prev_finished;
    bool            next_finished;
    bool            terminal_closing;
    bool            wire_alert_sent;
} realityclient_lstate_t;

enum realityclient_algorithm_e
{
    kRealityClientAlgorithmChaCha20Poly1305 = kDvsFirstOption,
    kRealityClientAlgorithmAes256Gcm        = kDvsSecondOption,
};

enum realityclient_frame_e
{
    kRealityClientTlsHeaderSize      = 5,
    kRealityClientTlsApplicationData = 0x17,
    kRealityClientTlsVersionMajor    = 0x03,
    kRealityClientTlsVersionMinor    = 0x03,
    kRealityClientTagSize            = kRealityV2TagSize,
    kRealityClientMaxFramePrefixSize = kRealityClientTlsHeaderSize + kRealityV2MaxVisiblePrefixSize,
    kRealityClientMaxTlsRecordBody   = kRealityV2MaxTlsRecordBody,
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
void realityclientTunnelOnStop(tunnel_t *t);

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
bool realityclientSendHandoffControl(tunnel_t *t, line_t *l, uint8_t record_kind);
bool realityclientProcessHandoffDownstream(tunnel_t *t, line_t *l, sbuf_t *buf);
bool realityclientFlushPendingUpstream(tunnel_t *t, line_t *l);
void realityclientCloseLineBidirectional(tunnel_t *t, line_t *l);
void realityclientFailAuthenticated(tunnel_t *t, line_t *l);
void realityclientHandlePeerAlert(tunnel_t *t, line_t *l, uint8_t alert);
void realityclientHandleUpstreamFinish(tunnel_t *t, line_t *l);
void realityclientHandleDownstreamFinish(tunnel_t *t, line_t *l);

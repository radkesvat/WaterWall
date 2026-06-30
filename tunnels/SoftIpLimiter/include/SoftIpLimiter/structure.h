#pragma once

#include "wwapi.h"

enum
{
    kSoftIpLimiterMaxIps             = 6,
    kSoftIpLimiterVlessVersion       = 0x00,
    kSoftIpLimiterVlessUuidLen       = 16,
    kSoftIpLimiterTrojanPasswordLen  = 56,
    kSoftIpLimiterInitialTableCap    = 64,
};

typedef enum softiplimiter_identifier_mode_e
{
    kSoftIpLimiterIdentifierNone = 0,
    kSoftIpLimiterIdentifierVless,
    kSoftIpLimiterIdentifierTrojan
} softiplimiter_identifier_mode_t;

typedef enum softiplimiter_phase_e
{
    kSoftIpLimiterPhaseWaitIdentity = 0,
    kSoftIpLimiterPhaseEstablished,
    kSoftIpLimiterPhaseClosing
} softiplimiter_phase_t;

typedef enum softiplimiter_close_origin_e
{
    kSoftIpLimiterCloseInternal = 0,
    kSoftIpLimiterCloseFromPrev,
    kSoftIpLimiterCloseFromNext
} softiplimiter_close_origin_t;

typedef enum softiplimiter_extract_result_e
{
    kSoftIpLimiterExtractInvalid = -1,
    kSoftIpLimiterExtractWait    = 0,
    kSoftIpLimiterExtractOk      = 1
} softiplimiter_extract_result_t;

typedef enum softiplimiter_table_reason_e
{
    kSoftIpLimiterTableOk = 0,
    kSoftIpLimiterTableLimitReached,
    kSoftIpLimiterTableMissingRow,
    kSoftIpLimiterTableMissingIp
} softiplimiter_table_reason_t;

typedef struct softiplimiter_ip_key_s
{
    uint8_t type;
    uint8_t bytes[16];
} softiplimiter_ip_key_t;

typedef struct softiplimiter_ip_row_s
{
    softiplimiter_ip_key_t ip_key;
    uint32_t               refs;
    // Refreshed atomically (relaxed) so the per-payload touch fast path can run
    // under a shared read lock without serializing the data plane. All structural
    // mutations (insert/prune/erase/swap-remove) stay under the exclusive write
    // lock, so these copies never race with the atomic refresh.
    atomic_ullong          last_seen_ms;
} softiplimiter_ip_row_t;

typedef struct softiplimiter_identity_entry_s
{
    uint8_t                ip_count;
    softiplimiter_ip_row_t ips[kSoftIpLimiterMaxIps];
} softiplimiter_identity_entry_t;

typedef struct softiplimiter_table_result_s
{
    softiplimiter_table_reason_t reason;
    uint8_t                      count;
    uint8_t                      limit;
} softiplimiter_table_result_t;

#define i_type softiplimiter_identity_map_t
#define i_key  hash_t
#define i_val  softiplimiter_identity_entry_t
#include "stc/hmap.h"

typedef struct softiplimiter_tstate_s
{
    wrwlock_t                       table_lock;
    softiplimiter_identity_map_t    table;
    softiplimiter_identifier_mode_t identifier_mode;
    uint64_t                        tolerance_ms;
    uint8_t                         simultaneous_user_limit;
    bool                            verbose;
} softiplimiter_tstate_t;

typedef struct softiplimiter_lstate_s
{
    buffer_stream_t          in_stream;
    hash_t                   identifier;
    softiplimiter_ip_key_t   ip_key;
    softiplimiter_phase_t    phase;
    bool                     closing;
    bool                     admitted;
    bool                     next_init_sent;
    bool                     ip_key_valid;
} softiplimiter_lstate_t;

enum
{
    kTunnelStateSize = sizeof(softiplimiter_tstate_t),
    kLineStateSize   = sizeof(softiplimiter_lstate_t)
};

WW_EXPORT void         softiplimiterTunnelDestroy(tunnel_t *t);
WW_EXPORT tunnel_t    *softiplimiterTunnelCreate(node_t *node);
WW_EXPORT api_result_t softiplimiterTunnelApi(tunnel_t *instance, sbuf_t *message);

void softiplimiterTunnelUpStreamInit(tunnel_t *t, line_t *l);
void softiplimiterTunnelUpStreamEst(tunnel_t *t, line_t *l);
void softiplimiterTunnelUpStreamFinish(tunnel_t *t, line_t *l);
void softiplimiterTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void softiplimiterTunnelUpStreamPause(tunnel_t *t, line_t *l);
void softiplimiterTunnelUpStreamResume(tunnel_t *t, line_t *l);

void softiplimiterTunnelDownStreamInit(tunnel_t *t, line_t *l);
void softiplimiterTunnelDownStreamEst(tunnel_t *t, line_t *l);
void softiplimiterTunnelDownStreamFinish(tunnel_t *t, line_t *l);
void softiplimiterTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void softiplimiterTunnelDownStreamPause(tunnel_t *t, line_t *l);
void softiplimiterTunnelDownStreamResume(tunnel_t *t, line_t *l);

void softiplimiterLinestateInitialize(softiplimiter_lstate_t *ls, line_t *l);
void softiplimiterLinestateDestroy(softiplimiter_lstate_t *ls);

void     softiplimiterTunnelstateInitialize(softiplimiter_tstate_t *ts);
void     softiplimiterTunnelstateDestroy(softiplimiter_tstate_t *ts);
uint64_t softiplimiterNowMs(void);

const char *softiplimiterIdentifierModeName(softiplimiter_identifier_mode_t mode);
bool        softiplimiterIpKeyEqual(const softiplimiter_ip_key_t *a, const softiplimiter_ip_key_t *b);
bool        softiplimiterBuildIpKey(line_t *l, softiplimiter_ip_key_t *out);
void        softiplimiterFormatIpKey(const softiplimiter_ip_key_t *ip_key, char *out, size_t out_len);

softiplimiter_extract_result_t softiplimiterTryExtractIdentifierFromBytes(softiplimiter_identifier_mode_t mode,
                                                                          const uint8_t *bytes,
                                                                          size_t len,
                                                                          hash_t *identifier_out);
softiplimiter_extract_result_t softiplimiterTryExtractIdentifierFromStream(softiplimiter_identifier_mode_t mode,
                                                                           buffer_stream_t *stream,
                                                                           hash_t *identifier_out);

bool softiplimiterTableAdmit(softiplimiter_identity_map_t *table, hash_t identifier,
                             const softiplimiter_ip_key_t *ip_key, uint8_t limit, uint64_t tolerance_ms,
                             uint64_t now_ms, softiplimiter_table_result_t *result);
bool softiplimiterTableTouch(softiplimiter_identity_map_t *table, hash_t identifier,
                             const softiplimiter_ip_key_t *ip_key, uint8_t limit, uint64_t tolerance_ms,
                             uint64_t now_ms, softiplimiter_table_result_t *result);
void softiplimiterTableRelease(softiplimiter_identity_map_t *table, hash_t identifier,
                               const softiplimiter_ip_key_t *ip_key, uint64_t tolerance_ms, uint64_t now_ms);

bool softiplimiterAdmitLine(tunnel_t *t, line_t *l, softiplimiter_lstate_t *ls, uint64_t now_ms,
                            softiplimiter_table_result_t *result);
bool softiplimiterTouchLine(tunnel_t *t, softiplimiter_lstate_t *ls, uint64_t now_ms,
                            softiplimiter_table_result_t *result);
void softiplimiterReleaseLine(tunnel_t *t, softiplimiter_lstate_t *ls);

void softiplimiterLogRejected(tunnel_t *t, line_t *l, const softiplimiter_lstate_t *ls, const char *reason,
                              const softiplimiter_table_result_t *result);
void softiplimiterLogActiveClose(tunnel_t *t, line_t *l, const softiplimiter_lstate_t *ls, const char *reason,
                                 const softiplimiter_table_result_t *result);
void softiplimiterCloseLine(tunnel_t *t, line_t *l, softiplimiter_close_origin_t origin);
void softiplimiterHandleInitialPayload(tunnel_t *t, line_t *l, sbuf_t *buf);

#pragma once

#include "buffer_budget.h"
#include "interface.h"

enum
{
    kStreamFragmenterMaxCuts    = 64,
    kStreamFragmenterHardCharge = 8 * 1024 * 1024,
    kStreamFragmenterHighCharge = 6 * 1024 * 1024,
    kStreamFragmenterLowCharge  = 3 * 1024 * 1024,
    kStreamFragmenterHardJobs   = 1024,
    kStreamFragmenterHighJobs   = 768,
    kStreamFragmenterLowJobs    = 384,
    kStreamFragmenterMaxHello   = 65536,
    kStreamFragmenterMaxWire    = 6 * kStreamFragmenterMaxHello,
    kStreamFragmenterMaxRewrite = kStreamFragmenterMaxWire + 5 * kStreamFragmenterMaxCuts
};

typedef struct streamfragmenter_cut_s
{
    uint32_t offset;
    uint32_t delay_ms;
    uint8_t  chance;
} streamfragmenter_cut_t;

typedef struct streamfragmenter_tstate_s
{
    streamfragmenter_cut_t cuts[kStreamFragmenterMaxCuts];
    uint32_t               scope;
    uint8_t                cut_count;
    uint8_t                bypass_chance;
    bool                   timed : 1;
    bool                   wait_for_est : 1;
    bool                   tls_hello_fragment : 1;
    uint32_t               tls_hello_timeout_ms;
} streamfragmenter_tstate_t;

typedef enum streamfragmenter_protocol_e
{
    kStreamFragmenterAwaitingData,
    kStreamFragmenterCollecting,
    kStreamFragmenterOpaque
} streamfragmenter_protocol_t;

typedef enum streamfragmenter_job_kind_e
{
    kStreamFragmenterJobOrdinary,
    kStreamFragmenterJobCandidate,
    kStreamFragmenterJobHello
} streamfragmenter_job_kind_t;

typedef enum streamfragmenter_timer_kind_e
{
    kStreamFragmenterTimerNone,
    kStreamFragmenterTimerAssembly,
    kStreamFragmenterTimerDelay
} streamfragmenter_timer_kind_t;

/* Parser state is line-local. Original record headers remain in the candidate
 * buffer, so a fallback can replay the exact wire prefix. */
typedef struct streamfragmenter_tls_parser_s
{
    uint8_t  record_header[5];
    uint8_t  handshake_header[4];
    uint8_t  record_header_used;
    uint8_t  handshake_header_used;
    uint16_t record_remaining;
    uint32_t handshake_total;
    uint32_t handshake_seen;
} streamfragmenter_tls_parser_t;

typedef enum streamfragmenter_tls_result_e
{
    kStreamFragmenterTlsIncomplete,
    kStreamFragmenterTlsHeaderReady,
    kStreamFragmenterTlsComplete,
    kStreamFragmenterTlsPassUnchanged
} streamfragmenter_tls_result_t;

/* Generic jobs retain their payload boundary and arrival-time decisions. A TLS
 * candidate coalesces the initial wire prefix across callbacks in this FIFO.
 * The active head stays here, including throughout timer waits. */
typedef struct streamfragmenter_job_s
{
    struct streamfragmenter_job_s *next;
    sbuf_t                        *buf;
    buffer_budget_reservation_t    reservation;
    uint64_t                       cuts;
    uint64_t                       due_us;
    uint32_t                       consumed;
    uint32_t                      *mapped_cuts; /* Only allocated for a rewritten hello. */
    uint8_t                        next_cut;
    bool                           delay_started;
    streamfragmenter_job_kind_t    kind;
} streamfragmenter_job_t;

typedef struct streamfragmenter_lstate_s
{
    tunnel_t                     *tunnel;
    line_t                       *line; /* Borrowed normal line; its creator drives Finish during drain. */
    streamfragmenter_job_t       *head;
    streamfragmenter_job_t       *tail;
    streamfragmenter_job_t       *candidate;
    buffer_budget_t               budget;
    wtimer_t                     *timer;
    uint64_t                      deadline_us;
    uint64_t                      assembly_deadline_us;
    streamfragmenter_tls_parser_t tls_parser;
    uint32_t                      remaining;
    streamfragmenter_protocol_t   protocol;
    streamfragmenter_timer_kind_t timer_kind;
    bool                          exhausted : 1;
    bool                          draining : 1;
    bool                          consumer_paused : 1;
    bool                          locally_paused : 1;
    bool                          source_paused : 1;
    bool                          waiting_for_est : 1;
    bool                          est_received : 1;
} streamfragmenter_lstate_t;

bool streamfragmenterLoadSettings(streamfragmenter_tstate_t *ts, const cJSON *settings);
void streamfragmenterLinestateInitialize(streamfragmenter_lstate_t *ls, tunnel_t *t, line_t *l);
void streamfragmenterLinestateDestroy(streamfragmenter_lstate_t *ls);
void streamfragmenterCloseLine(tunnel_t *t, line_t *l);
bool streamfragmenterUpdatePressure(tunnel_t *t, line_t *l);
void streamfragmenterDrain(tunnel_t *t, line_t *l);
bool streamfragmenterEnqueue(tunnel_t *t, line_t *l, sbuf_t *buf, uint64_t cuts, streamfragmenter_job_kind_t kind);
void streamfragmenterCandidateFallback(tunnel_t *t, line_t *l);
bool streamfragmenterArmAssemblyTimer(tunnel_t *t, line_t *l);
void streamfragmenterCancelAssemblyTimer(streamfragmenter_lstate_t *ls);

uint32_t                      streamfragmenterTlsNeed(const streamfragmenter_tls_parser_t *parser);
streamfragmenter_tls_result_t streamfragmenterTlsFeed(streamfragmenter_tls_parser_t *parser, const uint8_t *bytes,
                                                      uint32_t length);
bool                          streamfragmenterTlsRewrite(const sbuf_t *original, uint64_t selected_cuts,
                                                         const streamfragmenter_tstate_t *settings, sbuf_t *output, uint32_t *mapped_cuts);
uint32_t                      streamfragmenterTlsRewriteLength(const sbuf_t *original, uint64_t selected_cuts,
                                                               const streamfragmenter_tstate_t *settings);

void streamfragmenterTunnelUpStreamInit(tunnel_t *t, line_t *l);
void streamfragmenterTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void streamfragmenterTunnelUpStreamFinish(tunnel_t *t, line_t *l);
void streamfragmenterTunnelDownStreamFinish(tunnel_t *t, line_t *l);
void streamfragmenterTunnelDownStreamEst(tunnel_t *t, line_t *l);
void streamfragmenterTunnelDownStreamPause(tunnel_t *t, line_t *l);
void streamfragmenterTunnelDownStreamResume(tunnel_t *t, line_t *l);

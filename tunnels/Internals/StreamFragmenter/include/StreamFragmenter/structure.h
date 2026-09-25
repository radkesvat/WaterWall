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
    kStreamFragmenterLowJobs    = 384
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
    bool                   timed;
    bool                   wait_for_est;
} streamfragmenter_tstate_t;

/* Each job retains the original payload boundary and its arrival-time decisions.
 * The active head stays in this same FIFO, including throughout timer waits. */
typedef struct streamfragmenter_job_s
{
    struct streamfragmenter_job_s *next;
    sbuf_t                        *buf;
    buffer_budget_reservation_t    reservation;
    uint64_t                       cuts;
    uint64_t                       due_us;
    uint32_t                       consumed;
    uint8_t                        next_cut;
    bool                           delay_started;
} streamfragmenter_job_t;

typedef struct streamfragmenter_lstate_s
{
    tunnel_t               *tunnel;
    line_t                 *line; /* Borrowed normal line; its creator drives Finish during drain. */
    streamfragmenter_job_t *head;
    streamfragmenter_job_t *tail;
    buffer_budget_t         budget;
    wtimer_t               *timer;
    uint64_t                deadline_us;
    uint32_t                remaining;
    bool                    exhausted;
    bool                    draining;
    bool                    consumer_paused;
    bool                    locally_paused;
    bool                    source_paused;
    bool                    waiting_for_est;
    bool                    est_received;
} streamfragmenter_lstate_t;

bool streamfragmenterLoadSettings(streamfragmenter_tstate_t *ts, const cJSON *settings);
void streamfragmenterLinestateDestroy(streamfragmenter_lstate_t *ls);
void streamfragmenterCloseLine(tunnel_t *t, line_t *l);
bool streamfragmenterUpdatePressure(tunnel_t *t, line_t *l);
void streamfragmenterDrain(tunnel_t *t, line_t *l);

void streamfragmenterTunnelUpStreamInit(tunnel_t *t, line_t *l);
void streamfragmenterTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void streamfragmenterTunnelUpStreamFinish(tunnel_t *t, line_t *l);
void streamfragmenterTunnelDownStreamFinish(tunnel_t *t, line_t *l);
void streamfragmenterTunnelDownStreamEst(tunnel_t *t, line_t *l);
void streamfragmenterTunnelDownStreamPause(tunnel_t *t, line_t *l);
void streamfragmenterTunnelDownStreamResume(tunnel_t *t, line_t *l);

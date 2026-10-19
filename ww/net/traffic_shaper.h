#pragma once

#include "buffer_budget.h"
#include "buffer_queue.h"
#include "line.h"

typedef enum traffic_shaper_mode_e
{
    kTrafficShaperStream,
    kTrafficShaperDatagram
} traffic_shaper_mode_t;

typedef enum traffic_shaper_commit_e
{
    kTrafficShaperForward,
    kTrafficShaperWait,
    kTrafficShaperReject,
    kTrafficShaperForwardClose
} traffic_shaper_commit_t;

typedef struct traffic_shaper_preview_s
{
    size_t   bytes;
    uint32_t retry_ms;
    bool     reject;
} traffic_shaper_preview_t;

typedef struct traffic_shaper_ops_s
{
    /* Preview never consumes credit. queued distinguishes a retained FIFO head
     * from immediate input. A zero-length candidate is eligible when bytes==0
     * and retry_ms==0. No hook may emit a neighbor callback except the final
     * forward/pressure/close actions. */
    traffic_shaper_preview_t (*preview)(void *context, size_t requested, bool queued);
    traffic_shaper_commit_t (*commit)(void *context, size_t bytes, bool queued, bool remaining);
    void (*forward)(void *context, sbuf_t *buffer);
    void (*pressure)(void *context, bool paused);
    void (*close)(void *context);
    /* Optional synchronized user/client costs, in addition to the owner-local
     * budget. Reserve is transactional; release is infallible. */
    bool (*reserve)(void *context, buffer_budget_cost_t cost);
    void (*release)(void *context, buffer_budget_cost_t cost);
    /* Publish FIFO/eligibility changes, including quiescence. On empty, remove
     * the ticket only after every cost has been released. */
    void (*state_changed)(void *context, bool has_work, bool externally_paused);
} traffic_shaper_ops_t;

typedef struct traffic_shaper_continuation_s traffic_shaper_continuation_t;

typedef struct traffic_shaper_s
{
    buffer_queue_t                 queue;
    buffer_budget_t               *budget;
    buffer_budget_cost_t           retained_cost;
    sbuf_t                        *candidate;
    wtimer_t                      *timer;
    traffic_shaper_continuation_t *continuation;
    const traffic_shaper_ops_t    *ops;
    void                          *context;
    line_t                        *line;
    uint32_t                       yield_ms;
    traffic_shaper_mode_t          mode;
    bool                           allocation_charge;
    bool                           externally_paused;
    bool                           locally_paused; /* Stream backlog producer hold; never set for datagrams. */
    bool                           stopped;
} traffic_shaper_t;

typedef enum traffic_shaper_submit_e
{
    kTrafficShaperConsumed, /* Forwarded, dropped, or settled by close. */
    kTrafficShaperRetained, /* Ownership entered the bounded FIFO. */
    kTrafficShaperRefused   /* Caller still owns its unchanged input. */
} traffic_shaper_submit_t;

/* budget is stable and may be shared by both directions. Queues allocate lazily.
 * yield_ms==0 uses one force-queued continuation per turn; a positive value
 * retains a consumer's historical timer cadence. allocation_charge chooses
 * resident allocation cost rather than splice logical queue geometry. Datagram
 * backlog never originates producer Pause/Resume; explicit consumer pressure
 * still gates output and is propagated to its producer. */
void trafficshaperInit(traffic_shaper_t *shaper, line_t *line, buffer_budget_t *budget, const traffic_shaper_ops_t *ops,
                       void *context, traffic_shaper_mode_t mode, uint32_t yield_ms, bool allocation_charge);
traffic_shaper_submit_t trafficshaperSubmit(traffic_shaper_t *shaper, sbuf_t *buffer);
void                    trafficshaperDrain(traffic_shaper_t *shaper);
void                    trafficshaperTimerCallback(wtimer_t *timer);
void                    trafficshaperSetExternalPause(traffic_shaper_t *shaper, bool paused);
/* Reuses or resets an existing timer; scheduling refusal is reported without
 * emitting callbacks. delay_ms==0 selects a force-queued continuation. */
bool trafficshaperSchedule(traffic_shaper_t *shaper, uint32_t delay_ms);
/* Owner-worker quiescence detaches every asynchronous root, retaining buffers
 * for the normal owner's subsequent Finish. No callback is emitted. */
void   trafficshaperQuiesce(traffic_shaper_t *shaper);
void   trafficshaperDestroy(traffic_shaper_t *shaper);
size_t trafficshaperPending(const traffic_shaper_t *shaper);

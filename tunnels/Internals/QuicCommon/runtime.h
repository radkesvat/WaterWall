#pragma once

#include "carrier.h"
#include "quic_common.h"

enum
{
    kQuicPumpWork            = 256,
    kQuicFinalFlushTimeoutUs  = 30 * 1000 * 1000,
    kQuicFinAcknowledgeWaitUs = 1000 * 1000
};

/* A detached context may outlive its lstate only until the synchronous driver
 * returns. No library frame, timer, or later task retains a destroyed lstate.
 * This header is private to the shared C runtime, never the C++ engine. */
struct quic_context
{
    tunnel_t                   *tunnel;
    line_t                     *line;
    buffer_pool_t              *pool;
    ww_quic_engine_t           *engine;
    wtimer_t                   *timer;
    quic_context_t             *previous;
    quic_context_t             *next;
    buffer_budget_t             application_budget;
    buffer_budget_t             input_budget;
    buffer_queue_t              application;
    buffer_queue_t              input;
    sbuf_t                     *active_application;
    sbuf_t                     *active_input;
    buffer_budget_reservation_t application_reservation;
    buffer_budget_reservation_t input_reservation;
    ww_quic_carrier_t           carrier;
    size_t                      carrier_allocations;
    uint64_t                    input_generation;
    uint64_t                    final_deadline_us;
    bool                        final_flush : 1;
    bool                        fin_sent : 1;
    bool                        attached : 1;
    bool                        driving : 1;
    bool                        started : 1;
    bool                        next_init_sent : 1;
    bool                        pressure : 1;
    bool                        finish_up : 1;
    bool                        finish_down : 1;
};

/* Engine descriptor admission includes queued and active work. These counts
 * are QUIC resources, separate from retained bytes and allocation charge. */
static inline size_t quicApplicationEntries(quic_context_t *context)
{
    return bufferqueueGetBufCount(&context->application) + (context->active_application != NULL);
}

static inline size_t quicInputEntries(quic_context_t *context)
{
    return bufferqueueGetBufCount(&context->input) + (context->active_input != NULL) + context->carrier_allocations;
}

quic_context_t *quicGetContext(tunnel_t *t, line_t *l);
bool            quicEnter(quic_context_t *context);
void            quicLeave(quic_context_t *context);
bool            quicSurvived(const quic_context_t *context);
void            quicFail(quic_context_t *context, const char *reason);
void            quicRetire(quic_context_t *context);
void            quicReleaseActive(quic_context_t *context, bool application);
bool            quicFeedInput(quic_context_t *context);
void            quicPressure(quic_context_t *context);
void            quicPump(quic_context_t *context);
void            quicFinalWire(quic_context_t *context);
void            quicReconcileFinal(quic_context_t *context);
void            quicCancelTimer(quic_context_t *context);
void            quicArm(quic_context_t *context, bool more_work);

/* The client's application is prev and the server's is next. Once it has
 * finished, it accepts no further payload, pause, or resume on this line. */
static inline bool quicApplicationFinished(const quic_context_t *context)
{
    const quic_tstate_t *state = tunnelGetState(context->tunnel);
    return state->client ? context->finish_up : context->finish_down;
}

static inline bool quicCarrierFinished(const quic_context_t *context)
{
    const quic_tstate_t *state = tunnelGetState(context->tunnel);
    return state->client ? context->finish_down : context->finish_up;
}

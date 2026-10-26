#pragma once

#include "carrier.h"
#include "quic_common.h"

enum
{
    kQuicPumpWork = 256
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
    uint64_t                    input_generation;
    bool                        attached : 1;
    bool                        driving : 1;
    bool                        started : 1;
    bool                        next_init_sent : 1;
    bool                        pressure : 1;
    bool                        finish_up : 1;
    bool                        finish_down : 1;
};

quic_context_t *quicGetContext(tunnel_t *t, line_t *l);
bool            quicEnter(quic_context_t *context);
void            quicLeave(quic_context_t *context);
bool            quicSurvived(const quic_context_t *context);
void            quicFail(quic_context_t *context, const char *reason);
void            quicReleaseActive(quic_context_t *context, bool application);
bool            quicFeedInput(quic_context_t *context);
void            quicPressure(quic_context_t *context);
void            quicPump(quic_context_t *context);
void            quicFinalWire(quic_context_t *context);
void            quicCancelTimer(quic_context_t *context);
void            quicArm(quic_context_t *context, bool more_work);

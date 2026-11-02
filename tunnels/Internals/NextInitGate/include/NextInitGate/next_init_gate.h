#pragma once

#include "buffer_queue.h"
#include "line.h"

typedef enum next_init_gate_phase_e
{
    kNextInitGateWaiting,
    kNextInitGateStarting,
    kNextInitGateOpen
} next_init_gate_phase_t;

/* Embed at a stable address in a borrowed normal line's state. All operations
 * run on that line's owner worker. The node initializes its own state in Init;
 * this phase describes only the deferred handoff to next. */
typedef struct next_init_gate_s
{
    buffer_queue_t         pending;
    buffer_budget_cost_t   limits;
    next_init_gate_phase_t phase;
    bool                   pause_latched;
} next_init_gate_t;

/* Bounds cover only nested input queued during startup. The original accepted
 * input is separate working storage, consumed by Open. Empty queued buffers
 * still contribute charge. No buffer-count limit is imposed. */
void nextinitgateInit(next_init_gate_t *gate, size_t max_bytes, size_t max_charge);
/* Also accepts zeroed/empty state with a null pool. Otherwise use the line's
 * owner-worker pool; release queued input before clearing the node state. */
void nextinitgateDestroy(next_init_gate_t *gate, buffer_pool_t *pool);

/* Before next Init: remember the latest signal and return false. From the start
 * of next Init onward: clear any stale latch and return true; the caller must
 * immediately forward this notification, including repeats. Filter retired or
 * closing node state before calling. This does not gate payload on Resume. */
bool nextinitgateSignal(next_init_gate_t *gate, bool paused);

typedef enum next_init_gate_input_e
{
    kNextInitGateForward,
    kNextInitGateQueued,
    kNextInitGateRejected
} next_init_gate_input_t;

/* Requires Starting or Open; pre-start protocol input belongs to the node.
 * Queued transfers ownership and clears *buf. Forward and Rejected leave *buf
 * unchanged and owned by the caller. Preserves FIFO and buffer representation. */
next_init_gate_input_t nextinitgateSubmit(next_init_gate_t *gate, sbuf_t **buf);

typedef bool (*next_init_gate_valid_fn)(tunnel_t *t, line_t *line);
typedef enum next_init_gate_result_e
{
    kNextInitGateReady,
    kNextInitGateGone
} next_init_gate_result_t;

/* Requires Waiting and a live line. Publish the node's forwarding phase and
 * next-Init ownership before calling. Consumes nullable first on every result.
 * Holds a line reference through next Init, pending Pause, first and FIFO replay.
 * After EVERY callback, checks line life before calling still_mine, which must
 * also detect destruction of borrowed node state while the line remains alive.
 * On retirement, recycles undelivered first through the captured line pool;
 * the node's destroy path owns queued input. Gone forbids further line/state
 * access. Ready means Open with an empty FIFO; the node may then retire/bypass.
 * No callbacks run after releasing the startup barrier. */
next_init_gate_result_t nextinitgateOpen(next_init_gate_t *gate, tunnel_t *t, line_t *line, sbuf_t *first,
                                         next_init_gate_valid_fn still_mine);

#pragma once

#include "buffer_queue.h"
#include "line.h"

typedef enum fallback_replay_zero_delay_mode_e
{
    kFallbackReplayDeferred = 0, /* Reentrant input drains on a later loop turn. */
    kFallbackReplayCallerDriven, /* The node's synchronous pump drains each entry. */
    kFallbackReplayInlineNested  /* Ready input may reenter the branch inline. */
} fallback_replay_zero_delay_mode_e;

/* Immutable, stable node-owned policy. Keep it alive until all lines drain. */
typedef struct fallback_replay_config_s
{
    uint32_t                          delay_ms;
    uint32_t                          jitter_ms;
    size_t                            max_batch_bytes;
    fallback_replay_zero_delay_mode_e zero_delay_mode;
    bool                              compact_ordinary; /* Positive-delay admission may compact ordinary batches. */
} fallback_replay_config_t;

typedef enum fallback_replay_result_e
{
    kFallbackReplayOk,
    kFallbackReplayGone,
    kFallbackReplayRefused
} fallback_replay_result_e;

/* Embedded at a stable address in a borrowed normal line's state. Zero is idle;
 * Destroy returns it to zero. All operations run on the line/pool owner worker.
 * Fields are private to FallbackReplay; callers use the operations below. */
typedef struct fallback_replay_s
{
    buffer_queue_t                  pending;
    const fallback_replay_config_t *config;
    tunnel_t                       *branch;
    bool                            initializing : 1;
    bool                            startup : 1;
    bool                            dispatching : 1;
    bool                            scheduled : 1;
    bool                            closing : 1;
    bool                            branch_finished : 1;
} fallback_replay_t;

/* Consumes transcript on every result, leaving it empty and unbound. Preserves
 * its existing budget accounting, rebinding to budget if necessary. Refusal
 * recycles the entire transcript. When enabled, positive-delay ordinary batches
 * retry charge/entry admission in best-fit storage. Publish the node's fallback phase before
 * calling branch Init after Begin succeeds. No callbacks run in Begin. */
fallback_replay_result_e fallbackReplayBegin(fallback_replay_t *replay, line_t *line, tunnel_t *branch,
                                             const fallback_replay_config_t *config, buffer_budget_t *budget,
                                             buffer_queue_t *transcript);

/* Call immediately after successful branch Init and a surviving node-state
 * check, BEFORE replaying Pause. The startup FIFO barrier remains held. */
void fallbackReplayMarkInitialized(fallback_replay_t *replay);

/* Release the startup barrier after Pause replay. Zero delay sends the complete
 * initial batch inline, then follows the configured reentry policy. Positive
 * delay schedules one FIFO drain, even if jitter selects a zero-ms timer. */
fallback_replay_result_e fallbackReplayInitDone(fallback_replay_t *replay, tunnel_t *owner, line_t *line,
                                                LineTaskFnNoBuf task);

/* Always consumes payload. Optional compaction preserves bytes and the pending
 * deadline; zero-delay queues and batches containing splice buffers keep their
 * existing admission/representation. Admission refusal recycles the input; scheduling
 * refusal leaves retained input owned by replay until the caller closes/destroys
 * it. Gone means line/state retirement or an already-running close; stop using
 * the state even when the borrowed line remains alive. */
fallback_replay_result_e fallbackReplaySubmit(fallback_replay_t *replay, tunnel_t *owner, line_t *line, sbuf_t *payload,
                                              LineTaskFnNoBuf task);

/* The node's scheduled callback resolves its embedded replay and calls OnTask.
 * A late callback after Destroy is a harmless Gone result. */
fallback_replay_result_e fallbackReplayOnTask(fallback_replay_t *replay, tunnel_t *owner, line_t *line,
                                              LineTaskFnNoBuf task);

/* CallerDriven mode only. The node holds its pump guard across this operation.
 * Zero delay forwards at most one retained entry, preserving its boundary;
 * positive delay ensures a scheduled batch. Sets dispatched before any Payload.
 * Initialization/reentry barriers still block draining. Gone forbids continuing
 * the pump or touching line/state, even if dispatched was set. */
fallback_replay_result_e fallbackReplayDrainOne(fallback_replay_t *replay, tunnel_t *owner, line_t *line,
                                                LineTaskFnNoBuf task, bool *dispatched);

/* The node MUST publish its Closing phase or finished-side guard first,
 * suppressing callbacks toward the finished previous side. Drain at most one
 * final batch, or discard while
 * branch Init is still executing. On Ok, destroy the node state before
 * sending branch Finish iff send_finish is true. Gone permits neither action. */
fallback_replay_result_e fallbackReplayCloseFromPrev(fallback_replay_t *replay, line_t *line, bool *send_finish);

/* Consume a branch Finish nested in the final replay. Other branch Finish
 * callbacks remain the node's responsibility. */
bool fallbackReplayAbsorbBranchFinish(fallback_replay_t *replay);

/* Accepts zeroed state without a pool (e.g. before line attachment). Otherwise
 * pool must be the line's owner-worker pool and settle all retained buffers. */
void fallbackReplayDestroy(fallback_replay_t *replay, buffer_pool_t *pool);

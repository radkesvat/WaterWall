#pragma once

/*
 * Shared scaffolding for the Category-C per-line failure-injection tests.
 *
 * A Category-C failure belongs to one connection. The tunnel must release everything that line owned, close only
 * that line through the correct callbacks, and leave the process and every other line running. This header gives
 * each of those properties a machine-checkable form:
 *
 *   - the three process APIs are linker-wrapped and fail the test the moment one of them is reached;
 *   - every pooled buffer handed out is tracked, so a leak and a double recycle are both hard errors;
 *   - fake previous/next tunnels record an ordered event trace, so "no Init reached the next branch" and
 *     "upstream Finish came before downstream Finish" are single string comparisons.
 *
 * It deliberately includes no tunnel structure.h: several tunnels ship a header with that name and one
 * translation unit must only ever see the tunnel it is testing. Anything tunnel-specific belongs in the test.
 *
 * Every test that includes this header must link with:
 *   -Wl,--wrap=terminateProgram -Wl,--wrap=abortProgramNow -Wl,--wrap=requestProgramShutdown
 *   -Wl,--wrap=bufferpoolGetLargeBuffer -Wl,--wrap=bufferpoolGetSmallBuffer -Wl,--wrap=bufferpoolReuseBuffer
 */

#include "wwapi.h"

// ---------------------------------------------------------------------------
// assertions
// ---------------------------------------------------------------------------

static const char *g_twf_case = "<none>";

static void twfSetCase(const char *name)
{
    g_twf_case = name;
}

static void twfRequire(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "FAIL [%s]: %s\n", g_twf_case, message);
        fflush(stderr);
        _Exit(1);
    }
}

static void twfRequireEqualU32(uint32_t actual, uint32_t expected, const char *message)
{
    if (actual != expected)
    {
        fprintf(stderr, "FAIL [%s]: %s (expected %u, got %u)\n", g_twf_case, message, expected, actual);
        fflush(stderr);
        _Exit(1);
    }
}

static void twfRequireEqualText(const char *actual, const char *expected, const char *message)
{
    if (stringCompare(actual, expected) != 0)
    {
        fprintf(stderr, "FAIL [%s]: %s (expected \"%s\", got \"%s\")\n", g_twf_case, message, expected, actual);
        fflush(stderr);
        _Exit(1);
    }
}

// ---------------------------------------------------------------------------
// process API guard
// ---------------------------------------------------------------------------
//
// A Category-C failure belongs to one line, so reaching any process API is a
// test failure. A Category-B test proves the opposite policy - that a runtime
// failure does request an orderly shutdown - so it defines
// TWF_CUSTOM_PROCESS_API_WRAPS and supplies recording wrappers of its own
// (tunnel_orderly_shutdown_harness.h). Everything else here is shared.

#ifndef TWF_CUSTOM_PROCESS_API_WRAPS

_Noreturn void __wrap_terminateProgram(int exit_code);
_Noreturn void __wrap_abortProgramNow(int exit_code);
bool           __wrap_requestProgramShutdown(int exit_code);

_Noreturn void __wrap_terminateProgram(int exit_code)
{
    fprintf(stderr, "FAIL [%s]: a line-local failure called terminateProgram(%d)\n", g_twf_case, exit_code);
    fflush(stderr);
    _Exit(1);
}

_Noreturn void __wrap_abortProgramNow(int exit_code)
{
    fprintf(stderr, "FAIL [%s]: a line-local failure called abortProgramNow(%d)\n", g_twf_case, exit_code);
    fflush(stderr);
    _Exit(1);
}

bool __wrap_requestProgramShutdown(int exit_code)
{
    fprintf(stderr, "FAIL [%s]: a line-local failure called requestProgramShutdown(%d)\n", g_twf_case, exit_code);
    fflush(stderr);
    _Exit(1);
}

#endif // TWF_CUSTOM_PROCESS_API_WRAPS

// ---------------------------------------------------------------------------
// buffer accounting
// ---------------------------------------------------------------------------

enum
{
    kTwfMaxTrackedBuffers = 512
};

typedef struct twf_buffer_ledger_s
{
    sbuf_t  *live[kTwfMaxTrackedBuffers];
    uint32_t live_count;
    sbuf_t  *recycled[kTwfMaxTrackedBuffers];
    uint32_t recycled_count;
    uint32_t total_acquired;
    uint32_t total_recycled;
} twf_buffer_ledger_t;

static twf_buffer_ledger_t g_twf_buffers;

void __real_sbufDestroy(sbuf_t *b);
void __wrap_sbufDestroy(sbuf_t *b);

sbuf_t *__real_bufferpoolGetLargeBuffer(buffer_pool_t *pool);
sbuf_t *__real_bufferpoolGetSmallBuffer(buffer_pool_t *pool);
void    __real_bufferpoolReuseBuffer(buffer_pool_t *pool, sbuf_t *b);

sbuf_t *__wrap_bufferpoolGetLargeBuffer(buffer_pool_t *pool);
sbuf_t *__wrap_bufferpoolGetSmallBuffer(buffer_pool_t *pool);
void    __wrap_bufferpoolReuseBuffer(buffer_pool_t *pool, sbuf_t *b);

static void twfLedgerForget(sbuf_t **table, uint32_t *count, sbuf_t *b)
{
    for (uint32_t i = 0; i < *count; ++i)
    {
        if (table[i] == b)
        {
            table[i] = table[*count - 1U];
            --(*count);
            return;
        }
    }
}

static bool twfLedgerContains(sbuf_t *const *table, uint32_t count, const sbuf_t *b)
{
    for (uint32_t i = 0; i < count; ++i)
    {
        if (table[i] == b)
        {
            return true;
        }
    }
    return false;
}

static void twfLedgerRemember(sbuf_t **table, uint32_t *count, sbuf_t *b, const char *overflow_message)
{
    twfRequire(*count < kTwfMaxTrackedBuffers, overflow_message);
    table[(*count)++] = b;
}

static sbuf_t *twfTrackAcquired(sbuf_t *b)
{
    if (b == NULL)
    {
        return NULL;
    }

    // The pool may legitimately hand back a buffer that was recycled earlier, so it stops being a double-recycle
    // candidate the moment it is owned again.
    twfLedgerForget(g_twf_buffers.recycled, &g_twf_buffers.recycled_count, b);
    twfLedgerRemember(g_twf_buffers.live, &g_twf_buffers.live_count, b, "too many live buffers to track");
    ++g_twf_buffers.total_acquired;
    return b;
}

sbuf_t *__wrap_bufferpoolGetLargeBuffer(buffer_pool_t *pool)
{
    return twfTrackAcquired(__real_bufferpoolGetLargeBuffer(pool));
}

sbuf_t *__wrap_bufferpoolGetSmallBuffer(buffer_pool_t *pool)
{
    return twfTrackAcquired(__real_bufferpoolGetSmallBuffer(pool));
}

void __wrap_bufferpoolReuseBuffer(buffer_pool_t *pool, sbuf_t *b)
{
    twfRequire(b != NULL, "a NULL buffer was recycled");

    if (twfLedgerContains(g_twf_buffers.live, g_twf_buffers.live_count, b))
    {
        twfLedgerForget(g_twf_buffers.live, &g_twf_buffers.live_count, b);
        twfLedgerRemember(
            g_twf_buffers.recycled, &g_twf_buffers.recycled_count, b, "too many recycled buffers to track");
    }
    else
    {
        // Buffers produced by sbufSlice()/sbufReserveSpace() never came from the pool, so they are only checked
        // for a second recycle of the same pointer.
        twfRequire(! twfLedgerContains(g_twf_buffers.recycled, g_twf_buffers.recycled_count, b),
                   "a buffer was recycled twice");
        twfLedgerRemember(
            g_twf_buffers.recycled, &g_twf_buffers.recycled_count, b, "too many recycled buffers to track");
    }

    ++g_twf_buffers.total_recycled;
    __real_bufferpoolReuseBuffer(pool, b);
}

/*
 * Debug builds replace a buffer whenever ownership moves into a queue (BUFFER_WONT_BE_REUSED) and whenever
 * sbufReserveSpace() has to grow one. Both dispose of the previous allocation through sbufDestroy() rather than
 * the pool, so that is a legitimate end of life and not a leak.
 */
void __wrap_sbufDestroy(sbuf_t *b)
{
    if (b != NULL)
    {
        twfLedgerForget(g_twf_buffers.live, &g_twf_buffers.live_count, b);
        twfLedgerForget(g_twf_buffers.recycled, &g_twf_buffers.recycled_count, b);
    }
    __real_sbufDestroy(b);
}

static void twfBufferLedgerReset(void)
{
    memoryZero(&g_twf_buffers, sizeof(g_twf_buffers));
}

static void twfRequireNoLeakedBuffers(void)
{
    twfRequireEqualU32(g_twf_buffers.live_count, 0, "pooled buffers were leaked by the failure path");
}

static uint32_t twfRecycleCount(void)
{
    return g_twf_buffers.total_recycled;
}

// ---------------------------------------------------------------------------
// neighbour event trace
// ---------------------------------------------------------------------------
//
// Upstream (toward next) events are upper case, downstream (toward prev) events are lower case:
//
//   I/i Init   E/e Est   P/p Payload   F/f Finish   U/u Pause   R/r Resume

enum
{
    kTwfMaxEvents = 96
};

typedef struct twf_trace_s
{
    char     seq[kTwfMaxEvents + 1];
    uint32_t len;

    uint32_t next_init;
    uint32_t next_est;
    uint32_t next_payload;
    uint32_t next_finish;
    uint32_t prev_init;
    uint32_t prev_est;
    uint32_t prev_payload;
    uint32_t prev_finish;

    uint32_t next_payload_bytes;
    uint32_t prev_payload_bytes;

    // optional sink so a test can inspect the exact bytes a fake neighbour received
    uint8_t *capture;
    uint32_t capture_len;
    uint32_t capture_capacity;
} twf_trace_t;

static twf_trace_t *twfTrace(tunnel_t *t)
{
    return *(twf_trace_t **) tunnelGetState(t);
}

static void twfRecord(twf_trace_t *trace, char event)
{
    twfRequire(trace->len < kTwfMaxEvents, "neighbour event trace overflow");
    trace->seq[trace->len++] = event;
    trace->seq[trace->len]   = '\0';
}

static void twfCapture(twf_trace_t *trace, sbuf_t *buf)
{
    if (trace->capture == NULL)
    {
        return;
    }

    const uint32_t len = sbufGetLength(buf);
    twfRequire(trace->capture_len + len <= trace->capture_capacity, "neighbour capture buffer overflow");
    memoryCopy(trace->capture + trace->capture_len, sbufGetRawPtr(buf), len);
    trace->capture_len += len;
}

static void twfNextInit(tunnel_t *t, line_t *l)
{
    discard      l;
    twf_trace_t *trace = twfTrace(t);
    ++trace->next_init;
    twfRecord(trace, 'I');
}

static void twfNextEst(tunnel_t *t, line_t *l)
{
    discard      l;
    twf_trace_t *trace = twfTrace(t);
    ++trace->next_est;
    twfRecord(trace, 'E');
}

static void twfNextPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    twf_trace_t *trace = twfTrace(t);
    ++trace->next_payload;
    trace->next_payload_bytes += sbufGetLength(buf);
    twfCapture(trace, buf);
    twfRecord(trace, 'P');
    lineReuseBuffer(l, buf);
}

static void twfNextFinish(tunnel_t *t, line_t *l)
{
    discard      l;
    twf_trace_t *trace = twfTrace(t);
    ++trace->next_finish;
    twfRecord(trace, 'F');
}

static void twfNextPause(tunnel_t *t, line_t *l)
{
    discard l;
    twfRecord(twfTrace(t), 'U');
}

static void twfNextResume(tunnel_t *t, line_t *l)
{
    discard l;
    twfRecord(twfTrace(t), 'R');
}

static void twfPrevInit(tunnel_t *t, line_t *l)
{
    discard      l;
    twf_trace_t *trace = twfTrace(t);
    ++trace->prev_init;
    twfRecord(trace, 'i');
}

static void twfPrevEst(tunnel_t *t, line_t *l)
{
    discard      l;
    twf_trace_t *trace = twfTrace(t);
    ++trace->prev_est;
    twfRecord(trace, 'e');
}

static void twfPrevPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    twf_trace_t *trace = twfTrace(t);
    ++trace->prev_payload;
    trace->prev_payload_bytes += sbufGetLength(buf);
    twfCapture(trace, buf);
    twfRecord(trace, 'p');
    lineReuseBuffer(l, buf);
}

static void twfPrevFinish(tunnel_t *t, line_t *l)
{
    discard      l;
    twf_trace_t *trace = twfTrace(t);
    ++trace->prev_finish;
    twfRecord(trace, 'f');
}

static void twfPrevPause(tunnel_t *t, line_t *l)
{
    discard l;
    twfRecord(twfTrace(t), 'u');
}

static void twfPrevResume(tunnel_t *t, line_t *l)
{
    discard l;
    twfRecord(twfTrace(t), 'r');
}

/**
 * Wire a fake previous tunnel: it only ever receives downstream callbacks.
 */
static tunnel_t *twfCreatePrevTunnel(twf_trace_t *trace)
{
    tunnel_t *t = tunnelCreate(NULL, sizeof(twf_trace_t *), 0);
    twfRequire(t != NULL, "failed to create the fake previous tunnel");
    *(twf_trace_t **) tunnelGetState(t) = trace;

    t->fnInitD    = twfPrevInit;
    t->fnEstD     = twfPrevEst;
    t->fnPayloadD = twfPrevPayload;
    t->fnFinD     = twfPrevFinish;
    t->fnPauseD   = twfPrevPause;
    t->fnResumeD  = twfPrevResume;
    return t;
}

/**
 * Wire a fake next tunnel: it only ever receives upstream callbacks.
 */
static tunnel_t *twfCreateNextTunnel(twf_trace_t *trace)
{
    tunnel_t *t = tunnelCreate(NULL, sizeof(twf_trace_t *), 0);
    twfRequire(t != NULL, "failed to create the fake next tunnel");
    *(twf_trace_t **) tunnelGetState(t) = trace;

    t->fnInitU    = twfNextInit;
    t->fnEstU     = twfNextEst;
    t->fnPayloadU = twfNextPayload;
    t->fnFinU     = twfNextFinish;
    t->fnPauseU   = twfNextPause;
    t->fnResumeU  = twfNextResume;
    return t;
}

// ---------------------------------------------------------------------------
// worker environment
// ---------------------------------------------------------------------------

typedef struct twf_worker_env_s
{
    master_pool_t *large_master;
    master_pool_t *small_master;
    buffer_pool_t *pool;
    buffer_pool_t *pool_shortcut[1];
    wloop_t       *loop;
    wloop_t       *loop_shortcut[1];
} twf_worker_env_t;

enum
{
    kTwfDefaultSmallBufferSize = 1024
};

/**
 * Publish a single-worker environment: one buffer pool and one real event loop, both reachable through the
 * GSTATE shortcuts that lineGetBufferPool() and getWorkerLoop() use.
 *
 * @param left_padding left padding every pooled buffer must reserve, mirroring what the chain would have summed
 *                     from the nodes' required_padding_left. Tunnels that prepend headers need it.
 * @param small_buffer_size small-buffer size. Packet-side tunnels validate this against
 *                          kMaxAllowedPacketLength, so they need more than the default.
 */
static void twfWorkerEnvSetupWithSmallBuffers(twf_worker_env_t *env, uint32_t large_buffer_size,
                                              uint32_t small_buffer_size, uint16_t left_padding)
{
    memoryZero(env, sizeof(*env));

    GSTATE.workers_count = 1;

    env->large_master = masterpoolCreateWithCapacity(8);
    env->small_master = masterpoolCreateWithCapacity(8);
    twfRequire(env->large_master != NULL && env->small_master != NULL, "failed to create the test master pools");

    env->pool = bufferpoolCreate(env->large_master, env->small_master, 4, large_buffer_size, small_buffer_size);
    twfRequire(env->pool != NULL, "failed to create the test buffer pool");

    // Must happen before any buffer leaves the pool, exactly like the runtime does it during chain finalization.
    bufferpoolUpdateAllocationPaddings(env->pool, left_padding, left_padding);

    env->pool_shortcut[0]        = env->pool;
    GSTATE.shortcut_buffer_pools = env->pool_shortcut;

    env->loop = wloopCreate(WLOOP_FLAG_AUTO_FREE, env->pool, 0);
    twfRequire(env->loop != NULL, "failed to create the test event loop");

    env->loop_shortcut[0] = env->loop;
    GSTATE.shortcut_loops = env->loop_shortcut;

    twfBufferLedgerReset();
}

static void twfWorkerEnvSetup(twf_worker_env_t *env, uint32_t large_buffer_size, uint16_t left_padding)
{
    twfWorkerEnvSetupWithSmallBuffers(env, large_buffer_size, kTwfDefaultSmallBufferSize, left_padding);
}

// ---------------------------------------------------------------------------
// lines
// ---------------------------------------------------------------------------

/**
 * Allocate a bare line big enough for one tunnel's line state. The tests drive callbacks directly, so no chain
 * indexing runs and the tunnel under test keeps line-state offset zero.
 */
static line_t *twfLineCreate(uint32_t lstate_size)
{
    line_t *l = memoryAllocateCacheAlignedZero(sizeof(line_t) + lstate_size);
    twfRequire(l != NULL, "failed to allocate a test line");
    atomic_init(&l->refc, 1);
    l->alive = true;
    l->wid   = 0;
    return l;
}

static uint32_t twfLineRefCount(const line_t *l)
{
    return (uint32_t) atomicLoadRelaxed(&((line_t *) (uintptr_t) l)->refc);
}

static void twfLineDestroy(line_t *l)
{
    addresscontextReset(&l->routing_context.src_ctx);
    addresscontextReset(&l->routing_context.dest_ctx);
    lineClearUsers(l);
    memoryFreeAligned(l);
}

/**
 * Require that a tunnel's line state is entirely zero, which is the terminal shape every LinestateDestroy() and
 * every failing LinestateInitialize() must leave behind.
 */
static void twfRequireLineStateZeroed(const line_t *l, const tunnel_t *t, const char *message)
{
    const uint8_t *state = (const uint8_t *) lineGetState((line_t *) (uintptr_t) l, (tunnel_t *) (uintptr_t) t);
    for (uint32_t i = 0; i < t->lstate_size; ++i)
    {
        twfRequire(state[i] == 0, message);
    }
}

// ---------------------------------------------------------------------------
// pool-backed lines
// ---------------------------------------------------------------------------
//
// twfLineCreate() hands out a bare allocation, which is enough for a test that
// only drives callbacks. A test of the owner Finish postcondition cannot use it:
// lineDestroy() returns the line to line->pools[wid], so the line has to come
// from a real generic pool the same way the runtime's does.

typedef struct twf_line_pool_s
{
    master_pool_t  *master;
    generic_pool_t *pools[1];
} twf_line_pool_t;

/**
 * Publish a single-worker line pool sized for one tunnel's line state.
 *
 * @param lstate_size the tunnel's lstate_size; the tests drive callbacks directly, so no chain indexing runs and
 *                    the tunnel under test keeps line-state offset zero.
 */
static void twfLinePoolSetup(twf_line_pool_t *lp, uint32_t lstate_size, uint32_t capacity)
{
    memoryZero(lp, sizeof(*lp));

    lp->master = masterpoolCreateWithCapacity(2 * capacity);
    twfRequire(lp->master != NULL, "failed to create the test line master pool");

    lp->pools[0] = genericpoolCreateWithDefaultCacheAlignedAllocatorAndCapacity(
        lp->master, sizeof(line_t) + lstate_size, capacity);
    twfRequire(lp->pools[0] != NULL, "failed to create the test line pool");
}

static line_t *twfLinePoolCreateLine(twf_line_pool_t *lp)
{
    line_t *l = lineCreateForWorker(0, lp->pools, 0);
    twfRequire(l != NULL, "failed to create a pooled test line");
    return l;
}

/**
 * Release the pool. Every line taken from it must already have been reclaimed, which for a line the test still
 * holds means lineDestroy() plus the matching lineUnlock().
 */
static void twfLinePoolTeardown(twf_line_pool_t *lp)
{
    genericpoolDestroy(lp->pools[0]);
    masterpoolDestroy(lp->master);
}

// ---------------------------------------------------------------------------
// the owner Finish postcondition
// ---------------------------------------------------------------------------

typedef void (*TwfOwnerFinishFn)(tunnel_t *t, line_t *l);

/**
 * Run an owner's Finish handler the way a re-entrant caller does, and require the postcondition:
 *
 *     lineLock(line); owner_finish(owner, line); assert(! lineIsAlive(line)); lineUnlock(line);
 *
 * The outer lock is what makes the assertion legal at all - it keeps the allocation present past the owner's
 * lineDestroy(), which is exactly the frame the contract exists to protect. The caller still owns that reference
 * afterwards and releases it with twfRequireOwnedLineReclaimed().
 *
 * @param t the owner tunnel, used to check that its line state was destroyed too.
 */
static void twfRunOwnerFinish(tunnel_t *t, line_t *l, TwfOwnerFinishFn finish, const char *what)
{
    char message[192];

    twfRequire(lineIsAlive(l), "the line must be alive before the owner's Finish handler runs");
    lineLock(l);

    finish(t, l);

    snprintf(message, sizeof(message), "%s returned with its owned line still alive", what);
    twfRequire(! lineIsAlive(l), message);

    snprintf(message, sizeof(message), "%s left its own line state behind", what);
    twfRequireLineStateZeroed(l, t, message);
}

/**
 * Drop the reference twfRunOwnerFinish() took and require that it was the last one, which is what proves the
 * owner dropped the creator's reference exactly once.
 *
 * The line goes back to its pool here, so @p l is dangling on return. A caller that keeps the pointer in a
 * fixture must clear it before any teardown that would inspect it.
 */
static void twfRequireOwnedLineReclaimed(line_t *l, const char *what)
{
    char message[192];

    snprintf(message,
             sizeof(message),
             "%s did not leave exactly the caller's reference; a duplicate or missing lineDestroy()",
             what);
    twfRequireEqualU32(twfLineRefCount(l), 1, message);

    lineUnlock(l);
}

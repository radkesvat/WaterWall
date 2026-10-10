#pragma once

/* Explicit worker-zero pools/loop and normal-line fixtures. The scenario owns line shutdown and visible teardown. */
#include "fixtures/buffer_ledger.h"
#include "fixtures/splice_inventory.h"
#include "wevent.h"
#include "wwapi.h"

// ---------------------------------------------------------------------------
// worker environment
// ---------------------------------------------------------------------------

typedef struct twf_worker_env_s
{
    master_pool_t             *large_master;
    master_pool_t             *small_master;
    master_pool_t             *medium_master;
    master_pool_t             *splice_master;
    master_pool_t             *wios_master;
    buffer_pool_t             *pool;
    buffer_pool_t             *pool_shortcut[1];
    threadsafe_generic_pool_t *wios_pool;
    threadsafe_generic_pool_t *wios_shortcut[1];
    wloop_t                   *loop;
    wloop_t                   *loop_shortcut[1];
    worker_t                   worker;
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
static void twfWorkerEnvSetupWithBufferSizes(twf_worker_env_t *env, uint32_t large_buffer_size,
                                             uint32_t small_buffer_size, uint16_t left_padding, uint32_t splice_limit,
                                             uint32_t waiting_budget_basis)
{
    memoryZero(env, sizeof(*env));
    testSpliceInventoryInitialize(left_padding);

    GSTATE.flag_initialized = true;

    // The total is exactly the number of event workers.
    GSTATE.workers_count = 1;

    env->large_master  = masterpoolCreateWithCapacity(8);
    env->small_master  = masterpoolCreateWithCapacity(8);
    env->medium_master = masterpoolCreateWithCapacity(8);
    env->splice_master = masterpoolCreateWithCapacity(8);
    env->wios_master   = masterpoolCreateWithCapacity(8);
    twfRequire(env->large_master != NULL && env->small_master != NULL && env->wios_master != NULL,
               "failed to create the test master pools");

    env->pool = bufferpoolCreate(env->large_master,
                                 env->medium_master,
                                 env->small_master,
                                 4,
                                 large_buffer_size,
                                 MEDIUM_BUFFER_SIZE_RAM_HIGH,
                                 small_buffer_size,
                                 splice_limit,
                                 waiting_budget_basis);
    twfRequire(env->pool != NULL, "failed to create the test buffer pool");

    // Must happen before any buffer leaves the pool, exactly like the runtime does it during chain finalization.
    bufferpoolUpdateAllocationPaddings(env->pool, left_padding, left_padding, left_padding, left_padding);

    env->pool_shortcut[0]        = env->pool;
    GSTATE.shortcut_buffer_pools = env->pool_shortcut;

    env->wios_pool = threadsafegenericpoolCreateWithDefaultAllocatorAndCapacity(env->wios_master, sizeof(wio_t), 8);
    twfRequire(env->wios_pool != NULL, "failed to create the test wios pool");
    env->wios_shortcut[0]      = env->wios_pool;
    GSTATE.shortcut_wios_pools = env->wios_shortcut;

    env->loop = wloopCreate(WLOOP_FLAG_AUTO_FREE, env->pool, 0);
    twfRequire(env->loop != NULL, "failed to create the test event loop");

    env->loop_shortcut[0] = env->loop;
    GSTATE.shortcut_loops = env->loop_shortcut;

    env->worker = (worker_t) {
        .wid = 0, .buffer_pool = env->pool, .wios_pool = env->wios_pool, .loop = env->loop, .has_event_loop = true};
    GSTATE.workers = &env->worker;
    testWorkerBindWID(0);

    twfBufferLedgerReset();
}

static void twfWorkerEnvSetupWithSmallBuffers(twf_worker_env_t *env, uint32_t large_buffer_size,
                                              uint32_t small_buffer_size, uint16_t left_padding)
{
    twfWorkerEnvSetupWithBufferSizes(env,
                                     large_buffer_size,
                                     small_buffer_size,
                                     left_padding,
                                     min(large_buffer_size, (uint32_t) SPLICE_PAYLOAD_LIMIT),
                                     large_buffer_size);
}

static void twfWorkerEnvSetup(twf_worker_env_t *env, uint32_t large_buffer_size, uint16_t left_padding)
{
    twfWorkerEnvSetupWithSmallBuffers(env, large_buffer_size, kTwfDefaultSmallBufferSize, left_padding);
}

static void twfWorkerEnvTeardown(twf_worker_env_t *env)
{
    twfRequireNoLeakedBuffers();

    wloopDestroy(&env->loop);
    testWorkerUnbindWID();
    GSTATE.flag_initialized      = false;
    GSTATE.workers               = NULL;
    GSTATE.shortcut_buffer_pools = NULL;
    GSTATE.shortcut_wios_pools   = NULL;
    GSTATE.shortcut_loops        = NULL;

    threadsafegenericpoolDestroy(env->wios_pool);
    bufferpoolDestroy(env->pool);
    masterpoolMakeEmpty(env->large_master);
    masterpoolMakeEmpty(env->small_master);
    masterpoolMakeEmpty(env->medium_master);
    masterpoolMakeEmpty(env->splice_master);
    masterpoolMakeEmpty(env->wios_master);
    masterpoolDestroy(env->large_master);
    masterpoolDestroy(env->small_master);
    masterpoolDestroy(env->medium_master);
    masterpoolDestroy(env->splice_master);
    masterpoolDestroy(env->wios_master);
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
    return (uint32_t) atomicLoadU32Relaxed(&((line_t *) (uintptr_t) l)->refc);
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
 * holds means lineDestroy() plus the matching lineUnref().
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
 *     lineRef(line); owner_finish(owner, line); assert(! lineIsAlive(line)); lineUnref(line);
 *
 * The outer reference is what makes the assertion legal at all - it keeps the allocation present past the owner's
 * lineDestroy(), which is exactly the frame the contract exists to protect. The caller still owns that reference
 * afterwards and releases it with twfRequireOwnedLineReclaimed().
 *
 * @param t the owner tunnel, used to check that its line state was destroyed too.
 */
static void twfRunOwnerFinish(tunnel_t *t, line_t *l, TwfOwnerFinishFn finish, const char *what)
{
    char message[192];

    twfRequire(lineIsAlive(l), "the line must be alive before the owner's Finish handler runs");
    lineRef(l);

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

    lineUnref(l);
}

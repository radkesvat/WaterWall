/*
 * Covers: timer reset lifetime; the explicit inputs, callbacks and expected results below define this suite.
 * Setup: Isolated wloop and timer APIs with real collection/dispatch and heap/pooled memory tracking.
 * Cases: Scheduled reset, pending reset kept, self-rearm, self-reset then delete, other pending different/same
 * priority, multiple pending resets kept/cancelled, finite repetition, repeating self-rearm, infinite repetition,
 * allocation during cancellation, and shutdown/quiescence routes.
 * Checks: Assertion labels include: timer installation failed; timer lost pool provenance; reset must keep pending;
 * replacement timer must not reuse pending timer storage; quiescence recycled timers before owner drain.
 * Limits: Component fixtures do not establish host-network or application-throughput behavior.
 * CTest: waterwall.timer_reset_lifetime_unit
 */
#include "ev_memory.h"
#include "test_assert.h"

#define require(condition, message) TEST_REQUIRE(TEST_FAILURE_EXIT, condition, message)

#include "fixtures/worker_registry_fixture.h"
#include "wevent.h"
#include "wloop_internal.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef enum
{
    TEST_MODE_HEAP,
    TEST_MODE_POOLED
} test_mode_t;

typedef struct
{
    test_mode_t     mode;
    master_pool_t  *master;
    generic_pool_t *pool;
    wloop_t        *loop;
    long            alloc_baseline;
} test_fixture_t;

static unsigned int s_unexpected_calls;
static void         unexpectedTimer(wtimer_t *timer)
{
    discard timer;
    ++s_unexpected_calls;
    require(false, "an unexpected or cancelled timer ran");
}

static void fixtureInit(test_fixture_t *fix, test_mode_t mode)
{
    memset(fix, 0, sizeof(*fix));
    fix->mode           = mode;
    fix->alloc_baseline = eventloopAllocCount() - eventloopFreeCount();
    if (mode == TEST_MODE_POOLED)
    {
        fix->master = masterpoolCreateWithCapacity(32);
        fix->pool   = genericpoolCreateWithDefaultAllocatorAndCapacity(fix->master, sizeof(wtimeout_t), 16);
        require(fix->master && fix->pool, "pool construction failed");
    }
    fix->loop = wloopCreate(0, NULL, 0);
    require(fix->loop != NULL, "loop creation failed");
    if (mode == TEST_MODE_POOLED)
    {
        fix->loop->timer_pool = fix->pool;
    }
    atomicStoreExplicit(&fix->loop->status, WLOOP_STATUS_RUNNING, memory_order_release);
}

static void fixtureCleanup(test_fixture_t *fix)
{
    if (fix->loop)
    {
        wloopDestroy(&fix->loop);
    }
    if (fix->mode == TEST_MODE_POOLED)
    {
        if (fix->pool)
        {
            genericpoolDestroy(fix->pool);
        }
        if (fix->master)
        {
            require(masterpoolGetCheckedOut(fix->master) == 0, "storage remained checked out from master pool");
            masterpoolMakeEmpty(fix->master);
            masterpoolDestroy(fix->master);
        }
    }
    require(eventloopAllocCount() - eventloopFreeCount() == fix->alloc_baseline, "fixture leaked heap memory");
}

static wtimer_t *addTimer(test_fixture_t *fix, wtimer_cb cb, uint32_t timeout_ms, uint32_t repeat)
{
    wtimer_t *timer = wtimerAdd(fix->loop, cb, timeout_ms, repeat);
    require(timer != NULL, "timer creation failed");
    if (fix->mode == TEST_MODE_POOLED)
    {
        require(timer->allocation_pool == fix->pool, "timer lost pool provenance");
    }
    else
    {
        require(timer->allocation_pool == NULL, "heap timer has unexpected pool provenance");
    }
    return timer;
}

static void makeTimerDue(wloop_t *loop, wtimer_t *timer, uint64_t due_hrtime)
{
    heap_remove(&loop->timers, &timer->node);
    timer->next_timeout = due_hrtime;
    heap_insert(&loop->timers, &timer->node);
}

static void makeTimerDueNow(wloop_t *loop, wtimer_t *timer)
{
    wloopUpdateTime(loop);
    uint64_t now = loop->cur_hrtime;
    uint64_t due = now > 1000 ? now - 1000 : 0;
    makeTimerDue(loop, timer, due);
}

static void makeTimersDueBatch(wloop_t *loop, wtimer_t **timers, const uint64_t *offsets_us, size_t count)
{
    wloopUpdateTime(loop);
    uint64_t now  = loop->cur_hrtime;
    uint64_t base = now > 20000 ? now - 20000 : 0;
    for (size_t i = 0; i < count; ++i)
    {
        uint64_t offset = (offsets_us != NULL) ? offsets_us[i] : 0;
        makeTimerDue(loop, timers[i], base + offset);
    }
}

/* ========================================================================= */
/* Section 6 Scenario 1: Scheduled reset                                     */
/* ========================================================================= */

struct case1_ctx
{
    int target_calls;
    int unrelated_calls;
};

static void case1TargetCb(wtimer_t *timer)
{
    struct case1_ctx *ctx = (struct case1_ctx *) timer->userdata;
    ctx->target_calls++;
}

static void case1UnrelatedCb(wtimer_t *timer)
{
    struct case1_ctx *ctx = (struct case1_ctx *) timer->userdata;
    ctx->unrelated_calls++;
}

static void testScheduledReset(void)
{
    struct case1_ctx ctx = {0};
    test_fixture_t   fix;
    fixtureInit(&fix, TEST_MODE_HEAP);

    wloopUpdateTime(fix.loop);
    wtimer_t *unrelated = addTimer(&fix, case1UnrelatedCb, 50000, 1);
    unrelated->userdata = &ctx;

    wtimer_t *target = addTimer(&fix, case1TargetCb, 20000, 1);
    target->userdata = &ctx;

    require(fix.loop->ntimers == 2, "initial ntimers");
    require(wloopNActives(fix.loop) == 2, "initial nactives");
    uint64_t unrelated_deadline = unrelated->next_timeout;

    wloopUpdateTime(fix.loop);
    uint64_t reset_base_us = fix.loop->cur_hrtime;

    bool ok = wtimerReset(target, 40000);
    require(ok, "scheduled reset must succeed");

    uint64_t expected_deadline = ((reset_base_us + UINT64_C(40000000)) / UINT64_C(100000)) * UINT64_C(100000);

    require(fix.loop->ntimers == 2, "reset does not alter ntimers");
    require(wloopNActives(fix.loop) == 2, "reset does not alter nactives");
    require(unrelated->next_timeout == unrelated_deadline, "unrelated deadline unchanged");
    require(((wtimeout_t *) target)->timeout == 40000, "target timeout updated");
    require(target->next_timeout == expected_deadline, "target deadline rounded to 100ms");
    require(! target->destroy, "target destroy clear");
    require(! target->pending, "target pending clear");
    require(! target->pending_reset, "target pending_reset clear");

    /* Step 1: Pump when neither timer is due */
    wloopProcessEvents(fix.loop, 0);
    require(ctx.target_calls == 0, "target not due yet");
    require(ctx.unrelated_calls == 0, "unrelated not due yet");
    require(fix.loop->ntimers == 2, "both timers remain scheduled");

    /* Step 2: Force target due; unrelated remains scheduled */
    makeTimerDueNow(fix.loop, target);
    wloopProcessEvents(fix.loop, 0);
    require(ctx.target_calls == 1, "target delivered once");
    require(ctx.unrelated_calls == 0, "unrelated still not due");
    require(fix.loop->ntimers == 1, "target retired");

    /* Step 3: Force unrelated due */
    makeTimerDueNow(fix.loop, unrelated);
    wloopProcessEvents(fix.loop, 0);
    require(ctx.unrelated_calls == 1, "unrelated delivered once");
    require(fix.loop->ntimers == 0, "unrelated retired");

    fixtureCleanup(&fix);
}

/* ========================================================================= */
/* Section 6 Scenario 2: Pending reset kept                                  */
/* ========================================================================= */

struct case2_ctx
{
    wtimer_t *ctrl;
    wtimer_t *target;
    wtimer_t *unrelated;
    int       ctrl_calls;
    int       target_calls;
    int       unrelated_calls;
    bool      target_was_pending_in_ctrl;
    bool      target_pending_after_reset;
    bool      target_pending_reset_after_reset;
};

static void case2CtrlCb(wtimer_t *timer)
{
    struct case2_ctx *ctx = (struct case2_ctx *) timer->userdata;
    ctx->ctrl_calls++;

    ctx->target_was_pending_in_ctrl = ctx->target->pending;
    require(ctx->target->pending, "target must be pending in controller callback");
    require(ctx->unrelated->pending, "unrelated must be pending in controller callback");

    bool ok = wtimerReset(ctx->target, 10000);
    require(ok, "reset of pending target must succeed");

    ctx->target_pending_after_reset       = ctx->target->pending;
    ctx->target_pending_reset_after_reset = ctx->target->pending_reset;
    require(ctx->target->pending, "target pending must survive reset");
    require(ctx->target->pending_reset, "target pending_reset must be set");
    require(ctx->target->active, "target must remain active");
    require(! ctx->target->destroy, "target destroy must remain clear");
}

static void case2TargetCb(wtimer_t *timer)
{
    struct case2_ctx *ctx = (struct case2_ctx *) timer->userdata;
    ctx->target_calls++;
}

static void case2UnrelatedCb(wtimer_t *timer)
{
    struct case2_ctx *ctx = (struct case2_ctx *) timer->userdata;
    ctx->unrelated_calls++;
}

static void testPendingResetKept(void)
{
    struct case2_ctx ctx = {0};
    test_fixture_t   fix;
    fixtureInit(&fix, TEST_MODE_HEAP);

    ctx.ctrl      = addTimer(&fix, case2CtrlCb, 1000, 1);
    ctx.target    = addTimer(&fix, case2TargetCb, 1000, 1);
    ctx.unrelated = addTimer(&fix, case2UnrelatedCb, 1000, 1);

    ctx.ctrl->userdata      = &ctx;
    ctx.target->userdata    = &ctx;
    ctx.unrelated->userdata = &ctx;

    weventSetPriority(ctx.ctrl, WEVENT_HIGHEST_PRIORITY);
    weventSetPriority(ctx.target, WEVENT_NORMAL_PRIORITY);
    weventSetPriority(ctx.unrelated, WEVENT_LOWEST_PRIORITY);

    wtimer_t *timers[3] = {ctx.ctrl, ctx.target, ctx.unrelated};
    makeTimersDueBatch(fix.loop, timers, NULL, 3);

    wloopProcessEvents(fix.loop, 0);

    require(ctx.ctrl_calls == 1, "ctrl ran once");
    require(ctx.target_was_pending_in_ctrl, "target was pending");
    require(ctx.target_pending_after_reset, "target remained pending after reset");
    require(ctx.target_pending_reset_after_reset, "target had pending_reset set");
    require(ctx.target_calls == 0, "old target callback suppressed");
    require(ctx.unrelated_calls == 1, "unrelated due timer ran once");

    /* Pending reference released after dispatch completes */
    require(! ctx.target->pending, "target pending cleared after dispatch");
    require(! ctx.target->pending_reset, "target pending_reset cleared after dispatch");
    require(ctx.target->active, "target remains active");
    require(! ctx.target->destroy, "target destroy clear");
    require(fix.loop->ntimers == 1, "target remains in heap");

    /* Move target deadline into past to force delivery of replacement */
    makeTimerDueNow(fix.loop, ctx.target);
    wloopProcessEvents(fix.loop, 0);

    require(ctx.target_calls == 1, "replacement target fired once");
    require(fix.loop->ntimers == 0, "all timers retired");

    fixtureCleanup(&fix);
}

/* ========================================================================= */
/* Section 6 Scenario 3: Self-rearm                                         */
/* ========================================================================= */

struct case3_ctx
{
    int  calls;
    bool pending_in_first_cb;
    bool repeat_zero_in_first_cb;
    bool pending_after_rearm;
    bool pending_reset_after_rearm;
};

static void case3Cb(wtimer_t *timer)
{
    struct case3_ctx *ctx = (struct case3_ctx *) timer->userdata;
    ctx->calls++;
    if (ctx->calls == 1)
    {
        ctx->pending_in_first_cb     = timer->pending;
        ctx->repeat_zero_in_first_cb = (timer->repeat == 0);
        require(timer->pending, "timer must be pending in callback");
        require(timer->repeat == 0, "one-shot timer must enter callback with repeat == 0");

        bool ok = wtimerReset(timer, 5000);
        require(ok, "self reset must succeed");

        ctx->pending_after_rearm       = timer->pending;
        ctx->pending_reset_after_rearm = timer->pending_reset;
        require(timer->repeat == 1, "reset must revive repeat count to 1");
        require(timer->pending, "timer pending preserved");
        require(timer->pending_reset, "pending_reset set");
        require(timer->active, "timer remains active");
        require(! timer->destroy, "destroy remains clear");
    }
}

static void testSelfRearm(void)
{
    struct case3_ctx ctx = {0};
    test_fixture_t   fix;
    fixtureInit(&fix, TEST_MODE_HEAP);

    wtimer_t *timer = addTimer(&fix, case3Cb, 1000, 1);
    timer->userdata = &ctx;

    makeTimerDueNow(fix.loop, timer);

    /* First dispatch: fires, revives itself */
    wloopProcessEvents(fix.loop, 0);

    require(ctx.calls == 1, "first callback completed once");
    require(ctx.pending_in_first_cb, "pending in first callback");
    require(ctx.repeat_zero_in_first_cb, "repeat was 0 before reset");
    require(ctx.pending_after_rearm, "pending after rearm");
    require(ctx.pending_reset_after_rearm, "pending_reset after rearm");

    /* After dispatch finishes, pending markers cleared, timer remains scheduled */
    require(! timer->pending, "pending cleared after dispatch");
    require(! timer->pending_reset, "pending_reset cleared after dispatch");
    require(timer->active, "timer remains active");
    require(! timer->destroy, "destroy remains clear");
    require(fix.loop->ntimers == 1, "timer remains scheduled in heap");

    /* Second occurrence: force due and dispatch */
    makeTimerDueNow(fix.loop, timer);
    wloopProcessEvents(fix.loop, 0);

    require(ctx.calls == 2, "second occurrence delivered once");
    require(fix.loop->ntimers == 0, "timer retired after second delivery");

    fixtureCleanup(&fix);
}

/* ========================================================================= */
/* Section 6 Scenario 4: Self-reset then delete                              */
/* ========================================================================= */

struct case4_ctx
{
    test_fixture_t *fix;
    int             calls;
    long            alloc_before;
    long            alloc_in_cb_after_del;
    size_t          pool_checked_out_in_cb;
    bool            pending_before_del;
};

static void case4Cb(wtimer_t *timer)
{
    struct case4_ctx *ctx = (struct case4_ctx *) timer->userdata;
    ctx->calls++;

    require(timer->pending, "timer must be pending in callback");
    bool ok = wtimerReset(timer, 5000);
    require(ok, "reset must succeed");
    require(timer->pending, "pending preserved");
    require(timer->pending_reset, "pending_reset set");

    ctx->pending_before_del = timer->pending;

    /* Delete timer after resetting it */
    wtimerDelete(timer);

    /* Storage must still be valid and held by dispatch */
    ctx->alloc_in_cb_after_del = eventloopAllocCount() - eventloopFreeCount();
    if (ctx->fix->mode == TEST_MODE_POOLED)
    {
        ctx->pool_checked_out_in_cb = masterpoolGetCheckedOut(ctx->fix->master);
    }
    /* Do NOT touch timer after wtimerDelete */
}

static void testSelfResetThenDelete(test_mode_t mode)
{
    struct case4_ctx ctx = {0};
    test_fixture_t   fix;
    fixtureInit(&fix, mode);
    ctx.fix          = &fix;
    ctx.alloc_before = eventloopAllocCount() - eventloopFreeCount();

    wtimer_t *timer = addTimer(&fix, case4Cb, 1000, 1);
    timer->userdata = &ctx;

    if (mode == TEST_MODE_HEAP)
    {
        require(eventloopAllocCount() - eventloopFreeCount() == ctx.alloc_before + 1, "heap allocated for timer");
    }
    else
    {
        require(masterpoolGetCheckedOut(fix.master) == 1, "timer checked out from pool");
    }

    makeTimerDueNow(fix.loop, timer);
    wloopProcessEvents(fix.loop, 0);

    require(ctx.calls == 1, "callback ran once");
    require(ctx.pending_before_del, "pending before del");
    if (mode == TEST_MODE_HEAP)
    {
        require(ctx.alloc_in_cb_after_del == ctx.alloc_before + 1, "storage held during callback");
        require(eventloopAllocCount() - eventloopFreeCount() == ctx.alloc_before, "storage released after dispatch");
    }
    else
    {
        require(ctx.pool_checked_out_in_cb == 1, "storage checked out during callback");
        require(masterpoolGetCheckedOut(fix.master) == 0, "storage returned to pool after dispatch");
    }
    require(fix.loop->ntimers == 0, "ntimers is 0");
    require(wloopNActives(fix.loop) == 0, "nactives is 0");

    /* No later callback delivered */
    wloopProcessEvents(fix.loop, 0);
    require(ctx.calls == 1, "no subsequent delivery");

    fixtureCleanup(&fix);
}

/* ========================================================================= */
/* Section 6 Scenario 5: Other pending timer, higher priority               */
/* ========================================================================= */

struct case5_ctx
{
    test_fixture_t *fix;
    wtimer_t       *ctrl;
    wtimer_t       *target;
    wtimer_t       *unrelated;
    int             ctrl_calls;
    int             target_calls;
    int             unrelated_calls;
    long            alloc_before;
    long            alloc_in_ctrl_after_del;
    size_t          pool_checked_out_in_ctrl;
};

static void case5CtrlCb(wtimer_t *timer)
{
    struct case5_ctx *ctx = (struct case5_ctx *) timer->userdata;
    ctx->ctrl_calls++;

    require(ctx->target->pending, "target must be pending");
    bool ok = wtimerReset(ctx->target, 5000);
    require(ok, "reset of target must succeed");
    require(ctx->target->pending && ctx->target->pending_reset, "pending and pending_reset set");

    wtimerDelete(ctx->target);
    ctx->alloc_in_ctrl_after_del = eventloopAllocCount() - eventloopFreeCount();
    if (ctx->fix->mode == TEST_MODE_POOLED)
    {
        ctx->pool_checked_out_in_ctrl = masterpoolGetCheckedOut(ctx->fix->master);
    }
}

static void case5TargetCb(wtimer_t *timer)
{
    struct case5_ctx *ctx = (struct case5_ctx *) timer->userdata;
    ctx->target_calls++;
}

static void case5UnrelatedCb(wtimer_t *timer)
{
    struct case5_ctx *ctx = (struct case5_ctx *) timer->userdata;
    ctx->unrelated_calls++;
}

static void testOtherPendingDifferentPriority(test_mode_t mode)
{
    struct case5_ctx ctx = {0};
    test_fixture_t   fix;
    fixtureInit(&fix, mode);
    ctx.fix          = &fix;
    ctx.alloc_before = eventloopAllocCount() - eventloopFreeCount();

    ctx.ctrl      = addTimer(&fix, case5CtrlCb, 1000, 1);
    ctx.target    = addTimer(&fix, case5TargetCb, 1000, 1);
    ctx.unrelated = addTimer(&fix, case5UnrelatedCb, 1000, 1);

    ctx.ctrl->userdata      = &ctx;
    ctx.target->userdata    = &ctx;
    ctx.unrelated->userdata = &ctx;

    weventSetPriority(ctx.ctrl, WEVENT_HIGHEST_PRIORITY);
    weventSetPriority(ctx.target, WEVENT_NORMAL_PRIORITY);
    weventSetPriority(ctx.unrelated, WEVENT_LOWEST_PRIORITY);

    wtimer_t *timers[3] = {ctx.ctrl, ctx.target, ctx.unrelated};
    makeTimersDueBatch(fix.loop, timers, NULL, 3);

    wloopProcessEvents(fix.loop, 0);

    require(ctx.ctrl_calls == 1, "ctrl ran once");
    require(ctx.target_calls == 0, "target suppressed");
    require(ctx.unrelated_calls == 1, "unrelated ran once");

    if (mode == TEST_MODE_HEAP)
    {
        require(ctx.alloc_in_ctrl_after_del == ctx.alloc_before + 3, "target not freed prematurely in ctrl");
        require(eventloopAllocCount() - eventloopFreeCount() == ctx.alloc_before, "all timers freed after dispatch");
    }
    else
    {
        require(ctx.pool_checked_out_in_ctrl == 3, "3 timers checked out in ctrl");
        require(masterpoolGetCheckedOut(fix.master) == 0, "all timers returned to pool");
    }
    require(fix.loop->ntimers == 0, "ntimers is 0");
    require(wloopNActives(fix.loop) == 0, "nactives is 0");

    wloopProcessEvents(fix.loop, 0);
    require(ctx.target_calls == 0, "target never fires");

    fixtureCleanup(&fix);
}

/* ========================================================================= */
/* Section 6 Scenario 6: Other pending timer, same priority                  */
/* ========================================================================= */

struct case6_same_prio_ctx
{
    test_fixture_t *fix;
    wtimer_t       *ctrl;
    wtimer_t       *target;
    wtimer_t       *unrelated;
    int             ctrl_calls;
    int             target_calls;
    int             unrelated_calls;
    long            alloc_before;
    long            alloc_in_ctrl_after_del;
    size_t          pool_checked_out_in_ctrl;
};

static void case6SamePrioCtrlCb(wtimer_t *timer)
{
    struct case6_same_prio_ctx *ctx = (struct case6_same_prio_ctx *) timer->userdata;
    ctx->ctrl_calls++;

    /* Verify cached-next pointer chain: ctrl -> target -> unrelated */
    require(timer->pending_next == (wevent_t *) ctx->target, "ctrl must point to target in pending chain");
    require(ctx->target->pending_next == (wevent_t *) ctx->unrelated,
            "target must point to unrelated in pending chain");
    require(ctx->target->pending, "target must be pending");
    require(ctx->unrelated->pending, "unrelated must be pending");

    bool ok = wtimerReset(ctx->target, 5000);
    require(ok, "reset of target must succeed");
    require(ctx->target->pending && ctx->target->pending_reset, "pending and pending_reset set");

    wtimerDelete(ctx->target);

    ctx->alloc_in_ctrl_after_del = eventloopAllocCount() - eventloopFreeCount();
    if (ctx->fix->mode == TEST_MODE_POOLED)
    {
        ctx->pool_checked_out_in_ctrl = masterpoolGetCheckedOut(ctx->fix->master);
    }
}

static void case6SamePrioTargetCb(wtimer_t *timer)
{
    struct case6_same_prio_ctx *ctx = (struct case6_same_prio_ctx *) timer->userdata;
    ctx->target_calls++;
}

static void case6SamePrioUnrelatedCb(wtimer_t *timer)
{
    struct case6_same_prio_ctx *ctx = (struct case6_same_prio_ctx *) timer->userdata;
    ctx->unrelated_calls++;
}

static void testOtherPendingSamePriority(test_mode_t mode)
{
    struct case6_same_prio_ctx ctx = {0};
    test_fixture_t             fix;
    fixtureInit(&fix, mode);
    ctx.fix          = &fix;
    ctx.alloc_before = eventloopAllocCount() - eventloopFreeCount();

    ctx.unrelated = addTimer(&fix, case6SamePrioUnrelatedCb, 1000, 1);
    ctx.target    = addTimer(&fix, case6SamePrioTargetCb, 1000, 1);
    ctx.ctrl      = addTimer(&fix, case6SamePrioCtrlCb, 1000, 1);

    ctx.ctrl->userdata      = &ctx;
    ctx.target->userdata    = &ctx;
    ctx.unrelated->userdata = &ctx;

    weventSetPriority(ctx.unrelated, WEVENT_HIGHEST_PRIORITY);
    weventSetPriority(ctx.target, WEVENT_HIGHEST_PRIORITY);
    weventSetPriority(ctx.ctrl, WEVENT_HIGHEST_PRIORITY);

    /* Min-heap dequeue order: unrelated (100), target (200), ctrl (300).
     * LIFO pendings push produces dispatch order: ctrl -> target -> unrelated. */
    wtimer_t      *timers[3]  = {ctx.unrelated, ctx.target, ctx.ctrl};
    const uint64_t offsets[3] = {100, 200, 300};
    makeTimersDueBatch(fix.loop, timers, offsets, 3);

    wloopProcessEvents(fix.loop, 0);

    require(ctx.ctrl_calls == 1, "ctrl ran once");
    require(ctx.target_calls == 0, "target suppressed despite cached next pointer");
    require(ctx.unrelated_calls == 1, "unrelated ran once");

    if (mode == TEST_MODE_HEAP)
    {
        require(ctx.alloc_in_ctrl_after_del == ctx.alloc_before + 3, "storage held during ctrl cb");
        require(eventloopAllocCount() - eventloopFreeCount() == ctx.alloc_before, "all timers released");
    }
    else
    {
        require(ctx.pool_checked_out_in_ctrl == 3, "3 checked out in ctrl cb");
        require(masterpoolGetCheckedOut(fix.master) == 0, "all returned to pool");
    }
    require(fix.loop->ntimers == 0, "ntimers is 0");
    require(wloopNActives(fix.loop) == 0, "nactives is 0");

    fixtureCleanup(&fix);
}

/* ========================================================================= */
/* Section 6 Scenario 7: Multiple pending resets kept                        */
/* ========================================================================= */

struct case7_ctx
{
    wtimer_t *ctrl;
    wtimer_t *target;
    int       ctrl_calls;
    int       target_calls;
};

static void case7CtrlCb(wtimer_t *timer)
{
    struct case7_ctx *ctx = (struct case7_ctx *) timer->userdata;
    ctx->ctrl_calls++;

    require(ctx->target->pending, "target must be pending");

    /* Multiple resets */
    bool ok = wtimerReset(ctx->target, 2000);
    require(ok && ctx->target->pending && ctx->target->pending_reset, "reset 1 ok");

    ok = wtimerReset(ctx->target, 4000);
    require(ok && ctx->target->pending && ctx->target->pending_reset, "reset 2 ok");

    ok = wtimerReset(ctx->target, 8000);
    require(ok && ctx->target->pending && ctx->target->pending_reset, "reset 3 ok");
}

static void case7TargetCb(wtimer_t *timer)
{
    struct case7_ctx *ctx = (struct case7_ctx *) timer->userdata;
    ctx->target_calls++;
}

static void testMultiplePendingResetsKept(void)
{
    struct case7_ctx ctx = {0};
    test_fixture_t   fix;
    fixtureInit(&fix, TEST_MODE_HEAP);

    ctx.ctrl             = addTimer(&fix, case7CtrlCb, 1000, 1);
    ctx.target           = addTimer(&fix, case7TargetCb, 1000, 1);
    ctx.ctrl->userdata   = &ctx;
    ctx.target->userdata = &ctx;

    weventSetPriority(ctx.ctrl, WEVENT_HIGHEST_PRIORITY);
    weventSetPriority(ctx.target, WEVENT_NORMAL_PRIORITY);

    wtimer_t *timers[2] = {ctx.ctrl, ctx.target};
    makeTimersDueBatch(fix.loop, timers, NULL, 2);

    wloopProcessEvents(fix.loop, 0);

    require(ctx.ctrl_calls == 1, "ctrl ran once");
    require(ctx.target_calls == 0, "target old callback suppressed");
    require(! ctx.target->pending, "target pending clear after dispatch");
    require(! ctx.target->pending_reset, "target pending_reset clear after dispatch");
    require(ctx.target->active, "target active");
    require(((wtimeout_t *) ctx.target)->timeout == 8000, "final requested deadline wins");
    require(fix.loop->timers.nelts == 1, "exactly 1 timer in heap (no duplicate nodes)");
    require(fix.loop->ntimers == 1, "ntimers is 1");

    /* Fire at replacement deadline */
    makeTimerDueNow(fix.loop, ctx.target);
    wloopProcessEvents(fix.loop, 0);

    require(ctx.target_calls == 1, "target delivered once at replacement deadline");
    require(fix.loop->ntimers == 0, "all timers retired");

    fixtureCleanup(&fix);
}

/* ========================================================================= */
/* Section 6 Scenario 8: Multiple resets then delete                         */
/* ========================================================================= */

struct case8_ctx
{
    test_fixture_t *fix;
    wtimer_t       *ctrl;
    wtimer_t       *target;
    int             ctrl_calls;
    int             target_calls;
    long            alloc_before;
    long            alloc_in_ctrl_after_del;
    size_t          pool_checked_out_in_ctrl;
};

static void case8CtrlCb(wtimer_t *timer)
{
    struct case8_ctx *ctx = (struct case8_ctx *) timer->userdata;
    ctx->ctrl_calls++;

    require(ctx->target->pending, "target must be pending");

    bool ok = wtimerReset(ctx->target, 2000);
    require(ok && ctx->target->pending && ctx->target->pending_reset, "reset 1 ok");

    ok = wtimerReset(ctx->target, 4000);
    require(ok && ctx->target->pending && ctx->target->pending_reset, "reset 2 ok");

    ok = wtimerReset(ctx->target, 8000);
    require(ok && ctx->target->pending && ctx->target->pending_reset, "reset 3 ok");

    wtimerDelete(ctx->target);

    ctx->alloc_in_ctrl_after_del = eventloopAllocCount() - eventloopFreeCount();
    if (ctx->fix->mode == TEST_MODE_POOLED)
    {
        ctx->pool_checked_out_in_ctrl = masterpoolGetCheckedOut(ctx->fix->master);
    }
}

static void case8TargetCb(wtimer_t *timer)
{
    struct case8_ctx *ctx = (struct case8_ctx *) timer->userdata;
    ctx->target_calls++;
}

static void testMultipleResetsThenDelete(test_mode_t mode)
{
    struct case8_ctx ctx = {0};
    test_fixture_t   fix;
    fixtureInit(&fix, mode);
    ctx.fix          = &fix;
    ctx.alloc_before = eventloopAllocCount() - eventloopFreeCount();

    ctx.ctrl             = addTimer(&fix, case8CtrlCb, 1000, 1);
    ctx.target           = addTimer(&fix, case8TargetCb, 1000, 1);
    ctx.ctrl->userdata   = &ctx;
    ctx.target->userdata = &ctx;

    weventSetPriority(ctx.ctrl, WEVENT_HIGHEST_PRIORITY);
    weventSetPriority(ctx.target, WEVENT_NORMAL_PRIORITY);

    wtimer_t *timers[2] = {ctx.ctrl, ctx.target};
    makeTimersDueBatch(fix.loop, timers, NULL, 2);

    wloopProcessEvents(fix.loop, 0);

    require(ctx.ctrl_calls == 1, "ctrl ran once");
    require(ctx.target_calls == 0, "target suppressed");
    if (mode == TEST_MODE_HEAP)
    {
        require(ctx.alloc_in_ctrl_after_del == ctx.alloc_before + 2, "storage held during cb");
        require(eventloopAllocCount() - eventloopFreeCount() == ctx.alloc_before, "storage released");
    }
    else
    {
        require(ctx.pool_checked_out_in_ctrl == 2, "storage checked out in cb");
        require(masterpoolGetCheckedOut(fix.master) == 0, "returned to pool");
    }
    require(fix.loop->ntimers == 0, "ntimers is 0");
    require(wloopNActives(fix.loop) == 0, "nactives is 0");

    wloopProcessEvents(fix.loop, 0);
    require(ctx.target_calls == 0, "target never delivered");

    fixtureCleanup(&fix);
}

/* ========================================================================= */
/* Section 6 Scenario 9: Finite repetition                                  */
/* ========================================================================= */

struct case9_ctx
{
    wtimer_t *ctrl;
    wtimer_t *target;
    int       ctrl_calls;
    int       target_calls;
    uint32_t  repeat_in_ctrl_after_resets;
};

static void case9CtrlCb(wtimer_t *timer)
{
    struct case9_ctx *ctx = (struct case9_ctx *) timer->userdata;
    ctx->ctrl_calls++;

    require(ctx->target->pending, "target must be pending");
    require(ctx->target->repeat == 2, "repeat decremented from 3 to 2 by collection");

    bool ok = wtimerReset(ctx->target, 5000);
    require(ok && ctx->target->pending && ctx->target->pending_reset, "reset 1 ok");
    require(ctx->target->repeat == 2, "repeat preserved across reset");

    ok = wtimerReset(ctx->target, 10000);
    require(ok && ctx->target->pending && ctx->target->pending_reset, "reset 2 ok");
    require(ctx->target->repeat == 2, "repeat preserved across repeated reset");

    ctx->repeat_in_ctrl_after_resets = ctx->target->repeat;
}

static void case9TargetCb(wtimer_t *timer)
{
    struct case9_ctx *ctx = (struct case9_ctx *) timer->userdata;
    ctx->target_calls++;
}

static int  s_finite_control_calls;
static void finiteControlCb(wtimer_t *timer)
{
    discard timer;
    s_finite_control_calls++;
}

static void testFiniteRepetition(void)
{
    /* Part A: Pending reset on finite repeating timer */
    struct case9_ctx ctx = {0};
    test_fixture_t   fix;
    fixtureInit(&fix, TEST_MODE_HEAP);

    ctx.ctrl   = addTimer(&fix, case9CtrlCb, 1000, 1);
    ctx.target = addTimer(&fix, case9TargetCb, 1000, 3);
    require(ctx.target->repeat == 3, "initial repeat is 3");

    ctx.ctrl->userdata   = &ctx;
    ctx.target->userdata = &ctx;

    weventSetPriority(ctx.ctrl, WEVENT_HIGHEST_PRIORITY);
    weventSetPriority(ctx.target, WEVENT_NORMAL_PRIORITY);

    wtimer_t *timers[2] = {ctx.ctrl, ctx.target};
    makeTimersDueBatch(fix.loop, timers, NULL, 2);

    /* Iteration 1: ctrl resets target; 1st occurrence suppressed */
    wloopProcessEvents(fix.loop, 0);

    require(ctx.ctrl_calls == 1, "ctrl ran once");
    require(ctx.target_calls == 0, "1st occurrence suppressed");
    require(ctx.repeat_in_ctrl_after_resets == 2, "repeat in ctrl was 2");
    require(ctx.target->repeat == 2, "target repeat remains 2");
    require(ctx.target->active, "target active");
    require(! ctx.target->destroy, "target destroy clear");
    require(fix.loop->ntimers == 1, "ntimers is 1");

    /* Iteration 2: 2nd scheduled occurrence */
    makeTimerDueNow(fix.loop, ctx.target);
    wloopProcessEvents(fix.loop, 0);

    require(ctx.target_calls == 1, "2nd occurrence delivered (target_calls == 1)");
    require(ctx.target->repeat == 1, "repeat decremented to 1");
    require(fix.loop->ntimers == 1, "ntimers is 1");

    /* Iteration 3: 3rd scheduled occurrence */
    makeTimerDueNow(fix.loop, ctx.target);
    wloopProcessEvents(fix.loop, 0);

    require(ctx.target_calls == 2, "3rd occurrence delivered (total 2 callbacks delivered)");
    require(fix.loop->ntimers == 0, "timer retired after all occurrences");

    /* Part B: Ordinary finite-completion control (3 occurrences, no resets) */
    s_finite_control_calls = 0;
    wtimer_t *control      = addTimer(&fix, finiteControlCb, 1000, 3);
    require(control->repeat == 3, "control repeat is 3");

    for (int i = 0; i < 3; ++i)
    {
        makeTimerDueNow(fix.loop, control);
        wloopProcessEvents(fix.loop, 0);
        require(s_finite_control_calls == i + 1, "control callback count");
    }
    require(fix.loop->ntimers == 0, "control retired cleanly");

    fixtureCleanup(&fix);
}

/* ========================================================================= */
/* Section 6 Scenario 10: Repeating self-rearm                               */
/* ========================================================================= */

struct case10_ctx
{
    int      calls;
    uint32_t repeat_after_rearm;
    bool     was_pending;
};

static void case10Cb(wtimer_t *timer)
{
    struct case10_ctx *ctx = (struct case10_ctx *) timer->userdata;
    ctx->calls++;
    if (ctx->calls == 1)
    {
        ctx->was_pending = timer->pending;
        require(timer->pending, "timer must be pending");
        require(timer->repeat == 2, "repeat decremented to 2 before callback");

        bool ok = wtimerReset(timer, 5000);
        require(ok, "reset must succeed");

        ctx->repeat_after_rearm = timer->repeat;
        require(timer->repeat == 2, "repeat preserved across reset");
        require(timer->pending && timer->pending_reset, "pending and pending_reset set");
    }
}

static void testRepeatingSelfRearm(void)
{
    struct case10_ctx ctx = {0};
    test_fixture_t    fix;
    fixtureInit(&fix, TEST_MODE_HEAP);

    wtimer_t *timer = addTimer(&fix, case10Cb, 1000, 3);
    timer->userdata = &ctx;

    /* Occurrence 1 */
    makeTimerDueNow(fix.loop, timer);
    wloopProcessEvents(fix.loop, 0);

    require(ctx.calls == 1, "occurrence 1 completed");
    require(ctx.was_pending, "was pending");
    require(ctx.repeat_after_rearm == 2, "repeat preserved as 2");
    require(timer->repeat == 2, "timer repeat is 2");
    require(! timer->pending && ! timer->pending_reset && timer->active, "flags cleared");
    require(fix.loop->ntimers == 1, "ntimers is 1");

    /* Occurrence 2 */
    makeTimerDueNow(fix.loop, timer);
    wloopProcessEvents(fix.loop, 0);

    require(ctx.calls == 2, "occurrence 2 completed");
    require(timer->repeat == 1, "repeat decremented to 1");
    require(fix.loop->ntimers == 1, "ntimers is 1");

    /* Occurrence 3 */
    makeTimerDueNow(fix.loop, timer);
    wloopProcessEvents(fix.loop, 0);

    require(ctx.calls == 3, "occurrence 3 completed");
    require(fix.loop->ntimers == 0, "retired cleanly");

    fixtureCleanup(&fix);
}

/* ========================================================================= */
/* Section 6 Scenario 11: Infinite repetition                                */
/* ========================================================================= */

struct case11_self_ctx
{
    int calls;
};

static void case11SelfCb(wtimer_t *timer)
{
    struct case11_self_ctx *ctx = (struct case11_self_ctx *) timer->userdata;
    ctx->calls++;
    require(timer->repeat == INFINITE, "repeat must remain INFINITE");
    if (ctx->calls == 1)
    {
        bool ok = wtimerReset(timer, 5000);
        require(ok, "reset of infinite timer must succeed");
        require(timer->repeat == INFINITE, "repeat must remain INFINITE across reset");
    }
}

struct case11_ctrl_ctx
{
    wtimer_t *ctrl;
    wtimer_t *target;
    int       ctrl_calls;
    int       target_calls;
};

static void case11CtrlCb(wtimer_t *timer)
{
    struct case11_ctrl_ctx *ctx = (struct case11_ctrl_ctx *) timer->userdata;
    ctx->ctrl_calls++;

    require(ctx->target->pending, "infinite target must be pending");
    require(ctx->target->repeat == INFINITE, "target repeat is INFINITE");

    bool ok = wtimerReset(ctx->target, 5000);
    require(ok && ctx->target->pending && ctx->target->pending_reset, "reset ok");
    require(ctx->target->repeat == INFINITE, "target repeat remains INFINITE");
}

static void case11TargetCb(wtimer_t *timer)
{
    struct case11_ctrl_ctx *ctx = (struct case11_ctrl_ctx *) timer->userdata;
    ctx->target_calls++;
    require(timer->repeat == INFINITE, "target repeat remains INFINITE");
}

static void testInfiniteRepetition(void)
{
    test_fixture_t fix;
    fixtureInit(&fix, TEST_MODE_HEAP);

    /* Sub-case A: self-reset inside infinite timer callback */
    struct case11_self_ctx self_ctx = {0};
    wtimer_t              *timer    = addTimer(&fix, case11SelfCb, 1000, INFINITE);
    timer->userdata                 = &self_ctx;

    makeTimerDueNow(fix.loop, timer);
    wloopProcessEvents(fix.loop, 0);
    require(self_ctx.calls == 1, "first call delivered");
    require(timer->repeat == INFINITE, "repeat remains INFINITE");
    require(fix.loop->ntimers == 1, "ntimers is 1");

    makeTimerDueNow(fix.loop, timer);
    wloopProcessEvents(fix.loop, 0);
    require(self_ctx.calls == 2, "second call delivered");
    require(timer->repeat == INFINITE, "repeat remains INFINITE");

    wtimerDelete(timer);
    require(fix.loop->ntimers == 0, "explicit deletion cancelled infinite timer");

    /* Sub-case B: reset of pending infinite timer from controller */
    struct case11_ctrl_ctx ctrl_ctx = {0};
    ctrl_ctx.ctrl                   = addTimer(&fix, case11CtrlCb, 1000, 1);
    ctrl_ctx.target                 = addTimer(&fix, case11TargetCb, 1000, INFINITE);
    ctrl_ctx.ctrl->userdata         = &ctrl_ctx;
    ctrl_ctx.target->userdata       = &ctrl_ctx;

    weventSetPriority(ctrl_ctx.ctrl, WEVENT_HIGHEST_PRIORITY);
    weventSetPriority(ctrl_ctx.target, WEVENT_NORMAL_PRIORITY);

    wtimer_t *timers[2] = {ctrl_ctx.ctrl, ctrl_ctx.target};
    makeTimersDueBatch(fix.loop, timers, NULL, 2);

    wloopProcessEvents(fix.loop, 0);
    require(ctrl_ctx.ctrl_calls == 1, "ctrl ran once");
    require(ctrl_ctx.target_calls == 0, "old pending expiration suppressed");
    require(ctrl_ctx.target->repeat == INFINITE, "target repeat is INFINITE");
    require(fix.loop->ntimers == 1, "target remains scheduled");

    makeTimerDueNow(fix.loop, ctrl_ctx.target);
    wloopProcessEvents(fix.loop, 0);
    require(ctrl_ctx.target_calls == 1, "replacement deadline fired once");
    require(ctrl_ctx.target->repeat == INFINITE, "repeat is INFINITE");

    wtimerDelete(ctrl_ctx.target);
    require(fix.loop->ntimers == 0, "explicit deletion cancelled target");

    fixtureCleanup(&fix);
}

/* ========================================================================= */
/* Section 6 Scenario 12: Allocation during cancellation                     */
/* ========================================================================= */

struct case12_self_ctx
{
    test_fixture_t *fix;
    wtimer_t       *timer_a;
    wtimer_t       *timer_b;
    int             a_calls;
    int             b_calls;
    uintptr_t       addr_a;
    uintptr_t       addr_b;
    bool            addresses_differ;
    size_t          pool_checked_out_in_cb;
};

static void case12BCb(wtimer_t *timer)
{
    struct case12_self_ctx *ctx = (struct case12_self_ctx *) timer->userdata;
    ctx->b_calls++;
}

static void case12ACb(wtimer_t *timer)
{
    struct case12_self_ctx *ctx = (struct case12_self_ctx *) timer->userdata;
    ctx->a_calls++;
    ctx->addr_a = (uintptr_t) timer;

    bool ok = wtimerReset(timer, 2000);
    require(ok, "reset ok");
    wtimerDelete(timer);

    /* While timer_a is still referenced by dispatch, allocate replacement timer_b */
    ctx->timer_b           = addTimer(ctx->fix, case12BCb, 3000, 1);
    ctx->timer_b->userdata = ctx;
    ctx->addr_b            = (uintptr_t) ctx->timer_b;

    ctx->addresses_differ = (ctx->addr_a != ctx->addr_b);
    require(ctx->addresses_differ, "replacement timer must not reuse executing timer storage");
    require(((wtimeout_t *) ctx->timer_b)->timeout == 3000, "timer_b retains timeout");

    if (ctx->fix->mode == TEST_MODE_POOLED)
    {
        ctx->pool_checked_out_in_cb = masterpoolGetCheckedOut(ctx->fix->master);
    }
}

struct case12_ctrl_ctx
{
    test_fixture_t *fix;
    wtimer_t       *ctrl;
    wtimer_t       *target;
    wtimer_t       *replacement;
    int             ctrl_calls;
    int             target_calls;
    int             replacement_calls;
    uintptr_t       target_addr;
    uintptr_t       replacement_addr;
    bool            addresses_differ;
    size_t          pool_checked_out_in_cb;
};

static void case12TargetCb(wtimer_t *timer)
{
    struct case12_ctrl_ctx *ctx = (struct case12_ctrl_ctx *) timer->userdata;
    ctx->target_calls++;
}

static void case12ReplacementCb(wtimer_t *timer)
{
    struct case12_ctrl_ctx *ctx = (struct case12_ctrl_ctx *) timer->userdata;
    ctx->replacement_calls++;
}

static void case12CtrlCb(wtimer_t *timer)
{
    struct case12_ctrl_ctx *ctx = (struct case12_ctrl_ctx *) timer->userdata;
    ctx->ctrl_calls++;
    ctx->target_addr = (uintptr_t) ctx->target;

    bool ok = wtimerReset(ctx->target, 2000);
    require(ok, "reset ok");
    wtimerDelete(ctx->target);

    ctx->replacement           = addTimer(ctx->fix, case12ReplacementCb, 4000, 1);
    ctx->replacement->userdata = ctx;
    ctx->replacement_addr      = (uintptr_t) ctx->replacement;

    ctx->addresses_differ = (ctx->target_addr != ctx->replacement_addr);
    require(ctx->addresses_differ, "replacement timer must not reuse pending timer storage");
    require(((wtimeout_t *) ctx->replacement)->timeout == 4000, "replacement retains timeout");

    if (ctx->fix->mode == TEST_MODE_POOLED)
    {
        ctx->pool_checked_out_in_cb = masterpoolGetCheckedOut(ctx->fix->master);
    }
}

static void testAllocationDuringCancellation(test_mode_t mode)
{
    /* Part A: In executing callback */
    {
        struct case12_self_ctx ctx = {0};
        test_fixture_t         fix;
        fixtureInit(&fix, mode);
        ctx.fix           = &fix;
        long alloc_before = eventloopAllocCount() - eventloopFreeCount();

        ctx.timer_a           = addTimer(&fix, case12ACb, 1000, 1);
        ctx.timer_a->userdata = &ctx;

        makeTimerDueNow(fix.loop, ctx.timer_a);
        wloopProcessEvents(fix.loop, 0);

        require(ctx.a_calls == 1, "timer_a ran once");
        require(ctx.addresses_differ, "timer_a and timer_b addresses differed");
        if (mode == TEST_MODE_POOLED)
        {
            require(ctx.pool_checked_out_in_cb == 2, "both checked out during callback");
            require(masterpoolGetCheckedOut(fix.master) == 1, "only timer_b checked out after dispatch");
        }
        else
        {
            require(eventloopAllocCount() - eventloopFreeCount() == alloc_before + 1, "only timer_b allocated");
        }
        require(fix.loop->ntimers == 1, "timer_b active in heap");

        makeTimerDueNow(fix.loop, ctx.timer_b);
        wloopProcessEvents(fix.loop, 0);

        require(ctx.b_calls == 1, "timer_b delivered once");
        require(fix.loop->ntimers == 0, "ntimers is 0");
        if (mode == TEST_MODE_POOLED)
        {
            require(masterpoolGetCheckedOut(fix.master) == 0, "all returned to pool");
        }
        else
        {
            require(eventloopAllocCount() - eventloopFreeCount() == alloc_before, "all heap memory freed");
        }

        fixtureCleanup(&fix);
    }

    /* Part B: In controller callback */
    {
        struct case12_ctrl_ctx ctx = {0};
        test_fixture_t         fix;
        fixtureInit(&fix, mode);
        ctx.fix           = &fix;
        long alloc_before = eventloopAllocCount() - eventloopFreeCount();

        ctx.ctrl             = addTimer(&fix, case12CtrlCb, 1000, 1);
        ctx.target           = addTimer(&fix, case12TargetCb, 1000, 1);
        ctx.ctrl->userdata   = &ctx;
        ctx.target->userdata = &ctx;

        weventSetPriority(ctx.ctrl, WEVENT_HIGHEST_PRIORITY);
        weventSetPriority(ctx.target, WEVENT_NORMAL_PRIORITY);

        wtimer_t *timers[2] = {ctx.ctrl, ctx.target};
        makeTimersDueBatch(fix.loop, timers, NULL, 2);

        wloopProcessEvents(fix.loop, 0);

        require(ctx.ctrl_calls == 1, "ctrl ran once");
        require(ctx.target_calls == 0, "target suppressed");
        require(ctx.addresses_differ, "target and replacement addresses differed");
        if (mode == TEST_MODE_POOLED)
        {
            require(ctx.pool_checked_out_in_cb == 3, "ctrl, target, replacement all checked out");
            require(masterpoolGetCheckedOut(fix.master) == 1, "only replacement checked out");
        }
        else
        {
            require(eventloopAllocCount() - eventloopFreeCount() == alloc_before + 1, "only replacement allocated");
        }
        require(fix.loop->ntimers == 1, "replacement active in heap");

        makeTimerDueNow(fix.loop, ctx.replacement);
        wloopProcessEvents(fix.loop, 0);

        require(ctx.replacement_calls == 1, "replacement delivered once");
        require(fix.loop->ntimers == 0, "ntimers is 0");
        if (mode == TEST_MODE_POOLED)
        {
            require(masterpoolGetCheckedOut(fix.master) == 0, "all returned to pool");
        }
        else
        {
            require(eventloopAllocCount() - eventloopFreeCount() == alloc_before, "all heap memory freed");
        }

        fixtureCleanup(&fix);
    }
}

/* ========================================================================= */
/* Section 8 Shutdown Scenarios                                              */
/* ========================================================================= */

static void testShutdownQuiesceThenOwnerDelete(test_mode_t mode)
{
    test_fixture_t fix;
    fixtureInit(&fix, mode);

    wtimer_t *timer     = addTimer(&fix, unexpectedTimer, 60000, 1);
    wtimer_t *unrelated = addTimer(&fix, unexpectedTimer, 60000, 1);

    wtimerTestMakePendingOneShot(timer);
    bool reset_ok = wtimerReset(timer, 40000);
    require(reset_ok, "reset of pending timer must succeed");
    require(timer->pending && timer->pending_reset, "timer must be pending with pending_reset");
    require(fix.loop->timers.root != NULL, "timer must be in heap");

    if (mode == TEST_MODE_POOLED)
    {
        require(masterpoolGetCheckedOut(fix.master) == 2, "2 timers checked out");
    }

    atomicStoreExplicit(&fix.loop->normal_admission_open, false, memory_order_release);
    wloopQuiesceNormalWork(fix.loop);

    require(s_unexpected_calls == 0, "no callbacks may run during quiesce");
    require(! timer->pending, "pending must be cleared by quiesce");
    require(! timer->pending_reset, "pending_reset must be cleared by quiesce");
    require(fix.loop->timers.root == NULL && fix.loop->ntimers == 0, "scheduling heap must be empty");
    require(timer->quiesced, "timer must be retained in quiesced state");
    require(unrelated->quiesced, "unrelated timer must be quiesced");
    if (mode == TEST_MODE_POOLED)
    {
        require(masterpoolGetCheckedOut(fix.master) == 2, "quiescence retains timers before owner drain");
    }

    /* Delete once during owner cleanup */
    wtimerDelete(timer);
    if (mode == TEST_MODE_POOLED)
    {
        require(masterpoolGetCheckedOut(fix.master) == 1, "owner deletion returned timer to pool");
    }
    wtimerDelete(unrelated);
    if (mode == TEST_MODE_POOLED)
    {
        require(masterpoolGetCheckedOut(fix.master) == 0, "owner deletion returned unrelated to pool");
    }

    fixtureCleanup(&fix);
}

static void testShutdownQuiesceThenLoopDelete(test_mode_t mode)
{
    test_fixture_t fix;
    fixtureInit(&fix, mode);

    wtimer_t *timer     = addTimer(&fix, unexpectedTimer, 60000, 1);
    wtimer_t *unrelated = addTimer(&fix, unexpectedTimer, 60000, 1);

    wtimerTestMakePendingOneShot(timer);
    bool reset_ok = wtimerReset(timer, 40000);
    require(reset_ok, "reset of pending timer must succeed");

    atomicStoreExplicit(&fix.loop->normal_admission_open, false, memory_order_release);
    wloopQuiesceNormalWork(fix.loop);

    require(s_unexpected_calls == 0, "no callbacks may run during quiesce");
    require(timer->quiesced && unrelated->quiesced, "timers must be retained in quiesced state");

    /* Leave quiesced timers for wloopDestroy in fixtureCleanup */
    fixtureCleanup(&fix);
}

static void testShutdownDirectLoopDestroy(test_mode_t mode)
{
    test_fixture_t fix;
    fixtureInit(&fix, mode);

    wtimer_t *timer = addTimer(&fix, unexpectedTimer, 60000, 1);
    discard   addTimer(&fix, unexpectedTimer, 60000, 1);

    wtimerTestMakePendingOneShot(timer);
    bool reset_ok = wtimerReset(timer, 40000);
    require(reset_ok, "reset of pending timer must succeed");
    require(timer->pending && timer->pending_reset, "timer must be pending with pending_reset");
    require(fix.loop->timers.root != NULL, "timer must be in heap");

    /* Destroy loop directly while timer is pending and scheduled */
    fixtureCleanup(&fix);
    require(s_unexpected_calls == 0, "no callbacks ran during direct destruction");
}

static void testShutdownResetDeleteBeforeCleanupQuiesce(test_mode_t mode)
{
    test_fixture_t fix;
    fixtureInit(&fix, mode);

    wtimer_t *timer     = addTimer(&fix, unexpectedTimer, 60000, 1);
    wtimer_t *unrelated = addTimer(&fix, unexpectedTimer, 60000, 1);

    wtimerTestMakePendingOneShot(timer);
    bool reset_ok = wtimerReset(timer, 40000);
    require(reset_ok, "reset of pending timer must succeed");
    wtimerDelete(timer);
    /* Handle deleted: do not access timer handle afterward */

    atomicStoreExplicit(&fix.loop->normal_admission_open, false, memory_order_release);
    wloopQuiesceNormalWork(fix.loop);

    require(s_unexpected_calls == 0, "no callbacks ran");
    require(unrelated->quiesced, "unrelated timer quiesced");
    wtimerDelete(unrelated);

    fixtureCleanup(&fix);
}

static void testShutdownResetDeleteBeforeCleanupDirect(test_mode_t mode)
{
    test_fixture_t fix;
    fixtureInit(&fix, mode);

    wtimer_t *timer = addTimer(&fix, unexpectedTimer, 60000, 1);
    discard   addTimer(&fix, unexpectedTimer, 60000, 1);

    wtimerTestMakePendingOneShot(timer);
    bool reset_ok = wtimerReset(timer, 40000);
    require(reset_ok, "reset of pending timer must succeed");
    wtimerDelete(timer);
    /* Handle deleted: do not access timer handle afterward */

    fixtureCleanup(&fix);
    require(s_unexpected_calls == 0, "no callbacks ran");
}

/* ========================================================================= */
/* Main test runner                                                          */
/* ========================================================================= */

int main(void)
{
    testCaseSet("timer_reset_lifetime_test");
    test_worker_registry_t registry = {0};
    GSTATE.workers_count            = 1;
    testWorkerRegistryInstall(&registry);
    testWorkerBindWID(0);

    /* Section 6 Core Scenarios */
    testScheduledReset();
    testPendingResetKept();
    testSelfRearm();
    testSelfResetThenDelete(TEST_MODE_HEAP);
    testSelfResetThenDelete(TEST_MODE_POOLED);
    testOtherPendingDifferentPriority(TEST_MODE_HEAP);
    testOtherPendingDifferentPriority(TEST_MODE_POOLED);
    testOtherPendingSamePriority(TEST_MODE_HEAP);
    testOtherPendingSamePriority(TEST_MODE_POOLED);
    testMultiplePendingResetsKept();
    testMultipleResetsThenDelete(TEST_MODE_HEAP);
    testMultipleResetsThenDelete(TEST_MODE_POOLED);
    testFiniteRepetition();
    testRepeatingSelfRearm();
    testInfiniteRepetition();
    testAllocationDuringCancellation(TEST_MODE_HEAP);
    testAllocationDuringCancellation(TEST_MODE_POOLED);

    /* Section 8 Shutdown and Quiescence Scenarios */
    testShutdownQuiesceThenOwnerDelete(TEST_MODE_HEAP);
    testShutdownQuiesceThenOwnerDelete(TEST_MODE_POOLED);
    testShutdownQuiesceThenLoopDelete(TEST_MODE_HEAP);
    testShutdownQuiesceThenLoopDelete(TEST_MODE_POOLED);
    testShutdownDirectLoopDestroy(TEST_MODE_HEAP);
    testShutdownDirectLoopDestroy(TEST_MODE_POOLED);
    testShutdownResetDeleteBeforeCleanupQuiesce(TEST_MODE_HEAP);
    testShutdownResetDeleteBeforeCleanupQuiesce(TEST_MODE_POOLED);
    testShutdownResetDeleteBeforeCleanupDirect(TEST_MODE_HEAP);
    testShutdownResetDeleteBeforeCleanupDirect(TEST_MODE_POOLED);

    testWorkerUnbindWID();
    testWorkerRegistryRestore(&registry);
    puts("timer_reset_lifetime_test: all cases passed");
    return 0;
}

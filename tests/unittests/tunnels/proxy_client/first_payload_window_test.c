/*
 * Covers: the shared first-payload deadline, timer reclamation and owner notification contract.
 * Setup: existing worker/loop fixture, a controlled monotonic clock and timer admission/reset wrappers.
 * Cases: cached/expired/maximum deadlines, rounded early expiry, add/reset refusal, pending/quiesced cancel,
 * and cancellation or owner destruction from both kinds of notification.
 * Checks: deadline precision, remaining timeout, callback count/event, due state and complete timer cleanup.
 * Limits: client-specific Est, protocol encoding and association ownership remain in the existing client suites.
 * CTest: waterwall.first_payload_window_unit
 */
#include "ProxyClientCommon/first_payload_window.h"

#include "fixtures/failure/tunnel_line_failure_harness.h"
#include "wloop_internal.h"

typedef struct window_owner_s
{
    first_payload_window_t window;
    unsigned               callback_action;
} window_owner_t;

static twf_worker_env_t             env;
static window_owner_t              *owner;
static uint64_t                     now_us;
static unsigned                     notifications, add_calls, reset_calls;
static uint32_t                     added_ms, reset_ms;
static first_payload_window_event_t notified_event;
static bool                         refuse_add, refuse_reset;

uint64_t __wrap_getHRTimeUs(void);
uint64_t __wrap_getHRTimeUs(void)
{
    return now_us;
}

wtimer_t *__real_wtimerAdd(wloop_t *, wtimer_cb, uint32_t, uint32_t);
wtimer_t *__wrap_wtimerAdd(wloop_t *loop, wtimer_cb callback, uint32_t timeout_ms, uint32_t repeat);
wtimer_t *__wrap_wtimerAdd(wloop_t *loop, wtimer_cb callback, uint32_t timeout_ms, uint32_t repeat)
{
    ++add_calls;
    added_ms = timeout_ms;
    return refuse_add ? NULL : __real_wtimerAdd(loop, callback, timeout_ms, repeat);
}

bool __real_wtimerReset(wtimer_t *, uint32_t);
bool __wrap_wtimerReset(wtimer_t *timer, uint32_t timeout_ms);
bool __wrap_wtimerReset(wtimer_t *timer, uint32_t timeout_ms)
{
    ++reset_calls;
    reset_ms = timeout_ms;
    return ! refuse_reset && __real_wtimerReset(timer, timeout_ms);
}

static void notifyOwner(void *context, first_payload_window_event_t event)
{
    window_owner_t *notified = context;
    twfRequire(notified == owner && notified->window.timer == NULL, "notification retained the executing timer");
    twfRequire(firstPayloadWindowIsDue(&notified->window) == (event == kFirstPayloadWindowDue),
               "notification published the wrong due state");
    ++notifications;
    notified_event = event;
    if (notified->callback_action != 0)
    {
        firstPayloadWindowCancel(&notified->window);
        firstPayloadWindowCancel(&notified->window);
        twfRequire(! firstPayloadWindowIsDue(&notified->window), "cancel inside notification retained due state");
    }
    if (notified->callback_action == 2)
    {
        owner = NULL;
        memoryFree(notified);
    }
}

static void begin(void)
{
    now_us = UINT64_C(1000123456);
    twfWorkerEnvSetup(&env, 4096, 0);
    owner         = memoryAllocateZero(sizeof(*owner));
    notifications = add_calls = reset_calls = 0;
    refuse_add = refuse_reset = false;
}

static void end(void)
{
    if (owner != NULL)
    {
        firstPayloadWindowCancel(&owner->window);
        memoryFree(owner);
        owner = NULL;
    }
    twfRequire(wloopNTimers(env.loop) == 0, "window retained a timer after cleanup");
    twfWorkerEnvTeardown(&env);
}

static void advanceTo(uint64_t time_us)
{
    now_us = time_us;
    twfRequire(wloopProcessEvents(env.loop, 0) >= 0, "event-loop dispatch failed");
}

static void arm(uint32_t timeout_ms)
{
    firstPayloadWindowStart(&owner->window, env.loop, timeout_ms);
    twfRequire(firstPayloadWindowArm(&owner->window, env.loop, notifyOwner, owner) == kFirstPayloadWindowArmed,
               "timer was not armed");
    twfRequire(owner->window.timer->loop == env.loop && wloopNTimers(env.loop) == 1,
               "window lost its owner loop or timer");
}

static void testDeadlines(void)
{
    twfSetCase("cached owner clock and already elapsed deadline");
    begin();
    const uint64_t cached_us = now_us - 123;
    env.loop->cur_hrtime     = cached_us;
    firstPayloadWindowStart(&owner->window, env.loop, 400);
    twfRequire(owner->window.deadline_us == cached_us + 400000, "start sampled a new clock or lost precision");
    advanceTo(owner->window.deadline_us + 1);
    twfRequire(firstPayloadWindowArm(&owner->window, env.loop, notifyOwner, owner) == kFirstPayloadWindowArmDue,
               "elapsed deadline did not become due synchronously");
    twfRequire(firstPayloadWindowIsDue(&owner->window) && owner->window.timer == NULL && add_calls == 0 &&
                   notifications == 0,
               "elapsed arm allocated a timer or called out");
    end();

    twfSetCase("zero timeout is immediately due");
    begin();
    firstPayloadWindowCancel(&owner->window);
    twfRequire(! firstPayloadWindowIsDue(&owner->window), "zero state was due");
    firstPayloadWindowStart(&owner->window, env.loop, 0);
    twfRequire(firstPayloadWindowArm(&owner->window, env.loop, notifyOwner, owner) == kFirstPayloadWindowArmDue &&
                   add_calls == 0 && notifications == 0 && firstPayloadWindowIsDue(&owner->window),
               "zero timeout created a timer or missed its due latch");
    end();

    twfSetCase("maximum timeout preserves wide arithmetic and rounds remaining microseconds up");
    begin();
    firstPayloadWindowStart(&owner->window, env.loop, UINT32_MAX);
    const uint64_t deadline = now_us + (uint64_t) UINT32_MAX * 1000;
    twfRequire(owner->window.deadline_us == deadline, "maximum deadline overflowed");
    advanceTo(now_us + 1);
    twfRequire(firstPayloadWindowArm(&owner->window, env.loop, notifyOwner, owner) == kFirstPayloadWindowArmed &&
                   added_ms == UINT32_MAX,
               "remaining timeout overflowed or rounded down");
    end();
}

static void testEarlyExpiry(void)
{
    twfSetCase("coarse timer expiry rearms without shortening the first-payload window");
    begin();
    arm(1000);
    const uint64_t deadline = owner->window.deadline_us;
    twfRequire(owner->window.timer->next_timeout < deadline, "fixture did not exercise coarse timer rounding");
    advanceTo(owner->window.timer->next_timeout + 1);
    twfRequire(notifications == 0 && reset_calls == 1 && owner->window.timer != NULL &&
                   ! firstPayloadWindowIsDue(&owner->window) && wloopNTimers(env.loop) == 1,
               "early expiry notified the owner or lost the timer");
    twfRequire(reset_ms == (uint32_t) ((deadline - now_us + 999) / 1000), "early expiry rounded the remainder down");
    advanceTo(deadline - 1);
    twfRequire(notifications == 0, "window fired before its absolute deadline");
    advanceTo(owner->window.timer->next_timeout + 1);
    twfRequire(notifications == 1 && notified_event == kFirstPayloadWindowDue &&
                   firstPayloadWindowIsDue(&owner->window) && owner->window.timer == NULL,
               "rearmed timer failed to publish due exactly once");
    advanceTo(now_us + 1000000);
    twfRequire(notifications == 1, "one-shot notification repeated");
    end();
}

static void testCancel(void)
{
    for (unsigned mode = 0; mode < 3; ++mode)
    {
        twfSetCase("cancel armed, pending and quiesced windows");
        begin();
        arm(400);
        if (mode == 1)
            wtimerTestMakePendingOneShot(owner->window.timer);
        if (mode == 2)
        {
            wloopCloseNormalAdmission(env.loop);
            wloopQuiesceNormalWork(env.loop);
            twfRequire(owner->window.timer->quiesced, "quiescence did not retain the owner timer handle");
        }
        firstPayloadWindowCancel(&owner->window);
        firstPayloadWindowCancel(&owner->window);
        advanceTo(now_us + 1000000);
        twfRequire(notifications == 0 && owner->window.timer == NULL && ! firstPayloadWindowIsDue(&owner->window),
                   "cancelled window notified the owner or retained work");
        end();
    }
}

static void testRefusalAndReentry(void)
{
    twfSetCase("initial timer refusal is synchronous and silent");
    begin();
    firstPayloadWindowStart(&owner->window, env.loop, 400);
    refuse_add = true;
    twfRequire(firstPayloadWindowArm(&owner->window, env.loop, notifyOwner, owner) == kFirstPayloadWindowArmFailed &&
                   owner->window.timer == NULL && ! firstPayloadWindowIsDue(&owner->window) && notifications == 0,
               "failed arm retained work or notified asynchronously");
    end();

    for (unsigned failure = 0; failure < 2; ++failure)
        for (unsigned action = 1; action <= 2; ++action)
        {
            twfSetCase("notification can cancel or free its owner on due and reset refusal");
            begin();
            arm(400);
            owner->callback_action = action;
            refuse_reset           = failure != 0;
            if (failure)
            {
                wtimerTestMakePendingOneShot(owner->window.timer);
                advanceTo(now_us);
            }
            else
                advanceTo(owner->window.deadline_us + 1);
            twfRequire(notifications == 1 &&
                           notified_event == (failure ? kFirstPayloadWindowRearmFailed : kFirstPayloadWindowDue) &&
                           wloopNTimers(env.loop) == 0 && (owner == NULL) == (action == 2),
                       "notification retained its timer, repeated or failed to release its owner");
            end();
        }
}

int main(void)
{
    testDeadlines();
    testEarlyExpiry();
    testCancel();
    testRefusalAndReentry();
    puts("first_payload_window_test: all cases passed");
    return 0;
}

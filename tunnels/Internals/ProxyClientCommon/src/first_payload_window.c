#include "ProxyClientCommon/first_payload_window.h"

static uint32_t firstPayloadRemainingMs(uint64_t deadline_us, uint64_t now_us)
{
    assert(deadline_us > now_us);
    return (uint32_t) ((deadline_us - now_us + 999) / 1000);
}

static void firstPayloadExpired(wtimer_t *timer)
{
    first_payload_window_t *window = weventGetUserdata(timer);
    assert(window->timer == timer);
    uint64_t now = wloopNowLoopRunTime(weventGetLoop(timer));
    /* Dispatch owns this one-shot until a successful reset revives it. */
    window->timer = NULL;
    first_payload_window_event_t event;
    if (now < window->deadline_us)
    {
        if (wtimerReset(timer, firstPayloadRemainingMs(window->deadline_us, now)))
        {
            window->timer = timer;
            return;
        }
        event = kFirstPayloadWindowRearmFailed;
    }
    else
    {
        window->due = true;
        event       = kFirstPayloadWindowDue;
    }
    FirstPayloadWindowNotifyFn notify = window->notify;
    void                      *owner  = window->owner;
    /* Sending or closing can destroy the containing state even on a live line. */
    notify(owner, event);
}

void firstPayloadWindowStart(first_payload_window_t *window, wloop_t *loop, uint32_t timeout_ms)
{
    assert(window != NULL && loop != NULL && ! window->started);
    assert(currentThreadOwnsWorker(getLoopWorkerWID(loop)));
    window->started     = true;
    window->deadline_us = wloopNowLoopRunTime(loop) + (uint64_t) timeout_ms * 1000;
}

first_payload_window_arm_result_t firstPayloadWindowArm(first_payload_window_t *window, wloop_t *loop,
                                                        FirstPayloadWindowNotifyFn notify, void *owner)
{
    assert(window != NULL && loop != NULL && notify != NULL);
    assert(window->started && window->timer == NULL && ! window->due);
    assert(currentThreadOwnsWorker(getLoopWorkerWID(loop)));
    uint64_t now = wloopNowLoopRunTime(loop);
    if (now >= window->deadline_us)
    {
        window->due = true;
        return kFirstPayloadWindowArmDue;
    }
    window->timer = wtimerAdd(loop, firstPayloadExpired, firstPayloadRemainingMs(window->deadline_us, now), 1);
    if (window->timer == NULL)
        return kFirstPayloadWindowArmFailed;
    window->notify = notify;
    window->owner  = owner;
    weventSetUserData(window->timer, window);
    return kFirstPayloadWindowArmed;
}

void firstPayloadWindowCancel(first_payload_window_t *window)
{
    assert(window != NULL);
    wtimer_t *timer = window->timer;
    window->timer   = NULL;
    window->due     = false;
    window->notify  = NULL;
    window->owner   = NULL;
    if (timer != NULL)
    {
        assert(currentThreadOwnsWorker(getLoopWorkerWID(weventGetLoop(timer))));
        wtimerDelete(timer);
    }
}

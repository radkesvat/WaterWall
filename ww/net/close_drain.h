#pragma once

#include "wlibc.h"
#include "wloop.h"

enum
{
    kCloseDrainTimeoutMs = 30000
};

typedef struct close_drain_s close_drain_t;
typedef void (*CloseDrainExpiredFn)(close_drain_t *);

/* All access is on the owner worker. The record must stay at a stable address
 * until End unlinks it and detaches the timer callback. */
struct close_drain_s
{
    close_drain_t     **link;
    close_drain_t      *next;
    wtimer_t           *timer;
    CloseDrainExpiredFn expire;
    uint64_t            deadline_ms;
};

static inline bool closeDrainIsActive(const close_drain_t *drain)
{
    return drain->deadline_ms != 0;
}

static inline void closeDrainBeginAt(close_drain_t *drain, close_drain_t **head, CloseDrainExpiredFn expire,
                                     uint64_t deadline_ms)
{
    assert(! closeDrainIsActive(drain) && expire != NULL && deadline_ms != 0);
    drain->deadline_ms = deadline_ms;
    drain->expire      = expire;
    if (head != NULL)
    {
        drain->link = head;
        drain->next = *head;
        if (drain->next != NULL)
            drain->next->link = &drain->next;
        *head = drain;
    }
}

static inline void closeDrainBegin(close_drain_t *drain, close_drain_t **head, CloseDrainExpiredFn expire)
{
    closeDrainBeginAt(drain, head, expire, getHRTimeUs() / 1000U + kCloseDrainTimeoutMs);
}

static inline uint32_t closeDrainTimeRemaining(const close_drain_t *drain)
{
    const uint64_t now = getHRTimeUs() / 1000U;
    return now < drain->deadline_ms ? (uint32_t) (drain->deadline_ms - now) : 0;
}

static inline void closeDrainTimerCallback(wtimer_t *timer)
{
    close_drain_t *drain = weventGetUserdata(timer);
    assert(drain != NULL && drain->timer == timer);
    drain->timer             = NULL;
    const uint32_t remaining = closeDrainTimeRemaining(drain);
    if (remaining != 0 && wtimerReset(timer, remaining))
    {
        drain->timer = timer;
        return;
    }
    drain->expire(drain);
}

static inline bool closeDrainArm(close_drain_t *drain, wloop_t *loop)
{
    const uint32_t remaining = closeDrainTimeRemaining(drain);
    if (remaining == 0 || ! wloopNormalDispatchAllowed(loop))
        return false;
    if (drain->timer != NULL)
        return true;
    drain->timer = wtimerAddDeadline(loop, closeDrainTimerCallback, remaining);
    if (drain->timer == NULL)
        return false;
    weventSetUserData(drain->timer, drain);
    return true;
}

static inline void closeDrainCancelTimer(close_drain_t *drain)
{
    wtimer_t *timer = drain->timer;
    drain->timer    = NULL;
    if (timer != NULL)
    {
        weventSetUserData(timer, NULL);
        wtimerDelete(timer);
    }
}

static inline void closeDrainEnd(close_drain_t *drain)
{
    closeDrainCancelTimer(drain);
    if (drain->link != NULL)
    {
        *drain->link = drain->next;
        if (drain->next != NULL)
            drain->next->link = drain->link;
    }
    *drain = (close_drain_t) {0};
}

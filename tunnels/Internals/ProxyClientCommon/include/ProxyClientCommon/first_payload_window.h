#pragma once

#include "wwapi.h"

typedef enum first_payload_window_arm_result_e
{
    kFirstPayloadWindowArmDue,
    kFirstPayloadWindowArmed,
    kFirstPayloadWindowArmFailed
} first_payload_window_arm_result_t;

typedef enum first_payload_window_event_e
{
    kFirstPayloadWindowDue,
    kFirstPayloadWindowRearmFailed
} first_payload_window_event_t;

/* Both notifications run with the timer slot cleared and may destroy the window
 * and its containing owner. The helper touches neither after calling out. */
typedef void (*FirstPayloadWindowNotifyFn)(void *owner, first_payload_window_event_t event);

/* Embedded at a stable address in the client's line state. Zero is idle; all
 * operations belong to the exact direct line/carrier's event worker. The helper
 * owns only its timer, never a line or line reference. Fields are private. */
typedef struct first_payload_window_s
{
    wtimer_t                  *timer;
    uint64_t                   deadline_us;
    FirstPayloadWindowNotifyFn notify;
    void                      *owner;
    bool                       started : 1;
    bool                       due : 1;
} first_payload_window_t;

/* Call once on a zeroed window before forwarding the first transport Est, if
 * the request has not been sent. Records the cached owner-loop deadline only;
 * zero timeout becomes due when Arm runs after Est. Never invokes a callback. */
void firstPayloadWindowStart(first_payload_window_t *window, wloop_t *loop, uint32_t timeout_ms);

/* Call once after Est returns, on the same loop, only after revalidating the
 * association and unsent request. Never invokes notify inline: ArmDue latches
 * due, ArmFailed leaves no timer, and Armed retains notify/owner until expiry or
 * cancellation. Initial arm and asynchronous rearm refusal are node-owned close
 * decisions. Notify may receive a nullable owner if the caller needs no context. */
WW_MUST_USE first_payload_window_arm_result_t firstPayloadWindowArm(first_payload_window_t *window, wloop_t *loop,
                                                                    FirstPayloadWindowNotifyFn notify, void *owner);

static inline bool firstPayloadWindowIsDue(const first_payload_window_t *window)
{
    assert(window != NULL);
    return window->due;
}

/* Idempotent, including zero/unstarted state and notification callbacks. Clears
 * the due latch even with no timer. Request commitment and teardown must cancel
 * before discarding the containing state. Quiesced handles remain deletable on
 * the owner worker while its loop is alive. Does not restart the window. */
void firstPayloadWindowCancel(first_payload_window_t *window);

#include "devices/capture/capture_lifecycle.h"

#include <stdio.h>
#include <stdlib.h>

#define kUntouchedSourceState ((capture_lifecycle_state_t) 0x7F)

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "FAIL: %s\n", message);
        exit(1);
    }
}

int main(void)
{
    atomic_int                lifecycle;
    capture_lifecycle_state_t failed_from;
    atomic_init(&lifecycle, kCaptureLifecycleDown);

    require(captureLifecycleTransitionDownToStarting(&lifecycle), "DOWN -> STARTING failed");
    require(captureLifecycleLoad(&lifecycle) == kCaptureLifecycleStarting, "STARTING was not published");
    require(captureLifecycleTransitionStartingToUp(&lifecycle), "STARTING -> UP failed");
    require(captureLifecycleLoad(&lifecycle) == kCaptureLifecycleUp, "UP was not published");

    captureLifecycleTransitionToStopping(&lifecycle);
    require(captureLifecycleLoad(&lifecycle) == kCaptureLifecycleStopping, "UP -> STOPPING failed");
    captureLifecycleTransitionStoppingToDown(&lifecycle);
    require(captureLifecycleLoad(&lifecycle) == kCaptureLifecycleDown, "STOPPING -> DOWN failed");

    /*
     * The exact source state lets the reader wrapper leave startup rollback to
     * BringUp while requesting worker-0 shutdown only for runtime device loss.
     */
    require(captureLifecycleTransitionDownToStarting(&lifecycle), "second start failed");
    failed_from = kUntouchedSourceState;
    require(captureLifecycleTransitionToFailed(&lifecycle, &failed_from), "STARTING -> FAILED failed");
    require(failed_from == kCaptureLifecycleStarting, "startup failure reported the wrong source state");
    require(! captureLifecycleTransitionStartingToUp(&lifecycle), "FAILED was overwritten with UP");

    capture_lifecycle_state_t loser_source = kUntouchedSourceState;
    require(! captureLifecycleTransitionToFailed(&lifecycle, &loser_source),
            "a second reader wrapper won the FAILED transition");
    require(loser_source == kUntouchedSourceState, "a losing FAILED transition changed its source state");

    captureLifecycleTransitionToStopping(&lifecycle);
    captureLifecycleTransitionStoppingToDown(&lifecycle);

    require(captureLifecycleTransitionDownToStarting(&lifecycle), "third start failed");
    require(captureLifecycleTransitionStartingToUp(&lifecycle), "third startup publication failed");
    failed_from = kUntouchedSourceState;
    require(captureLifecycleTransitionToFailed(&lifecycle, &failed_from), "UP -> FAILED failed");
    require(failed_from == kCaptureLifecycleUp, "runtime failure reported the wrong source state");
    require(captureLifecycleLoad(&lifecycle) == kCaptureLifecycleFailed, "runtime failure did not publish FAILED");
    require(! captureLifecycleTransitionDownToStarting(&lifecycle), "FAILED -> STARTING was accepted");

    captureLifecycleTransitionToStopping(&lifecycle);
    require(captureLifecycleLoad(&lifecycle) == kCaptureLifecycleStopping, "FAILED -> STOPPING failed");
    failed_from = kUntouchedSourceState;
    require(! captureLifecycleTransitionToFailed(&lifecycle, &failed_from), "STOPPING was overwritten with FAILED");
    require(failed_from == kUntouchedSourceState, "STOPPING -> FAILED rejection changed its source state");

    captureLifecycleTransitionStoppingToDown(&lifecycle);
    failed_from = kUntouchedSourceState;
    require(! captureLifecycleTransitionToFailed(&lifecycle, &failed_from), "DOWN was overwritten with FAILED");
    require(failed_from == kUntouchedSourceState, "DOWN -> FAILED rejection changed its source state");

    return 0;
}

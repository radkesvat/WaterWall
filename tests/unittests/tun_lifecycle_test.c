#include "devices/tun/tun_lifecycle.h"

#include <stdio.h>
#include <stdlib.h>

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
    atomic_int lifecycle;
    atomic_init(&lifecycle, kTunLifecycleDown);

    // Initial DOWN -> STARTING -> UP
    require(tunLifecycleTransitionDownToStarting(&lifecycle), "DOWN -> STARTING failed");
    require(tunLifecycleLoad(&lifecycle) == kTunLifecycleStarting, "STARTING was not published");
    require(tunLifecycleTransitionStartingToUp(&lifecycle), "STARTING -> UP failed");
    require(tunLifecycleLoad(&lifecycle) == kTunLifecycleUp, "UP was not published");

    // Cleanup changes UP -> STOPPING -> DOWN
    tunLifecycleTransitionToStopping(&lifecycle);
    require(tunLifecycleLoad(&lifecycle) == kTunLifecycleStopping, "UP -> STOPPING failed");
    tunLifecycleTransitionStoppingToDown(&lifecycle);
    require(tunLifecycleLoad(&lifecycle) == kTunLifecycleDown, "STOPPING -> DOWN failed");

    // Failure during STARTING prevents STARTING -> UP
    require(tunLifecycleTransitionDownToStarting(&lifecycle), "second start failed");
    require(tunLifecycleTransitionToFailed(&lifecycle), "STARTING -> FAILED failed");
    require(tunLifecycleLoad(&lifecycle) == kTunLifecycleFailed, "FAILED was not published during startup");
    require(! tunLifecycleTransitionStartingToUp(&lifecycle), "FAILED was overwritten with UP");

    // Only one of two simulated wrappers can win the first active-to-failed transition
    require(! tunLifecycleTransitionToFailed(&lifecycle), "a second wrapper won the FAILED transition");

    // Cleanup from FAILED
    tunLifecycleTransitionToStopping(&lifecycle);
    require(tunLifecycleLoad(&lifecycle) == kTunLifecycleStopping, "FAILED -> STOPPING failed");
    tunLifecycleTransitionStoppingToDown(&lifecycle);

    // Failure after publication changes UP -> FAILED
    require(tunLifecycleTransitionDownToStarting(&lifecycle), "third start failed");
    require(tunLifecycleTransitionStartingToUp(&lifecycle), "third startup publication failed");
    require(tunLifecycleTransitionToFailed(&lifecycle), "UP -> FAILED failed");
    require(tunLifecycleLoad(&lifecycle) == kTunLifecycleFailed, "FAILED was not published after startup");

    // FAILED -> STARTING is rejected
    require(! tunLifecycleTransitionDownToStarting(&lifecycle), "FAILED -> STARTING was accepted");

    // Cleanup
    tunLifecycleTransitionToStopping(&lifecycle);
    tunLifecycleTransitionStoppingToDown(&lifecycle);

    // A wrapper observing STOPPING does not publish FAILED
    require(tunLifecycleTransitionDownToStarting(&lifecycle), "fourth start failed");
    tunLifecycleTransitionToStopping(&lifecycle);
    require(! tunLifecycleTransitionToFailed(&lifecycle), "STOPPING was overwritten with FAILED");
    require(tunLifecycleLoad(&lifecycle) == kTunLifecycleStopping, "STOPPING did not remain published");

    return 0;
}

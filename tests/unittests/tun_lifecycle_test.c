#include "devices/tun/tun_lifecycle.h"
#include "wwapi.h"

// Sentinel the helper must never write when the transition loses.
#define kUntouchedSourceState ((tun_lifecycle_state_t) 0x7F)

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "FAIL: %s\n", message);
        exit(1);
    }
}

static void testSharedTransitionTable(void)
{
    for (int value = kDeviceLifecycleDown; value <= kDeviceLifecycleFailed; ++value)
    {
        const device_lifecycle_state_t initial = (device_lifecycle_state_t) value;
        atomic_int                     lifecycle;
        device_lifecycle_state_t       failed_from = kUntouchedSourceState;

        atomic_init(&lifecycle, value);
        const bool down_to_starting = deviceLifecycleTransitionDownToStarting(&lifecycle);
        require(down_to_starting == (initial == kDeviceLifecycleDown), "DOWN -> STARTING verdict differed");
        require(deviceLifecycleLoad(&lifecycle) ==
                    (initial == kDeviceLifecycleDown ? kDeviceLifecycleStarting : initial),
                "DOWN -> STARTING final state differed");

        atomicStoreRelaxed(&lifecycle, value);
        const bool starting_to_up = deviceLifecycleTransitionStartingToUp(&lifecycle);
        require(starting_to_up == (initial == kDeviceLifecycleStarting), "STARTING -> UP verdict differed");
        require(deviceLifecycleLoad(&lifecycle) == (initial == kDeviceLifecycleStarting ? kDeviceLifecycleUp : initial),
                "STARTING -> UP final state differed");

        atomicStoreRelaxed(&lifecycle, value);
        const bool to_failed = deviceLifecycleTransitionToFailed(&lifecycle, &failed_from);
        require(to_failed == deviceLifecycleIsActive(initial), "active -> FAILED verdict differed");
        require(deviceLifecycleLoad(&lifecycle) ==
                    (deviceLifecycleIsActive(initial) ? kDeviceLifecycleFailed : initial),
                "active -> FAILED final state differed");
        require(failed_from ==
                    (deviceLifecycleIsActive(initial) ? initial : (device_lifecycle_state_t) kUntouchedSourceState),
                "active -> FAILED source report differed");

        atomicStoreRelaxed(&lifecycle, value);
        deviceLifecycleTransitionToStopping(&lifecycle);
        const device_lifecycle_state_t stopped =
            initial == kDeviceLifecycleDown ? kDeviceLifecycleDown : kDeviceLifecycleStopping;
        require(deviceLifecycleLoad(&lifecycle) == stopped, "transition-to-STOPPING final state differed");

        atomicStoreRelaxed(&lifecycle, value);
        deviceLifecycleTransitionStoppingToDown(&lifecycle);
        require(deviceLifecycleLoad(&lifecycle) == kDeviceLifecycleDown, "transition-to-DOWN final state differed");
    }
}

int main(void)
{
    atomic_int            lifecycle;
    tun_lifecycle_state_t failed_from;
    atomic_init(&lifecycle, kTunLifecycleDown);

    testSharedTransitionTable();

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

    /*
     * Failure during STARTING prevents STARTING -> UP, and must report
     * kTunLifecycleStarting. That source state is what tells the I/O thread
     * wrapper this is a bring-up rollback and not a runtime loss, so it must not
     * request process shutdown.
     */
    require(tunLifecycleTransitionDownToStarting(&lifecycle), "second start failed");
    failed_from = kUntouchedSourceState;
    require(tunLifecycleTransitionToFailed(&lifecycle, &failed_from), "STARTING -> FAILED failed");
    require(failed_from == kTunLifecycleStarting, "STARTING -> FAILED did not report STARTING as the source state");
    require(tunLifecycleLoad(&lifecycle) == kTunLifecycleFailed, "FAILED was not published during startup");
    require(! tunLifecycleTransitionStartingToUp(&lifecycle), "FAILED was overwritten with UP");

    // Only one of two simulated wrappers can win the first active-to-failed
    // transition, and the loser must not touch the caller's source state.
    tun_lifecycle_state_t loser_source = kUntouchedSourceState;
    require(! tunLifecycleTransitionToFailed(&lifecycle, &loser_source), "a second wrapper won the FAILED transition");
    require(loser_source == kUntouchedSourceState, "a losing FAILED transition overwrote the reported source state");
    require(failed_from == kTunLifecycleStarting, "a losing FAILED transition clobbered the winner's source state");

    // Cleanup from FAILED
    tunLifecycleTransitionToStopping(&lifecycle);
    require(tunLifecycleLoad(&lifecycle) == kTunLifecycleStopping, "FAILED -> STOPPING failed");
    tunLifecycleTransitionStoppingToDown(&lifecycle);

    /*
     * Failure after publication changes UP -> FAILED and must report
     * kTunLifecycleUp: this is the runtime loss of a published device, the case
     * that makes the wrapper request an orderly process shutdown.
     */
    require(tunLifecycleTransitionDownToStarting(&lifecycle), "third start failed");
    require(tunLifecycleTransitionStartingToUp(&lifecycle), "third startup publication failed");
    failed_from = kUntouchedSourceState;
    require(tunLifecycleTransitionToFailed(&lifecycle, &failed_from), "UP -> FAILED failed");
    require(failed_from == kTunLifecycleUp, "UP -> FAILED did not report UP as the source state");
    require(tunLifecycleLoad(&lifecycle) == kTunLifecycleFailed, "FAILED was not published after startup");

    // FAILED -> STARTING is rejected
    require(! tunLifecycleTransitionDownToStarting(&lifecycle), "FAILED -> STARTING was accepted");

    // Cleanup
    tunLifecycleTransitionToStopping(&lifecycle);
    tunLifecycleTransitionStoppingToDown(&lifecycle);

    // A wrapper observing STOPPING does not publish FAILED: the routine returned
    // because normal teardown asked it to, so no failure is reported.
    require(tunLifecycleTransitionDownToStarting(&lifecycle), "fourth start failed");
    tunLifecycleTransitionToStopping(&lifecycle);
    failed_from = kUntouchedSourceState;
    require(! tunLifecycleTransitionToFailed(&lifecycle, &failed_from), "STOPPING was overwritten with FAILED");
    require(failed_from == kUntouchedSourceState, "a rejected STOPPING -> FAILED reported a source state");
    require(tunLifecycleLoad(&lifecycle) == kTunLifecycleStopping, "STOPPING did not remain published");

    // DOWN -> FAILED is rejected too: a device that was never started cannot
    // fail, and the reported source state must stay untouched.
    tunLifecycleTransitionStoppingToDown(&lifecycle);
    require(tunLifecycleLoad(&lifecycle) == kTunLifecycleDown, "STOPPING -> DOWN failed");
    failed_from = kUntouchedSourceState;
    require(! tunLifecycleTransitionToFailed(&lifecycle, &failed_from), "DOWN was overwritten with FAILED");
    require(failed_from == kUntouchedSourceState, "a rejected DOWN -> FAILED reported a source state");
    require(tunLifecycleLoad(&lifecycle) == kTunLifecycleDown, "DOWN did not remain published");

    // A NULL out-parameter is accepted for callers that only need the verdict.
    require(tunLifecycleTransitionDownToStarting(&lifecycle), "fifth start failed");
    require(tunLifecycleTransitionToFailed(&lifecycle, NULL), "FAILED transition rejected a NULL source state");
    require(tunLifecycleLoad(&lifecycle) == kTunLifecycleFailed, "FAILED was not published with a NULL out-parameter");

    return 0;
}

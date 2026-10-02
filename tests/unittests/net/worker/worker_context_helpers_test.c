/*
 * Covers: Worker-context accessors, message admission and settlement, cross-worker pipe/HalfDuplex
 * callbacks and worker teardown.
 * Setup: The suite-local fixture owns nine real workers and deterministic enqueue/wakeup/timed-rearm
 * seams; individual forked cases retain their process boundaries.
 * Cases: Accessor module, message module, pipe cases, conditional HalfDuplex cases and teardown races
 * are called explicitly below. --line-refcount-publication-only selects the publication case without
 * shared runtime initialization.
 * Checks: Owner authority, FIFO/fairness, task-or-cancel accounting, line/buffer references and shutdown
 * outcomes remain in their case modules.
 * Limits: Fork cases are conditional on platform support; link-wrap failure cases retain their build
 * condition.
 * Organization: Forked cases precede shared initialization; live pipe, HalfDuplex, pool and batch cases
 * precede races that close admission for workers 1–8. The driver owns final runtime shutdown.
 * CTest: waterwall.worker_context_helpers_unit
 */
#include "worker_fixture.h"

static void testMessageAdmissionRacesWorkerTeardown(void)
{
    /* Exercise a live target before the teardown-race cases permanently close
     * worker admission for workers 1 through 8. The pipe fixture finalizes all
     * chain-owned pools before it publishes workers_run_flag, so worker startup
     * cannot race global allocation-padding construction. */
    testPipePublicationIsLinearizedWithPreStop();
    testPipePayloadFinishLateAndRefused();
    testWorkerMessagePoolCrossWorkerReturn();
#ifdef WW_TEST_HALFDUPLEX_WORKERS
    testHalfDuplexWorkers();
#endif
    testWorkerMessageBatchOrderingAndFairness();
    testWorkerMessageFullBatchFifoAndFairness();
#ifdef WW_WORKER_MESSAGE_LINK_WRAP
    testWorkerMessageHardSuccessorWakeFallback();
    testWakeupFailurePreservesBothOwnershipContracts();
#endif
    runTeardownWinsRace(1, kRacePostNormal);
    runTeardownWinsRace(2, kRacePostWithCleanup);
    runTeardownWinsRace(3, kRacePostRetainOnRefusal);
    runTeardownWinsRace(4, kRacePostTimed);
    runEnqueueWinsRace(5, kRacePostNormal);
    runEnqueueWinsRace(6, kRacePostWithCleanup);
    runEnqueueWinsRace(7, kRacePostRetainOnRefusal);
    runEnqueueWinsRace(8, kRacePostTimed);
}

int main(int argc, char **argv)
{
    testCaseSet("worker_context_helpers_test");
    if (argc == 2 && strcmp(argv[1], "--line-refcount-publication-only") == 0)
    {
        testLineRefcountPublishesTeardownToFinalReleaser();
        return 0;
    }

    testWorkerMessageConstructionTransactional();
    testWorkerMessageInitialCapacity();
#if defined(WW_WORKER_MESSAGE_LINK_WRAP) && defined(HAS_UNIX_FORK)
    testTimedRearmRefusalInIsolatedProcess();
#endif
#if defined(HAS_UNIX_FORK)
    testLocalBatchCleanupCannotReadmitInIsolatedProcess();
    testLocalBatchQuiescencePositionsInIsolatedProcess();
    testPendingCleanupReentryInIsolatedProcess();
    testForeignDelayedCancellationInIsolatedProcess();
    testDelayedPatternCompletionAndCancellationInIsolatedProcess();
#endif
    initTestGlobalState();

    testAccessorsOnOwningWorker();
    testWorkerTimerPools();
    testWorkerMessagePoolLocalReuse();
    testPredicatesRejectUnregisteredAndOutOfRange();

    testOwningWorkerOutsideCallbackQueues();
    testTransactionalEnqueueFailureStages();
    testOtherEventWorkerQueues();
    testUnregisteredThreadQueues();
    testOutOfRangeCallerQueues();
    testInvalidTargetsCleanUpExactlyOnce();
    testAdmissionOpenIsOneWayAndChecked();
    testMessageAdmissionRacesWorkerTeardown();

    testTunnelApiHelpersRejectNonEventWorkers();
    testResolverRejectsForeignCallers();
    testLineResolverRejectsForeignCallers();
    testPipeToRejectsBadWorkers();

    testTeardownCleanupCannotReadmitMessages();

    shutdownTestGlobalState();

#if defined(HAS_UNIX_FORK)
    testCheckedAccessorsAbortOffEventWorkers();
#endif

    return 0;
}

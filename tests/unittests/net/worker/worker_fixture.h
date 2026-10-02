#pragma once
/* Shared nine-worker runtime and deterministic enqueue/blocker seams. The
 * driver owns initialization and final shutdown; groups never acquire a fresh
 * runtime implicitly. Case identity stays fixed until every worker joins. */
#include "ev_memory.h"
#include "global_state.h"
#include "wloop_internal.h"
#include "worker.h"
#include "worker_message_batch.h"
#include "worker_messages.h"
#include "worker_messages_internal.h"
#include "wwapi.h"

#if defined(__unix__) || defined(__APPLE__) || defined(UNIX)
#include <sys/wait.h>
#include <unistd.h>
#define HAS_UNIX_FORK 1
#endif
typedef enum
{
    kRacePostNormal = 0,
    kRacePostWithCleanup,
    kRacePostRetainOnRefusal,
    kRacePostTimed
} race_post_kind_e;
typedef struct worker_loop_blocker_s
{
    atomic_bool entered;
    atomic_bool release;
    atomic_int  nested_runs;
    atomic_int  nested_cleanups;
    bool        run_nested_after_close;
} worker_loop_blocker_t;

#include "test_assert.h"

#define require(condition, message) TEST_REQUIRE(TEST_FAILURE_EXIT, condition, message)
extern atomic_int  g_enqueue_pause_stage;
extern atomic_int  g_enqueue_pause_wid;
extern atomic_bool g_force_timed_rearm_refusal;
extern atomic_bool g_enqueue_seam_reached;
extern atomic_bool g_enqueue_seam_release;
extern atomic_int  g_enqueue_seam_hits;
#ifdef WW_WORKER_MESSAGE_LINK_WRAP
extern atomic_bool g_fail_wakeup_post;
#endif
void                          watchBufferDisposal(sbuf_t *buf, atomic_uint *counter);
void                          teardownCurrentWorker(worker_t *worker);
void                          initTestGlobalState(void);
void                          shutdownTestGlobalState(void);
void                          waitForAtomicBool(const atomic_bool *value, const char *message);
void                          testAccessorsOnOwningWorker(void);
void                          testWorkerTimerPools(void);
void                          testWorkerMessagePoolLocalReuse(void);
void                          testPredicatesRejectUnregisteredAndOutOfRange(void);
void                          testTunnelApiHelpersRejectNonEventWorkers(void);
void                          testResolverRejectsForeignCallers(void);
void                          testLineResolverRejectsForeignCallers(void);
void                          testCheckedAccessorsAbortOffEventWorkers(void);
void                          testWorkerMessageConstructionTransactional(void);
void                          testWorkerMessageInitialCapacity(void);
void                          testTransactionalEnqueueFailureStages(void);
void                          testWorkerMessagePoolCrossWorkerReturn(void);
void                          testTimedRearmRefusalInIsolatedProcess(void);
void                          testWorkerMessageBatchOrderingAndFairness(void);
void                          testWorkerMessageFullBatchFifoAndFairness(void);
void                          testWorkerMessageHardSuccessorWakeFallback(void);
void                          testLocalBatchCleanupCannotReadmitInIsolatedProcess(void);
void                          testLocalBatchQuiescencePositionsInIsolatedProcess(void);
void                          testPendingCleanupReentryInIsolatedProcess(void);
void                          testForeignDelayedCancellationInIsolatedProcess(void);
void                          testDelayedPatternCompletionAndCancellationInIsolatedProcess(void);
void                          testAdmissionOpenIsOneWayAndChecked(void);
void                          testOwningWorkerOutsideCallbackQueues(void);
void                          testOtherEventWorkerQueues(void);
void                          testUnregisteredThreadQueues(void);
void                          testOutOfRangeCallerQueues(void);
void                          testInvalidTargetsCleanUpExactlyOnce(void);
void                          runTeardownWinsRace(wid_t wid, race_post_kind_e kind);
void                          runEnqueueWinsRace(wid_t wid, race_post_kind_e kind);
void                          testWakeupFailurePreservesBothOwnershipContracts(void);
void                          testLineRefcountPublishesTeardownToFinalReleaser(void);
void                          testTeardownCleanupCannotReadmitMessages(void);
void                          testPipeToRejectsBadWorkers(void);
void                          testPipePublicationIsLinearizedWithPreStop(void);
void                          testPipePayloadFinishLateAndRefused(void);
void                          testHalfDuplexWorkers(void);
const ww_lifecycle_context_t *testShutdownContext(void);
WTHREAD_ROUTINE(messagePoolForeignRoutine);
void pipeTunnelAfterFastStopCheckTestSeam(tunnel_t *wrapper, line_t *source_line);
void workerLoopBlockerCallback(worker_t *worker, void *arg1, void *arg2, void *arg3);
void pipeQueueBarrier(worker_t *worker, void *arg1, void *arg2, void *arg3);

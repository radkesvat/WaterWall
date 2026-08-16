#pragma once

#include "async_dns.h"
#include "lifecycle.h"
#include "threadsafe_generic_pool.h"
#include "watomic.h"
#include "wlibc.h"
#include "wloop.h"
#include "wthread.h"

typedef uint8_t        wid_t;
typedef _Atomic(wid_t) atomic_wid_t;

enum
{
    kInvalidWID = UINT8_MAX,
};

typedef struct worker_message_queue_s worker_message_queue_t;

/**
 * @brief Worker lifecycle state, stored atomically and only ever advanced.
 *
 * Requests are published by the main coordinator. Acknowledgements are
 * published by the owner worker after the represented work is complete.
 */
typedef enum
{
    kWorkerLifecycleInitialized = 0, // resources created, thread not running yet
    kWorkerLifecycleRunning,         // worker routine entered
    kWorkerLifecycleQuiesceRequested,
    kWorkerLifecycleQuiesced,
    kWorkerLifecycleDrainRequested,
    kWorkerLifecycleDrained,
    kWorkerLifecycleTeardownRequested,
    kWorkerLifecycleExited,
    kWorkerLifecycleJoined
} worker_lifecycle_e;

/**
 * @brief Structure representing a worker.
 */
typedef struct worker_s
{

    // Thread-safe pool for managing WIO objects.
    // functions like wloopPostEvent allocate WIO from target wid loop.
    threadsafe_generic_pool_t *wios_pool;

    /*
     * `loop` and `message_queue` are published and detached together. Foreign
     * posters must hold control_mutex while reading either pointer and while
     * using the referenced object. If both locks are needed, the global order
     * is control_mutex followed by worker_message_queue_s::mutex.
     */
    wloop_t                *loop;          // Event loop associated with the worker.
    dns_resolver_t          dns_resolver;  // Worker-local async DNS resolver.
    buffer_pool_t          *buffer_pool;   // Buffer pool for managing memory buffers.
    generic_pool_t         *context_pool;  // Generic pool for managing context objects.
    worker_message_queue_t *message_queue; // Worker-owned queued/timed messages.
    wthread_t               thread;        // Thread associated with the worker.
    // Lifetime lock for loop/message_queue and the worker phase protocol.
    wmutex_t               control_mutex;
    wcond_mutex_t          control_condition_mutex;
    wcondvar_t             control_condition;
    atomic_int             lifecycle;           // worker_lifecycle_e
    atomic_bool            resources_destroyed; // guards one-shot own-resource teardown
    ww_lifecycle_context_t lifecycle_context;
    bool                   lifecycle_context_set;
    /*
     * The authoritative admission gate for every worker-message delivery
     * shape: inline, queued, and timed. It is closed before loop/queue
     * detachment, so teardown callbacks cannot re-admit work merely because
     * they still execute with this worker's TLS identity.
     */
    atomic_bool message_admission_open;
    bool        thread_valid; // True only after native thread handle creation succeeds.
    // True when this worker owns an event loop. Pseudo-workers (currently the
    // lwIP worker) do not, and must be identified by this flag rather than by a
    // null `loop`, which a normal worker also clears while tearing down.
    bool  has_event_loop;
    tid_t tid; // Os Thread Id
    wid_t wid; // Worker ID.

} worker_t;

extern thread_local wid_t tl_wid; // Thread-local worker ID. */

/**
 * @brief Initializes a worker.
 * @param worker Pointer to the worker to initialize.
 * @param tid Worker ID.
 * @param eventloop  create eventloop for this thread
 */
bool workerInit(worker_t *worker, wid_t wid, bool eventloop);

/**
 * Transactionally construct the worker's WIO and context pool metadata.
 * Returns false without publishing either pool when any constructor fails.
 */
bool workerTryCreateCorePools(worker_t *worker);
bool workerTryCreateBufferPool(worker_t *worker);

/**
 * @brief Runs the worker.
 * @param worker Pointer to the worker to run.
 */
void workerRun(worker_t *worker);

/**
 * @brief Runs the worker in a new thread.
 * @param worker Pointer to the worker to run.
 * @return `kWThreadErrorNone` on success, otherwise native thread-creation error.
 */
wthread_error_t workerSpawn(worker_t *worker);

/**
 * @brief Binds the current thread to a registered worker instance.
 * @param worker Pointer to the target worker structure.
 */
void workerBindCurrentThread(worker_t *worker);

/**
 * @brief Unbinds the current thread from its worker role, restoring kInvalidWID.
 */
void workerUnbindCurrentThread(void);

/**
 * @brief Whether @p wid is a valid registered worker slot (including pseudo-workers).
 */
bool workerWIDIsRegistered(wid_t wid);

/**
 * @brief Whether @p wid is a registered ordinary event worker.
 */
bool workerWIDIsEventWorker(wid_t wid);

/**
 * @brief Whether the current thread owns a registered worker slot.
 */
bool currentThreadHasRegisteredWID(void);

/**
 * @brief Whether the current thread is a registered ordinary event worker.
 */
bool currentThreadIsEventWorker(void);

/**
 * @brief Whether the current thread is a registered event worker and owns @p wid.
 */
bool currentThreadIsEventWorkerWID(wid_t wid);

/**
 * @brief Diagnostic integer conversion for worker IDs, rendering kInvalidWID as -1.
 *
 * Diagnostic logging helper only. Preserves every valid WID (including the lwIP
 * pseudo-worker) numerically and converts kInvalidWID to -1 for formatters using %d.
 * Does not validate whether a non-sentinel WID is currently registered.
 *
 * @param wid Worker ID to convert.
 * @return Integer representation of @p wid, or -1 for kInvalidWID.
 */
static inline int workerWIDForLog(wid_t wid)
{
    return wid == kInvalidWID ? -1 : (int) wid;
}

/**
 * @brief Test-only helper to bind the current thread to a test WID.
 */
static inline void testWorkerBindWID(wid_t wid)
{
    tl_wid = wid;
}

/**
 * @brief Test-only helper to restore kInvalidWID on the current thread.
 */
static inline void testWorkerUnbindWID(void)
{
    tl_wid = kInvalidWID;
}

/**
 * @brief Resolves a domain on the current worker's async DNS channel.
 *
 * The caller must pass its own worker ID. This helper is intentionally
 * worker-local and asserts if called for a different worker.
 */
int workerResolveDomainAsync(wid_t wid, const char *domain, dns_resolve_cb cb, void *userdata);

/**
 * @brief Resolves a domain/service pair on the current worker's async DNS channel.
 *
 * The caller must pass its own worker ID. socktype may be 0, SOCK_STREAM, or
 * SOCK_DGRAM depending on the intended socket use.
 */
int workerResolveDomainServiceAsync(wid_t wid, const char *domain, const char *service, int socktype, dns_resolve_cb cb,
                                    void *userdata);

/**
 * @brief Gets the worker ID of the current thread.
 * @return The worker ID, or kInvalidWID if called from an unregistered thread.
 */
static inline wid_t getWID(void)
{
    return tl_wid;
}

/**
 * @brief Close normal admission and request worker quiescence.
 *
 * Advances the lifecycle to kWorkerLifecycleQuiesceRequested and wakes the
 * worker's event loop through its lifecycle-control path. Safe before the loop starts
 * running, safe while it is blocked in the poller, safe when the worker already
 * exited, and safe to repeat.
 *
 * The caller must not assume the worker quiesced when this returns; wait for
 * kWorkerLifecycleQuiesced before releasing external producers.
 *
 * @param worker Pointer to the worker structure.
 * The boolean wrappers return false only when the request is unavailable. Use
 * the typed result when immediate wake delivery matters diagnostically.
 */
typedef enum worker_quiesce_request_result_e
{
    kWorkerQuiesceRequestUnavailable = 0,
    kWorkerQuiesceRequestAcceptedWakeDelivered,
    kWorkerQuiesceRequestAcceptedWakeDegraded,
    kWorkerQuiesceRequestAlreadyAccepted
} worker_quiesce_request_result_e;

worker_quiesce_request_result_e workerRequestQuiesceResult(worker_t *worker);
worker_quiesce_request_result_e workerRequestQuiesceWithContextResult(worker_t                     *worker,
                                                                      const ww_lifecycle_context_t *context);
worker_quiesce_request_result_e workerInstallApplicationQuiesceRequest(worker_t                     *worker,
                                                                       const ww_lifecycle_context_t *context);
bool                            workerRequestQuiesce(worker_t *worker);
bool workerRequestQuiesceWithContext(worker_t *worker, const ww_lifecycle_context_t *context);

/**
 * @brief Whether this worker has been asked to stop.
 */
bool workerQuiesceRequested(const worker_t *worker);

/**
 * @brief Publish a drain or teardown release to a parked worker.
 */
bool workerRequestDrain(worker_t *worker);
bool workerRequestTeardown(worker_t *worker);

/** @brief Wait until the worker reaches at least @p phase. */
bool workerWaitForPhase(worker_t *worker, worker_lifecycle_e phase, uint32_t timeout_ms);

/** @brief Current worker lifecycle phase. */
worker_lifecycle_e workerGetLifecycle(const worker_t *worker);

/** Owner-worker lifecycle stages. */
void workerPerformQuiesce(worker_t *worker, const ww_lifecycle_context_t *context);
void workerPerformDrain(worker_t *worker, const ww_lifecycle_context_t *context);
void workerPerformTeardown(worker_t *worker);

/**
 * @brief Destroy the worker's own event-loop-local resources. Runs at most once.
 *
 * Ownership rules:
 *   - a worker thread calls this for itself after its loop returned;
 *   - worker 0 calls it for itself, on worker 0;
 *   - a pseudo-worker has no WaterWall event loop or workerSpawn() thread and
 *     is cleaned up by the shutdown thread only after any external thread that
 *     uses its resources (such as lwIP's tcpip_thread) has been joined.
 * It must never be called for another worker that owns a running event loop.
 *
 * @param worker Pointer to the worker structure.
 */
void workerDestroyPseudoWorkerResources(worker_t *worker);

/** Destroy an event worker whose OS thread was never created. */
void workerDestroyUnstartedResources(worker_t *worker);

/**
 * @brief Waits for a worker's spawned OS thread to exit.
 *
 * Does not advance the worker lifecycle. Use only after the worker has reached
 * kWorkerLifecycleExited.
 *
 * @param worker Pointer to the worker structure.
 * @return true after a confirmed join, false while thread ownership remains.
 */
bool workerJoin(worker_t *worker);

/**
 * @brief Advance a single worker through quiesce, drain, and teardown, then join.
 *
 * Convenience wrapper; prefer requesting every worker to stop before joining any
 * of them.
 *
 * @param worker Pointer to the worker structure.
 * @return true after a confirmed join, false while thread ownership remains.
 */
bool workerExitJoin(worker_t *worker);

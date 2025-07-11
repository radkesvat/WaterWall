#pragma once

#include "generic_pool.h"
#include "watomic.h"
#include "wlibc.h"
#include "wloop.h"
#include "wthread.h"

typedef uint8_t        wid_t;
typedef _Atomic(wid_t) atomic_wid_t;

/**
 * @brief Structure representing a worker.
 */
typedef struct worker_s
{
    wloop_t        *loop;                // Event loop associated with the worker.
    buffer_pool_t  *buffer_pool;         // Buffer pool for managing memory buffers.
    generic_pool_t *context_pool;        // Generic pool for managing context objects.
    generic_pool_t *pipetunnel_msg_pool; // Generic pool for managing pipe tunnel messages.
    wthread_t       thread;              // Thread associated with the worker.
    tid_t           tid;                 // Os Thread Id
    wid_t           wid;                 // Worker ID.

} worker_t;

extern thread_local wid_t tl_wid; // Thread-local worker ID. */

/**
 * @brief Initializes a worker.
 * @param worker Pointer to the worker to initialize.
 * @param tid Worker ID.
 * @param eventloop  create eventloop for this thread
 */
void workerInit(worker_t *worker, wid_t wid, bool eventloop);

/**
 * @brief Runs the worker.
 * @param worker Pointer to the worker to run.
 */
void workerRun(worker_t *worker);

/**
 * @brief Runs the worker in a new thread.
 * @param worker Pointer to the worker to run.
 */
void workerSpawn(worker_t *worker);

/**
 * @brief Gets the worker ID of the current thread.
 * @return The worker ID.
 */
static inline wid_t getWID(void)
{
    return tl_wid;
}

/**
 * @brief Tells a worker that it should stop immediately
 *
 * Signals the worker's event loop to finish , but dose not woit (join theard)
 * if it is our own thread, it also frees resources
 * @param worker Pointer to the worker structure.
 */
void workerFinish(worker_t *worker);

/**
 * @brief Cleanly exits a worker.
 *
 * Signals the worker's event loop to run once, waits for the worker thread to finish,
 * and destroys allocated resource pools. (if its our own thread, otherwise other worker dose that it self)
 *
 * @param worker Pointer to the worker structure.
 */
void workerExitJoin(worker_t *worker);

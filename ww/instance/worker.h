#pragma once

#include "generic_pool.h"
#include "wlibc.h"
#include "wloop.h"
#include "wthread.h"
#include "watomic.h"


typedef uint8_t wid_t;
typedef _Atomic(wid_t) atomic_wid_t;

/**
 * @brief Structure representing a worker.
 */
typedef struct worker_s
{
    wloop_t        *loop;              /**< Event loop associated with the worker. */
    buffer_pool_t  *buffer_pool;       /**< Buffer pool for managing memory buffers. */
    generic_pool_t *context_pool;      /**< Generic pool for managing context objects. */
    generic_pool_t *pipetunnel_msg_pool; /**< Generic pool for managing pipe tunnel messages. */
    wthread_t       thread;            /**< Thread associated with the worker. */
    wid_t           wid;               /**< Worker ID. */

} worker_t;

extern thread_local wid_t tl_wid; /**< Thread-local worker ID. */

/**
 * @brief Initializes a worker.
 * @param worker Pointer to the worker to initialize.
 * @param tid Worker ID.
 */
void workerInit(worker_t *worker, wid_t tid);

/**
 * @brief Runs the worker.
 * @param worker Pointer to the worker to run.
 */
void workerRun(worker_t *worker);

/**
 * @brief Runs the worker in a new thread.
 * @param worker Pointer to the worker to run.
 */
void workerRunNewThread(worker_t *worker);

/**
 * @brief Gets the worker ID of the current thread.
 * @return The worker ID.
 */
static inline wid_t getWID(void){
    return tl_wid;
}

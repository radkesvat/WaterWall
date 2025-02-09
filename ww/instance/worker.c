#include "worker.h"
#include "context.h"
#include "global_state.h"
#include "pipe_tunnel.h"
#include "tunnel.h"
#include "wloop.h"
#include "wthread.h"



thread_local wid_t tl_wid;

/**
 * @brief Initializes a worker.
 *
 * This function initializes a worker by setting its ID, creating context and message pools,
 * and creating an event loop.
 *
 * @param worker Pointer to the worker to initialize.
 * @param wid  Worker ID.
 */
void workerInit(worker_t *worker, wid_t wid)
{
    *worker = (worker_t){.wid = wid};

    worker->context_pool = genericpoolCreateWithDefaultAllocatorAndCapacity(
        GSTATE.masterpool_context_pools, sizeof(context_t), (16) + GSTATE.ram_profile);

    worker->pipetunnel_msg_pool = genericpoolCreateWithDefaultAllocatorAndCapacity(
        GSTATE.masterpool_pipetunnel_msg_pools, pipeLineGetMesageSize(), (8) + GSTATE.ram_profile);

    worker->buffer_pool = bufferpoolCreate(GSTATE.masterpool_buffer_pools_large, GSTATE.masterpool_buffer_pools_small,
                                           (0) + GSTATE.ram_profile,LARGE_BUFFER_SIZE, SMALL_BUFFER_SIZE );

    // note that loop depeneds on worker->buffer_pool
    worker->loop = wloopCreate(WLOOP_FLAG_AUTO_FREE, worker->buffer_pool, wid);
}

/**
 * @brief Runs the worker.
 *
 * This function sets the thread-local worker ID, initializes the random number generator,
 * runs the event loop, and destroys the event loop.
 *
 * @param worker Pointer to the worker to run.
 */
void workerRun(worker_t *worker)
{
    tl_wid = worker->wid;
    frandInit();
    wloopRun(worker->loop);
    wloopDestroy(&worker->loop);
}

/**
 * @brief Worker thread routine.
 *
 * This function is the entry point for the worker thread. It runs the worker and returns 0.
 *
 * @param userdata Pointer to the worker.
 * @return 0.
 */
static WTHREAD_ROUTINE(worker_thread) // NOLINT
{
    worker_t *worker = userdata;

    workerRun(worker);

    return 0;
}

/**
 * @brief Runs the worker in a new thread.
 *
 * This function creates a new thread and runs the worker in it.
 *
 * @param worker Pointer to the worker to run.
 */
void workerRunNewThread(worker_t *worker)
{
    worker->thread = threadCreate(worker_thread, worker);
}

#include "worker.h"
#include "context.h"
#include "global_state.h"
#include "managers/signal_manager.h"
#include "pipe_tunnel.h"
#include "tunnel.h"
#include "wevent.h"
#include "wloop.h"
#include "wthread.h"

#include "loggers/internal_logger.h"

thread_local wid_t tl_wid;

/**
 * @brief Cleanly exits a worker.
 *
 * Signals the worker's event loop to run once, waits for the worker thread to finish,
 * and destroys allocated resource pools.
 *
 * @param worker Pointer to the worker structure.
 */
void workerExitJoin(worker_t *worker)
{
    if (worker->tid == getTID())
    {
        if (worker->loop)
        {
            wloopDestroy(&worker->loop);
        }

        genericpoolDestroy(worker->context_pool);
        genericpoolDestroy(worker->pipetunnel_msg_pool);
        bufferpoolDestroy(worker->buffer_pool);
    }
    else
    {
        if (worker->loop)
        {
            worker->loop->flags = worker->loop->flags | WLOOP_FLAG_RUN_ONCE;
            atomicThreadFence(memory_order_release);
            threadJoin(worker->thread);
        }
        else
        {
            // lwip thread
            genericpoolDestroy(worker->context_pool);
            genericpoolDestroy(worker->pipetunnel_msg_pool);
            bufferpoolDestroy(worker->buffer_pool);
        }
    }
    worker->loop                = NULL;
    worker->context_pool        = NULL;
    worker->pipetunnel_msg_pool = NULL;
    worker->buffer_pool         = NULL;
}

// /**
//  * @brief Signal handler for worker exit.
//  *
//  * Invoked when a termination signal is received and calls workerExitJoin.
//  *
//  * @param userdata Pointer to the worker structure.
//  * @param signum Signal number.
//  */
// static void exitHandle(void *userdata, int signum)
// {
//     discard   signum;
//     worker_t *worker = userdata;
//     workerExitJoin(worker);
// }

/**
 * @brief Initializes a worker.
 *
 * This function initializes a worker by setting its ID, creating context and message pools,
 * and creating an event loop.
 *
 * @param worker Pointer to the worker to initialize.
 * @param wid  Worker ID.
 * @param eventloop  create eventloop for this thread
 */
void workerInit(worker_t *worker, wid_t wid, bool eventloop)
{
    *worker = (worker_t) {.wid = wid};

    worker->context_pool = genericpoolCreateWithDefaultAllocatorAndCapacity(GSTATE.masterpool_context_pools,
                                                                            sizeof(context_t), RAM_PROFILE);

    worker->pipetunnel_msg_pool = genericpoolCreateWithDefaultAllocatorAndCapacity(
        GSTATE.masterpool_pipetunnel_msg_pools, (uint32_t) pipeTunnelGetMesageSize(), RAM_PROFILE);

    worker->buffer_pool = bufferpoolCreate(GSTATE.masterpool_buffer_pools_large, GSTATE.masterpool_buffer_pools_small,
                                           RAM_PROFILE, PROPER_LARGE_BUFFER_SIZE(RAM_PROFILE), SMALL_BUFFER_SIZE);

    if (eventloop)
    {
        // note that loop depeneds on worker->buffer_pool
        worker->loop = wloopCreate(WLOOP_FLAG_AUTO_FREE, worker->buffer_pool, wid);
    }
    else
    {
        worker->loop = NULL;
    }
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
    tl_wid    = worker->wid;
    wid_t wid = worker->wid;

    wloopRun(worker->loop);

    genericpoolDestroy(worker->context_pool);
    genericpoolDestroy(worker->pipetunnel_msg_pool);
    bufferpoolDestroy(worker->buffer_pool);
    wloopDestroy(&worker->loop);

    LOGD("Worker %d cleanly exited !", wid);
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
    worker->tid      = getTID();
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
void workerSpawn(worker_t *worker)
{
    worker->thread = threadCreate(worker_thread, worker);
}

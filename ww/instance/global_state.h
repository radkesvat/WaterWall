#pragma once

#include "wlibc.h"

#include "buffer_pool.h"
#include "generic_pool.h"
#include "wloop.h"
#include "worker.h"

/*
    This is a global state file that powers many WW things up

    this also dose not limit loading another WW lib dynamically, it manages
    the loaded library and sets it up so there is no such problem of multiple global symbols

*/

typedef struct
{
    char *log_file_path;
    char *log_level;
    bool  log_console;

} logger_construction_data_t;

typedef err_t (*LwipV4Hook)(struct pbuf *, struct netif *);
typedef void (*WorkerMessageCalback)(worker_t *worker, void *arg1, void *arg2, void *arg3);

typedef struct ww_global_state_s
{
    wloop_t                  **shortcut_loops;
    buffer_pool_t            **shortcut_buffer_pools;
    generic_pool_t           **shortcut_context_pools;
    generic_pool_t           **shortcut_pipetunnel_msg_pools;
    master_pool_t             *masterpool_buffer_pools_large;
    master_pool_t             *masterpool_buffer_pools_small;
    master_pool_t             *masterpool_context_pools;
    master_pool_t             *masterpool_pipetunnel_msg_pools;
    master_pool_t             *masterpool_messages;
    worker_t                  *workers;
    struct signal_manager_s   *signal_manager;
    struct socket_manager_s   *socekt_manager;
    struct node_manager_s     *node_manager;
    struct logger_s           *core_logger;
    struct logger_s           *network_logger;
    struct logger_s           *dns_logger;
    struct logger_s           *internal_logger;
    struct dedicated_memory_s *openssl_dedicated_memory;
    LwipV4Hook                 lwip_process_v4_hook;
    void                      *wintun_dll_handle;
    void                      *windivert_dll_handle;
    uint32_t                   workers_count;
    uint32_t                   ram_profile;
    uint64_t                   main_thread_id;
    wid_t                      lwip_wid;
    atomic_wid_t               distribute_wid;
    uint16_t                   buffer_allocation_padding;
    uint16_t                   capturedevice_queue_start_number;
    uint16_t                   mtu_size;
    uint8_t                    flag_initialized : 1;
    uint8_t                    flag_buffers_calculated : 1;
    uint8_t                    flag_tundev_windows_initialized : 1;
    uint8_t                    flag_openssl_initialized : 1;
    uint8_t                    flag_libsodium_initialized : 1;
    uint8_t                    flag_lwip_initialized : 1;
    atomic_bool                application_stopping_flag; // prevent threads sending messages to each other
    atomic_bool                workers_run_flag;          // main thread sets this to true when it started its loop

} ww_global_state_t;

typedef struct
{
    unsigned int               workers_count;
    enum ram_profiles_e        ram_profile;
    uint16_t                   mtu_size;
    logger_construction_data_t internal_logger_data;
    logger_construction_data_t core_logger_data;
    logger_construction_data_t network_logger_data;
    logger_construction_data_t dns_logger_data;

} ww_construction_data_t;

extern ww_global_state_t global_ww_state;

#define GSTATE           global_ww_state
#define GLOBAL_MTU_SIZE  global_ww_state.mtu_size
#define RAM_PROFILE      global_ww_state.ram_profile
#define WORKERS          global_ww_state.workers
#define WORKERS_COUNT    global_ww_state.workers_count
#define WORKER_ADDITIONS 1 // 1 for lwip thread (included in workers_count)

/*!
 * @brief Get the number of workers.
 *
 * @return The number of workers.
 */
static inline wid_t getWorkersCount(void)
{
    return (wid_t) WORKERS_COUNT;
}

/*!
 * @brief Get a worker by its ID.
 *
 * @param wid The worker ID.
 * @return A pointer to the worker.
 */
static inline worker_t *getWorker(wid_t wid)
{
    return &(WORKERS[wid]);
}

/*!
 * @brief Get the buffer pool for a worker.
 *
 * @param wid The worker ID.
 * @return A pointer to the buffer pool.
 */
static inline buffer_pool_t *getWorkerBufferPool(wid_t wid)
{
    return GSTATE.shortcut_buffer_pools[wid];
}

/*!
 * @brief Get the context pool for a worker.
 *
 * @param wid The worker ID.
 * @return A pointer to the context pool.
 */
static inline generic_pool_t *getWorkerContextPool(wid_t wid)
{
    return GSTATE.shortcut_context_pools[wid];
}

/*!
 * @brief Get the pipe tunnel message pool for a worker.
 *
 * @param wid The worker ID.
 * @return A pointer to the pipe tunnel message pool.
 */
static inline generic_pool_t *getWorkerPipeTunnelMsgPool(wid_t wid)
{
    return GSTATE.shortcut_pipetunnel_msg_pools[wid];
}

/*!
 * @brief Get the event loop for a worker.
 *
 * @param wid The worker ID.
 * @return A pointer to the event loop.
 */
static inline struct wloop_s *getWorkerLoop(wid_t wid)
{
    return GSTATE.shortcut_loops[wid];
}

static inline wid_t getNextDistributionWID(void)
{
    wid_t wid = atomicAddExplicit(&GSTATE.distribute_wid, 1, memory_order_relaxed);

    // we dont consider lwip thread
    if (wid >= getWorkersCount() - WORKER_ADDITIONS)
    {
        atomicStoreRelaxed(&GSTATE.distribute_wid, 0);
        wid = 0;
    }

    return wid;
}

/*!
 * @brief Send a worker message.
 *
 * @param wid The worker ID. (that receives the message)
 * @param cb The callback function.
 * @param arg1 The first argument.
 * @param arg2 The second argument.
 * @param arg3 The third argument.
 */
void sendWorkerMessage(wid_t wid, WorkerMessageCalback cb, void *arg1, void *arg2, void *arg3);

// same as above but dose not do a dircet call if the wid is the same as the current worker
void sendWorkerMessageForceQueue(wid_t wid, WorkerMessageCalback cb, void *arg1, void *arg2, void *arg3);

/*!
 * @brief Runs the main thread.
 */
WW_EXPORT void runMainThread(void);

/*!
 * @brief Exits the main thread.
 *
 * This function exits the main thread
 */
WW_EXPORT void finishGlobalState(void);

/*!
 * @brief Creates the global state.
 *
 * @param data The construction data for the global state.
 */
WW_EXPORT void createGlobalState(ww_construction_data_t data);
/*!
 * @brief Gets the global state.
 *
 * @return A pointer to the global state.
 */
WW_EXPORT ww_global_state_t *getGlobalState(void);
/*!
 * @brief Sets the global state.
 *
 * @param state A pointer to the global state.
 */
WW_EXPORT void setGlobalState(ww_global_state_t *state);
/*!
 * @brief Updates the allocation padding for the global state.
 *
 * @param padding The padding value.
 */
WW_EXPORT void globalstateUpdateAllocationPadding(uint16_t padding);

/*!
 * @brief Initializes the Lwip worker and spawn it.
 */
WW_EXPORT void initTcpIpStack(void);

/*!
 * @brief Destroys global state, all threads must be stopped before doing this
 */
WW_EXPORT void destroyGlobalState(void);

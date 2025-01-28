#pragma once

#include "wlibc.h"
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

typedef struct ww_global_state_s
{
    struct wloop_s         **shortcut_loops;
    buffer_pool_t   **shortcut_buffer_pools;
    generic_pool_t  **shortcut_context_pools;
    generic_pool_t  **shortcut_line_pools;
    generic_pool_t  **shortcut_pipeline_msg_pools;
    struct master_pool_s    *masterpool_buffer_pools_large;
    struct master_pool_s    *masterpool_buffer_pools_small;
    struct master_pool_s    *masterpool_context_pools;
    struct master_pool_s    *masterpool_line_pools;
    struct master_pool_s    *masterpool_pipeline_msg_pools;
    struct worker_s         *workers;
    struct signal_manager_s *signal_manager;
    struct socket_manager_s *socekt_manager;
    struct node_manager_s   *node_manager;
    struct logger_s         *core_logger;
    struct logger_s         *network_logger;
    struct logger_s         *dns_logger;
    struct logger_s         *ww_logger;
    unsigned int             workers_count;
    unsigned int             ram_profile;
    bool                     initialized;

} ww_global_state_t;

typedef struct
{
    unsigned int               workers_count;
    enum ram_profiles_e        ram_profile;
    logger_construction_data_t internal_logger_data;
    logger_construction_data_t core_logger_data;
    logger_construction_data_t network_logger_data;
    logger_construction_data_t dns_logger_data;

} ww_construction_data_t;

extern ww_global_state_t global_ww_state;

#define GSTATE        global_ww_state
#define RAM_PROFILE   global_ww_state.ram_profile
#define WORKERS       global_ww_state.workers
#define WORKERS_COUNT global_ww_state.workers_count

static inline tid_t getWorkersCount(void)
{
    return WORKERS_COUNT;
}

static inline worker_t *getWorker(tid_t tid)
{
    return &(WORKERS[tid]);
}

static inline buffer_pool_t *getWorkerBufferPool(tid_t tid)
{
    return GSTATE.shortcut_buffer_pools[tid];
}

static inline generic_pool_t *getWorkerLinePool(tid_t tid)
{
    return GSTATE.shortcut_line_pools[tid];
}

static inline generic_pool_t *getWorkerContextPool(tid_t tid)
{
    return GSTATE.shortcut_context_pools[tid];
}

static inline generic_pool_t *getWorkerPipeLineMsgPool(tid_t tid)
{
    return GSTATE.shortcut_pipeline_msg_pools[tid];
}

static inline struct wloop_s *getWorkerLoop(tid_t tid)
{
    return GSTATE.shortcut_loops[tid];
}

WW_EXPORT void runMainThread(void);

WW_EXPORT void createGlobalState(ww_construction_data_t data);

WW_EXPORT struct ww_global_state_s *getGlobalState(void)
{
    return &(GSTATE);
}

WW_EXPORT void setGlobalState(struct ww_global_state_s *state);

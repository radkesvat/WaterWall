#pragma once

#include "wlibc.h"
#include "worder.h"



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

enum ram_profiles
{
    kRamProfileInvalid  = 0,
    kRamProfileS1Memory = 1,
    kRamProfileS2Memory = 8,
    kRamProfileM1Memory = 16 * 8 * 1,
    kRamProfileM2Memory = 16 * 8 * 2,
    kRamProfileL1Memory = 16 * 8 * 3,
    kRamProfileL2Memory = 16 * 8 * 4
};


typedef struct ww_global_state_s
{
    struct wloop_s         **shortcut_loops;
    struct buffer_pool_s   **shortcut_buffer_pools;
    struct generic_pool_s  **shortcut_context_pools;
    struct generic_pool_s  **shortcut_line_pools;
    struct generic_pool_s  **shortcut_pipeline_msg_pools;
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
    enum ram_profiles          ram_profile;
    logger_construction_data_t core_logger_data;
    logger_construction_data_t network_logger_data;
    logger_construction_data_t dns_logger_data;

} ww_construction_data_t;

void createGlobalState(ww_construction_data_t data);

_Noreturn void runMainThread(void);

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

static inline struct buffer_pool_s *getWorkerBufferPool(tid_t tid)
{
    return GSTATE.shortcut_buffer_pools[tid];
}

static inline struct generic_pool_s *getWorkerLinePool(tid_t tid)
{
    return GSTATE.shortcut_line_pools[tid];
}

static inline struct generic_pool_s *getWorkerContextPool(tid_t tid)
{
    return GSTATE.shortcut_context_pools[tid];
}

static inline struct generic_pool_s *getWorkerPipeLineMsgPool(tid_t tid)
{
    return GSTATE.shortcut_pipeline_msg_pools[tid];
}

static inline struct wloop_s *getWorkerLoop(tid_t tid)
{
    return GSTATE.shortcut_loops[tid];
}

struct ww_global_state_s *getGlobalState(void)
{
    return &(GSTATE);
}




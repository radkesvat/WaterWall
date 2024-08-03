#pragma once
#include "buffer_pool.h"
#include "hthread.h"
#include "managers/memory_manager.h"

#include <stddef.h>
/*
    This is a global state file that powers many WW things up

    this also dose not limit loading another WW lib dynamically, it manages
    the loaded library and sets it up so there is no such problem of multiple global symbols

*/

#if defined(_MSC_VER)
#define WWEXPORT __declspec(dllexport)
#elif defined(__GNUC__)
#define WWEXPORT __attribute__((visibility("default")))
#else
#define WWEXPORT
#endif

#if defined(__GNUC__) || defined(__clang__) || defined(__IBMC__) || defined(__IBMCPP__) || defined(__COMPCERT__)

#define WW_LIKELY(x)   __builtin_expect(x, 1)
#define WW_UNLIKELY(x) __builtin_expect(x, 0)

#else

#define WW_LIKELY(x)   (v)
#define WW_UNLIKELY(x) (v)
#endif

#define MUSTALIGN2(n, w) assert(((w) & ((w) - 1)) == 0); /* alignment w is not a power of two */

/*
    kCpuLineCacheSize is the size of a cache line of the target CPU.
    The value 64 covers i386, x86_64, arm32, arm64.
    Note that Intel TBB uses 128 (max_nfs_size).
    todo (platform code) set value depending on target preprocessor information.
*/
enum
{
    kCpuLineCacheSize = 64
};

#define ATTR_ALIGNED_LINE_CACHE __attribute__((aligned(kCpuLineCacheSize)))

#define MUSTALIGN2(n, w) assert(((w) & ((w) - 1)) == 0); /* alignment w is not a power of two */

#define ALIGN2(n, w) (((n) + ((w) - 1)) & ~((w) - 1))

struct ww_global_state_s;

WWEXPORT void setWW(struct ww_global_state_s *state);

struct ww_global_state_s *getWW(void);

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

typedef struct
{
    unsigned int               workers_count;
    enum ram_profiles          ram_profile;
    logger_construction_data_t core_logger_data;
    logger_construction_data_t network_logger_data;
    logger_construction_data_t dns_logger_data;

} ww_construction_data_t;

void initHeap(void);
void createWW(ww_construction_data_t data);

_Noreturn void runMainThread(void);

typedef uint8_t tid_t;

typedef struct worker_s
{
    hthread_t              thread;
    struct hloop_s        *loop;
    struct buffer_pool_s  *buffer_pool;
    struct generic_pool_s *shift_buffer_pool;
    struct generic_pool_s *context_pool;
    struct generic_pool_s *line_pool;
    struct generic_pool_s *pipeline_msg_pool;
    tid_t                  tid;

} worker_t;

typedef struct ww_global_state_s
{
    struct hloop_s         **shortcut_loops;
    struct buffer_pool_s   **shortcut_buffer_pools;
    struct generic_pool_s  **shortcut_shift_buffer_pools;
    struct generic_pool_s  **shortcut_context_pools;
    struct generic_pool_s  **shortcut_line_pools;
    struct generic_pool_s  **shortcut_pipeline_msg_pools;
    struct master_pool_s    *masterpool_buffer_pools_large;
    struct master_pool_s    *masterpool_buffer_pools_small;
    struct master_pool_s    *masterpool_shift_buffer_pools;
    struct master_pool_s    *masterpool_context_pools;
    struct master_pool_s    *masterpool_line_pools;
    struct master_pool_s    *masterpool_pipeline_msg_pools;
    struct worker_s         *workers;
    struct socket_manager_s *socekt_manager;
    struct node_manager_s   *node_manager;
    struct logger_s         *core_logger;
    struct logger_s         *network_logger;
    struct logger_s         *dns_logger;
    unsigned int             workers_count;
    unsigned int             ram_profile;
    bool                     initialized;

} ww_global_state_t;

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

static inline struct generic_pool_s *getWorkerShiftBufferPool(uint8_t tid)
{
    return GSTATE.shortcut_shift_buffer_pools[tid];
}

static inline struct buffer_pool_s *getWorkerBufferPool(uint8_t tid)
{
    return GSTATE.shortcut_buffer_pools[tid];
}

static inline struct generic_pool_s *getWorkerLinePool(uint8_t tid)
{
    return GSTATE.shortcut_line_pools[tid];
}

static inline struct generic_pool_s *getWorkerContextPool(uint8_t tid)
{
    return GSTATE.shortcut_context_pools[tid];
}

static inline struct generic_pool_s *getWorkerPipeLineMsgPool(uint8_t tid)
{
    return GSTATE.shortcut_pipeline_msg_pools[tid];
}

static inline struct hloop_s *getWorkerLoop(uint8_t tid)
{
    return GSTATE.shortcut_loops[tid];
}

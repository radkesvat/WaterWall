#pragma once
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

/*
    kCpuLineCacheSize is the size of a cache line of the target CPU.
    The value 64 covers i386, x86_64, arm32, arm64.
*/
enum
{
#if defined(__i386__) || defined(__x86_64__)
    kCpuLineCacheSize = 64
#elif defined(__arm__) || defined(__aarch64__)
    kCpuLineCacheSize = 64
#elif defined(__powerpc64__)
    kCpuLineCacheSize = 128
#else
    kCpuLineCacheSize = 64
#endif
        ,

    kCpuLineCacheSizeMin1 = kCpuLineCacheSize - 1
};

#define ATTR_ALIGNED_LINE_CACHE __attribute__((aligned(kCpuLineCacheSize)))

#define MUSTALIGN2(n, w) assert(((w) & ((w) - 1)) == 0); /* alignment w is not a power of two */

#define ALIGN2(n, w) (((n) + ((w) - 1)) & ~((w) - 1))

#if defined(WW_AVX) && defined(__GNUC__) && (defined(__x86_64__) || defined(__i386__))

#include <x86intrin.h>
static inline void memCopy128(void *dest, const void *src, long int n)
{
    __m256i       *d_vec = (__m256i *) (dest);
    const __m256i *s_vec = (const __m256i *) (src);

    if ((uintptr_t) dest % 128 != 0 || (uintptr_t) src % 128 != 0)
    {

        while (n > 0)
        {
            _mm256_storeu_si256(d_vec, _mm256_loadu_si256(s_vec));
            _mm256_storeu_si256(d_vec + 1, _mm256_loadu_si256(s_vec + 1));
            _mm256_storeu_si256(d_vec + 2, _mm256_loadu_si256(s_vec + 2));
            _mm256_storeu_si256(d_vec + 3, _mm256_loadu_si256(s_vec + 3));

            n -= 128;
            d_vec += 4;
            s_vec += 4;
        }

        return;
    }

    while (n > 0)
    {
        _mm256_store_si256(d_vec, _mm256_load_si256(s_vec));
        _mm256_store_si256(d_vec + 1, _mm256_load_si256(s_vec + 1));
        _mm256_store_si256(d_vec + 2, _mm256_load_si256(s_vec + 2));
        _mm256_store_si256(d_vec + 3, _mm256_load_si256(s_vec + 3));

        n -= 128;
        d_vec += 4;
        s_vec += 4;
    }
}

#else

static inline void memCopy128(uint8_t *__restrict _dest, const uint8_t *__restrict _src, size_t n)
{
    while (n > 0)
    {
        memcpy(_dest, _src, 128);
        n -= 128;
        _dest += 128;
        _src += 128;
    }
}

#endif

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
    struct generic_pool_s *context_pool;
    struct generic_pool_s *line_pool;
    struct generic_pool_s *pipeline_msg_pool;
    tid_t                  tid;

} worker_t;

typedef struct ww_global_state_s
{
    struct hloop_s         **shortcut_loops;
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

static inline struct hloop_s *getWorkerLoop(tid_t tid)
{
    return GSTATE.shortcut_loops[tid];
}

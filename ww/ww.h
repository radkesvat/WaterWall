#pragma once
#include "hthread.h"
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

struct ww_runtime_state_s;

WWEXPORT void setWW(struct ww_runtime_state_s *state);

struct ww_runtime_state_s *getWW(void);

typedef struct
{
    char *log_file_path;
    char *log_level;
    bool  log_console;
} logger_construction_data_t;

enum ram_profiles
{
    kRamProfileInvalid  = 0,      // 0 is invalid memory multiplier
    kRamProfileS1Memory = 1,      // no preallocation (very small) (0.6MB per thread)
    kRamProfileM1Memory = 16 * 1, // APPROX 20MB per thread
    kRamProfileM2Memory = 16 * 2, // APPROX 40MB per thread
    kRamProfileL1Memory = 16 * 3, // APPROX 56MB per thread
    kRamProfileL2Memory = 16 * 4  // APPROX 72MB per thread
};

typedef struct
{
    unsigned int               workers_count;
    enum ram_profiles          ram_profile;
    logger_construction_data_t core_logger_data;
    logger_construction_data_t network_logger_data;
    logger_construction_data_t dns_logger_data;

} ww_construction_data_t;

void createWW(ww_construction_data_t data);

_Noreturn void runMainThread(void);

extern unsigned int             workers_count;
extern hthread_t               *workers;
extern unsigned int             frand_seed;
extern unsigned int             ram_profile;
extern struct hloop_s         **loops;
extern struct buffer_pool_s   **buffer_pools;
extern struct socket_manager_s *socket_disp_state;
extern struct node_manager_s   *node_disp_state;
extern struct logger_s         *core_logger;
extern struct logger_s         *network_logger;
extern struct logger_s         *dns_logger;

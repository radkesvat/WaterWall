#ifndef WW_SYS_INFO_H_
#define WW_SYS_INFO_H_

/**
 * @file wsysinfo.h
 * @brief Lightweight cross-platform system resource queries.
 *
 * Exposes helpers for CPU count, memory information, and coarse
 * "system under load" checks.
 */

#include "wlibc.h"
#include "wmutex.h"

typedef struct wloop_s  wloop_t;
typedef struct wtimer_s wtimer_t;

#ifdef OS_LINUX
#include <sys/sysinfo.h>
#endif

#ifdef OS_DARWIN
#include <mach/mach_host.h>
#include <sys/sysctl.h>
#endif

/**
 * @brief Get the number of configured CPUs.
 *
 * @return Number of logical processors configured on the host.
 */
static inline int getNCPU(void)
{
#ifdef OS_WIN
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    return (int) si.dwNumberOfProcessors;
#else
    // return get_nprocs();
    // return get_nprocs_conf();
    // return sysconf(_SC_NPROCESSORS_ONLN);     // processors available
    return (int) sysconf(_SC_NPROCESSORS_CONF); // processors configured
#endif
}

typedef struct meminfo_s
{
    unsigned long total; // KB
    unsigned long free;  // KB
} meminfo_t;

/**
 * @brief Populate total/free physical memory values (in KB).
 *
 * @param mem Output buffer for memory information.
 * @return `0` on success, otherwise a platform-specific error code.
 */
static inline int getMemInfo(meminfo_t *mem)
{
#ifdef OS_WIN
    MEMORYSTATUSEX memstat;
    memoryZero(&memstat, sizeof(memstat));
    memstat.dwLength = sizeof(memstat);
    GlobalMemoryStatusEx(&memstat);
    mem->total = (unsigned long) (memstat.ullTotalPhys >> 10);
    mem->free  = (unsigned long) (memstat.ullAvailPhys >> 10);
    return 0;
#elif defined(OS_LINUX)
    struct sysinfo info;
    if (sysinfo(&info) < 0)
    {
        return errno;
    }
    mem->total = info.totalram * info.mem_unit >> 10;
    mem->free  = info.freeram * info.mem_unit >> 10;
    return 0;
#elif defined(OS_DARWIN)
    uint64_t memsize  = 0;
    size_t   size     = sizeof(memsize);
    int      which[2] = {CTL_HW, HW_MEMSIZE};
    sysctl(which, 2, &memsize, &size, NULL, 0);
    mem->total = memsize >> 10;

    vm_statistics_data_t   info;
    mach_msg_type_number_t count = sizeof(info) / sizeof(integer_t);
    host_statistics(mach_host_self(), HOST_VM_INFO, (host_info_t) &info, &count);
    mem->free = ((uint64_t) info.free_count * (uint64_t) sysconf(_SC_PAGESIZE)) >> 10;
    return 0;
#else
    discard(mem);
    return -10;
#endif
}
/**
 * @brief Check whether current CPU/memory usage exceeds a threshold.
 *
 * @param threshold Load threshold in range `[0.0, 1.0]`.
 * @return `true` if system load is above threshold.
 */
bool isSystemUnderLoad(double threshold);

typedef enum system_memory_snapshot_status_e
{
    kSystemMemorySnapshotFresh,
    kSystemMemorySnapshotStale,
    kSystemMemorySnapshotUnsupported,
    kSystemMemorySnapshotUnavailable,
} system_memory_snapshot_status_t;

typedef struct system_memory_snapshot_s
{
    uint64_t generation;
    uint64_t sampled_at_ms;
    uint64_t host_total_bytes;
    uint64_t host_available_bytes;
    uint64_t cgroup_limit_bytes;
    uint64_t cgroup_current_bytes;
    uint64_t cgroup_available_bytes;
    uint64_t effective_available_bytes;
    uint32_t host_used_basis_points;
    uint32_t cgroup_used_basis_points;
    bool     cgroup_limited;
} system_memory_snapshot_t;

typedef enum system_memory_provider_result_e
{
    kSystemMemoryProviderOk,
    kSystemMemoryProviderUnsupported,
    kSystemMemoryProviderUnavailable,
} system_memory_provider_result_t;

typedef system_memory_provider_result_t (*SystemMemoryProviderFn)(void *userdata, system_memory_snapshot_t *snapshot);
typedef uint64_t (*SystemMemoryNowMsFn)(void *userdata);

#ifdef WW_SYSINFO_TEST_SEAM
typedef void (*SystemLoadSamplerTestTimerCallback)(void *callback_userdata);
typedef struct system_load_sampler_timer_test_ops_s
{
    wtimer_t *(*add)(void *userdata, wloop_t *loop, SystemLoadSamplerTestTimerCallback callback,
                     void *callback_userdata, uint32_t timeout_ms, uint32_t repeat);
    void (*set_userdata)(void *userdata, wtimer_t *timer, void *timer_userdata);
    void *(*get_userdata)(void *userdata, wtimer_t *timer);
    void (*delete_timer)(void *userdata, wtimer_t *timer);
} system_load_sampler_timer_test_ops_t;
#endif

typedef struct system_load_state_s
{
    wmutex_t  mutex;
    wtimer_t *timer;
    uint64_t  prev_total;
    uint64_t  prev_idle;
    uint64_t  prev_read_ms;
    uint64_t  last_valid_ms;
    double    cached_cpu_load;
    double    cached_memory_load;
    bool      initialized;
    bool      supported;
    bool      have_previous;
    bool      sample_valid;
    bool      sample_error;
    bool      sample_warming_up;
    bool      force_under_load;
    bool      memory_sample_valid;
    bool      unsupported_logged;

    /*
     * Memory publication is independent of the CPU delta warm-up above. The
     * writer serializes through mutex, while hot-path readers use this bounded
     * atomic sequence without taking the mutex or invoking a provider.
     */
    atomic_ullong memory_generation;
    atomic_ullong memory_sampled_at_ms;
    atomic_ullong memory_host_total_bytes;
    atomic_ullong memory_host_available_bytes;
    atomic_ullong memory_cgroup_limit_bytes;
    atomic_ullong memory_cgroup_current_bytes;
    atomic_ullong memory_cgroup_available_bytes;
    atomic_ullong memory_effective_available_bytes;
    atomic_uint   memory_host_used_basis_points;
    atomic_uint   memory_cgroup_used_basis_points;
    atomic_bool   memory_cgroup_limited;
    atomic_bool   memory_provider_supported;
    atomic_bool   memory_provider_unavailable;

    SystemMemoryProviderFn memory_provider;
    SystemMemoryNowMsFn    memory_now_ms;
    void                  *memory_provider_userdata;
    void                  *memory_now_userdata;
    void                  *memory_provider_state;
#ifdef WW_SYSINFO_TEST_SEAM
    const system_load_sampler_timer_test_ops_t *test_timer_ops;
    void                                       *test_timer_userdata;
#endif
} system_load_state_t;

bool systemLoadSamplerTryInit(system_load_state_t *state);
void systemLoadSamplerInit(system_load_state_t *state);
bool systemLoadSamplerStart(system_load_state_t *state, wloop_t *loop);
void systemLoadSamplerStop(system_load_state_t *state);
void systemLoadSamplerDestroy(system_load_state_t *state);
bool systemLoadSamplerUpdate(system_load_state_t *state);
void systemLoadSamplerSetForceUnderLoad(system_load_state_t *state, bool force_under_load);

/**
 * Return the last coherently published memory-only snapshot. This performs
 * bounded atomic loads only; it never refreshes or queries the operating
 * system.
 */
system_memory_snapshot_status_t systemMemorySnapshotGet(system_memory_snapshot_t *snapshot);

/**
 * Deterministic provider/clock seam used by focused sampler tests. Configure
 * it before publishing the state or starting concurrent readers.
 */
void systemLoadSamplerSetMemoryTestHooks(system_load_state_t *state, SystemMemoryProviderFn provider,
                                         SystemMemoryNowMsFn now_ms, void *userdata);

#ifdef WW_SYSINFO_TEST_SEAM
bool systemLoadSamplerTryInitWithMemoryTestHooks(system_load_state_t *state, SystemMemoryProviderFn provider,
                                                 SystemMemoryNowMsFn now_ms, void *userdata,
                                                 const system_load_sampler_timer_test_ops_t *timer_ops,
                                                 void                                       *timer_userdata);
#endif

/* Pure parsers used by the Linux provider and deterministic unit coverage. */
bool systemMemoryParseLinuxMeminfo(const char *contents, uint64_t *total_bytes, uint64_t *available_bytes);
bool systemMemoryParseUnsignedValue(const char *contents, bool allow_max, uint64_t *value, bool *unbounded);

#endif // WW_SYS_INFO_H_

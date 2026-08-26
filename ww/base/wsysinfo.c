/**
 * @file wsysinfo.c
 * @brief Platform-specific implementation of system load checks.
 */

#include "wsysinfo.h"
#include "global_state.h"
#include "wevent.h"
#include "wlibc.h"
#include "wsysinfo_linux.h"

typedef enum system_load_read_result_e
{
    kSystemLoadReadOk,
    kSystemLoadReadUnsupported,
    kSystemLoadReadError
} system_load_read_result_t;

static double normalizeLoadThreshold(double threshold)
{
    if (threshold < 0.0)
    {
        return 0.0;
    }

    // The API documents thresholds in the 0.0..1.0 range. Accept percentage
    // style values too so callers do not need to agree on one convention.
    if (threshold > 1.0)
    {
        threshold /= 100.0;
    }

    if (threshold > 1.0)
    {
        return 1.0;
    }

    return threshold;
}

static uint64_t systemLoadNowMS(void)
{
    return (uint64_t) (getHRTimeUs() / 1000ULL);
}

static bool systemLoadSampleIsFresh(uint64_t now_ms, uint64_t sample_ms)
{
    return sample_ms != 0 && now_ms >= sample_ms && (now_ms - sample_ms) <= SYSTEM_LOAD_SAMPLE_MAX_AGE_MS;
}

static uint64_t systemMemoryDefaultNowMS(void *userdata)
{
    discard userdata;
    return systemLoadNowMS();
}

bool systemMemoryParseUnsignedValue(const char *contents, bool allow_max, uint64_t *value, bool *unbounded)
{
    if (contents == NULL || value == NULL || unbounded == NULL)
    {
        return false;
    }

    while (isspace((unsigned char) *contents))
    {
        ++contents;
    }
    if (allow_max && strncmp(contents, "max", 3) == 0)
    {
        const char *tail = contents + 3;
        while (isspace((unsigned char) *tail))
        {
            ++tail;
        }
        if (*tail != '\0')
        {
            return false;
        }
        *value     = 0;
        *unbounded = true;
        return true;
    }

    if (*contents == '\0' || *contents == '-' || *contents == '+')
    {
        return false;
    }

    uint64_t parsed = 0;
    bool     digits = false;
    while (*contents >= '0' && *contents <= '9')
    {
        const uint32_t digit = (uint32_t) (*contents - '0');
        if (parsed > (UINT64_MAX - digit) / 10U)
        {
            return false;
        }
        parsed = (parsed * 10U) + digit;
        digits = true;
        ++contents;
    }
    while (isspace((unsigned char) *contents))
    {
        ++contents;
    }
    if (! digits || *contents != '\0')
    {
        return false;
    }

    *value     = parsed;
    *unbounded = false;
    return true;
}

static bool systemMemoryParseMeminfoLine(const char *line, const char *field, uint64_t *bytes)
{
    const size_t field_len = strlen(field);
    if (strncmp(line, field, field_len) != 0 || line[field_len] != ':')
    {
        return false;
    }

    const char *cursor = line + field_len + 1U;
    while (isspace((unsigned char) *cursor))
    {
        ++cursor;
    }

    uint64_t kib    = 0;
    bool     digits = false;
    while (*cursor >= '0' && *cursor <= '9')
    {
        const uint32_t digit = (uint32_t) (*cursor - '0');
        if (kib > (UINT64_MAX - digit) / 10U)
        {
            return false;
        }
        kib    = (kib * 10U) + digit;
        digits = true;
        ++cursor;
    }
    while (*cursor == ' ' || *cursor == '\t')
    {
        ++cursor;
    }
    if (! digits || strncmp(cursor, "kB", 2) != 0)
    {
        return false;
    }
    cursor += 2;
    while (*cursor == ' ' || *cursor == '\t' || *cursor == '\r')
    {
        ++cursor;
    }
    if (*cursor != '\0' && *cursor != '\n')
    {
        return false;
    }
    if (kib > UINT64_MAX / 1024U)
    {
        return false;
    }
    *bytes = kib * 1024U;
    return true;
}

bool systemMemoryParseLinuxMeminfo(const char *contents, uint64_t *total_bytes, uint64_t *available_bytes)
{
    if (contents == NULL || total_bytes == NULL || available_bytes == NULL)
    {
        return false;
    }

    uint64_t    total          = 0;
    uint64_t    available      = 0;
    bool        have_total     = false;
    bool        have_available = false;
    const char *cursor         = contents;

    while (*cursor != '\0')
    {
        const char  *newline = strchr(cursor, '\n');
        const size_t length  = newline == NULL ? strlen(cursor) : (size_t) (newline - cursor);
        if (length >= 256U)
        {
            return false;
        }

        char line[256];
        memoryCopy(line, cursor, length);
        line[length] = '\0';
        if (strncmp(line, "MemTotal", 8) == 0)
        {
            if (have_total || ! systemMemoryParseMeminfoLine(line, "MemTotal", &total))
            {
                return false;
            }
            have_total = true;
        }
        else if (strncmp(line, "MemAvailable", 12) == 0)
        {
            if (have_available || ! systemMemoryParseMeminfoLine(line, "MemAvailable", &available))
            {
                return false;
            }
            have_available = true;
        }

        if (newline == NULL)
        {
            break;
        }
        cursor = newline + 1U;
    }

    if (! have_total || ! have_available || total == 0 || available > total)
    {
        return false;
    }
    *total_bytes     = total;
    *available_bytes = available;
    return true;
}

static bool systemMemoryBasisPoints(uint64_t used, uint64_t total, uint32_t *basis_points)
{
    if (total == 0 || used > total || basis_points == NULL)
    {
        return false;
    }

    uint64_t left  = total;
    uint64_t right = 10000U;
    while (right != 0)
    {
        const uint64_t remainder = left % right;
        left                     = right;
        right                    = remainder;
    }

    const uint64_t divisor   = total / left;
    const uint32_t scale     = (uint32_t) (10000U / left);
    uint64_t       quotient  = used / divisor;
    uint64_t       remainder = used % divisor;
    uint32_t       result    = (uint32_t) (quotient * scale);

    /* At most 10,000 overflow-free modular additions. This slow path runs only
     * in the 500 ms background sampler and keeps even multi-petabyte totals
     * exact without compiler-specific 128-bit arithmetic. */
    uint64_t fractional_remainder = 0;
    for (uint32_t i = 0; i < scale; ++i)
    {
        if (fractional_remainder >= divisor - remainder)
        {
            fractional_remainder -= divisor - remainder;
            result++;
        }
        else
        {
            fractional_remainder += remainder;
        }
    }
    if (result > 10000U)
    {
        return false;
    }
    *basis_points = result;
    return true;
}

static bool systemMemoryFinalizeSnapshot(system_memory_snapshot_t *snapshot, uint64_t sampled_at_ms)
{
    if (snapshot == NULL || snapshot->host_total_bytes == 0 ||
        snapshot->host_available_bytes > snapshot->host_total_bytes)
    {
        return false;
    }

    const uint64_t host_used = snapshot->host_total_bytes - snapshot->host_available_bytes;
    if (! systemMemoryBasisPoints(host_used, snapshot->host_total_bytes, &snapshot->host_used_basis_points))
    {
        return false;
    }

    snapshot->sampled_at_ms             = sampled_at_ms;
    snapshot->effective_available_bytes = snapshot->host_available_bytes;
    if (! snapshot->cgroup_limited)
    {
        snapshot->cgroup_limit_bytes       = 0;
        snapshot->cgroup_current_bytes     = 0;
        snapshot->cgroup_available_bytes   = 0;
        snapshot->cgroup_used_basis_points = 0;
        return true;
    }

    if (snapshot->cgroup_limit_bytes == 0)
    {
        return false;
    }

    const uint64_t remaining = snapshot->cgroup_current_bytes >= snapshot->cgroup_limit_bytes
                                   ? 0
                                   : snapshot->cgroup_limit_bytes - snapshot->cgroup_current_bytes;
    if (snapshot->cgroup_available_bytes > remaining ||
        ((snapshot->cgroup_current_bytes >= snapshot->cgroup_limit_bytes) != (snapshot->cgroup_available_bytes == 0)))
    {
        return false;
    }
    const uint64_t bounded_current = min(snapshot->cgroup_current_bytes, snapshot->cgroup_limit_bytes);
    if (! systemMemoryBasisPoints(bounded_current, snapshot->cgroup_limit_bytes, &snapshot->cgroup_used_basis_points))
    {
        return false;
    }
    snapshot->effective_available_bytes = min(snapshot->host_available_bytes, snapshot->cgroup_available_bytes);
    return true;
}

#if defined(OS_WIN)
static uint64_t filetimeToU64(const FILETIME *ft)
{
    return ((uint64_t) ft->dwHighDateTime << 32U) | (uint64_t) ft->dwLowDateTime;
}

static system_load_read_result_t readCpuTimes(uint64_t *total, uint64_t *idle)
{
    FILETIME idle_time;
    FILETIME kernel_time;
    FILETIME user_time;

    if (! GetSystemTimes(&idle_time, &kernel_time, &user_time))
    {
        return kSystemLoadReadError;
    }

    *idle  = filetimeToU64(&idle_time);
    *total = filetimeToU64(&kernel_time) + filetimeToU64(&user_time);
    return kSystemLoadReadOk;
}

static bool readMemoryLoad(double *load)
{
    MEMORYSTATUSEX mem_status;
    memoryZero(&mem_status, sizeof(mem_status));
    mem_status.dwLength = sizeof(mem_status);

    if (! GlobalMemoryStatusEx(&mem_status) || mem_status.ullTotalPhys == 0)
    {
        return false;
    }

    *load = 1.0 - ((double) mem_status.ullAvailPhys / (double) mem_status.ullTotalPhys);
    return true;
}

#elif defined(OS_DARWIN)
#include <mach/host_info.h>
#include <mach/mach_host.h>

static system_load_read_result_t readCpuTimes(uint64_t *total, uint64_t *idle)
{
    host_cpu_load_info_data_t cpuinfo;
    mach_msg_type_number_t    count = HOST_CPU_LOAD_INFO_COUNT;

    if (host_statistics(mach_host_self(), HOST_CPU_LOAD_INFO, (host_info_t) &cpuinfo, &count) != KERN_SUCCESS)
    {
        return kSystemLoadReadError;
    }

    uint64_t total_ticks = 0;
    for (int i = 0; i < CPU_STATE_MAX; i++)
    {
        total_ticks += (uint64_t) cpuinfo.cpu_ticks[i];
    }

    *total = total_ticks;
    *idle  = (uint64_t) cpuinfo.cpu_ticks[CPU_STATE_IDLE];
    return kSystemLoadReadOk;
}

static bool readMemoryLoad(double *load)
{
    discard load;
    return false;
}

#elif defined(OS_LINUX)
static system_load_read_result_t readCpuTimes(uint64_t *total, uint64_t *idle)
{
    FILE *fp = fopen("/proc/stat", "r");
    if (! fp)
    {
        return kSystemLoadReadError;
    }

    char               line[256];
    unsigned long long user       = 0;
    unsigned long long nice       = 0;
    unsigned long long system     = 0;
    unsigned long long idle_ticks = 0;
    unsigned long long iowait     = 0;
    unsigned long long irq        = 0;
    unsigned long long softirq    = 0;
    unsigned long long steal      = 0;
    unsigned long long guest      = 0;
    unsigned long long guest_nice = 0;

    if (! fgets(line, sizeof(line), fp))
    {
        fclose(fp);
        return kSystemLoadReadError;
    }

    fclose(fp);

    int fields = sscanf(line,
                        "cpu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu",
                        &user,
                        &nice,
                        &system,
                        &idle_ticks,
                        &iowait,
                        &irq,
                        &softirq,
                        &steal,
                        &guest,
                        &guest_nice);
    if (fields < 4)
    {
        return kSystemLoadReadError;
    }

    *total = (uint64_t) (user + nice + system + idle_ticks + iowait + irq + softirq + steal);
    *idle  = (uint64_t) (idle_ticks + iowait);
    return kSystemLoadReadOk;
}

static bool readMemoryLoad(double *load)
{
    discard load;
    return false;
}

#elif defined(OS_FREEBSD)
#include <sys/resource.h>
#include <sys/sysctl.h>
#include <sys/types.h>

static system_load_read_result_t readCpuTimes(uint64_t *total, uint64_t *idle)
{
#if defined(CPUSTATES) && defined(CP_IDLE)
    long   cp_time[CPUSTATES];
    size_t len = sizeof(cp_time);

    if (sysctlbyname("kern.cp_time", cp_time, &len, NULL, 0) != 0 || len < sizeof(cp_time))
    {
        return kSystemLoadReadError;
    }

    uint64_t total_ticks = 0;
    for (int i = 0; i < CPUSTATES; i++)
    {
        if (cp_time[i] > 0)
        {
            total_ticks += (uint64_t) cp_time[i];
        }
    }

    *total = total_ticks;
    *idle  = cp_time[CP_IDLE] > 0 ? (uint64_t) cp_time[CP_IDLE] : 0;
    return kSystemLoadReadOk;
#else
    discard total;
    discard idle;
    return kSystemLoadReadUnsupported;
#endif
}

static bool readMemoryLoad(double *load)
{
    discard load;
    return false;
}

#elif defined(OS_NETBSD)
#include <sys/sched.h>
#include <sys/sysctl.h>
#include <sys/types.h>

static system_load_read_result_t readCpuTimes(uint64_t *total, uint64_t *idle)
{
#if defined(KERN_CP_TIME) && defined(CPUSTATES) && defined(CP_IDLE)
    uint64_t cp_time[CPUSTATES];
    size_t   len    = sizeof(cp_time);
    int      mib[2] = {CTL_KERN, KERN_CP_TIME};

    if (sysctl(mib, 2, cp_time, &len, NULL, 0) != 0 || len < sizeof(cp_time))
    {
        return kSystemLoadReadError;
    }

    uint64_t total_ticks = 0;
    for (int i = 0; i < CPUSTATES; i++)
    {
        total_ticks += cp_time[i];
    }

    *total = total_ticks;
    *idle  = cp_time[CP_IDLE];
    return kSystemLoadReadOk;
#else
    discard total;
    discard idle;
    return kSystemLoadReadUnsupported;
#endif
}

static bool readMemoryLoad(double *load)
{
    discard load;
    return false;
}

#elif defined(OS_OPENBSD)
#include <sys/sched.h>
#include <sys/sysctl.h>
#include <sys/types.h>

static system_load_read_result_t readCpuTimes(uint64_t *total, uint64_t *idle)
{
#if defined(KERN_CPTIME) && defined(CPUSTATES) && defined(CP_IDLE)
    long   cp_time[CPUSTATES];
    size_t len    = sizeof(cp_time);
    int    mib[2] = {CTL_KERN, KERN_CPTIME};

    if (sysctl(mib, 2, cp_time, &len, NULL, 0) != 0 || len < sizeof(cp_time))
    {
        return kSystemLoadReadError;
    }

    uint64_t total_ticks = 0;
    for (int i = 0; i < CPUSTATES; i++)
    {
        if (cp_time[i] > 0)
        {
            total_ticks += (uint64_t) cp_time[i];
        }
    }

    *total = total_ticks;
    *idle  = cp_time[CP_IDLE] > 0 ? (uint64_t) cp_time[CP_IDLE] : 0;
    return kSystemLoadReadOk;
#else
    discard total;
    discard idle;
    return kSystemLoadReadUnsupported;
#endif
}

static bool readMemoryLoad(double *load)
{
    discard load;
    return false;
}

#elif defined(OS_BSD)

static system_load_read_result_t readCpuTimes(uint64_t *total, uint64_t *idle)
{
    discard total;
    discard idle;
    return kSystemLoadReadUnsupported;
}

static bool readMemoryLoad(double *load)
{
    discard load;
    return false;
}

#else

static system_load_read_result_t readCpuTimes(uint64_t *total, uint64_t *idle)
{
    discard total;
    discard idle;
    return kSystemLoadReadUnsupported;
}

static bool readMemoryLoad(double *load)
{
    discard load;
    return false;
}

#endif

#if defined(OS_LINUX)

#include "wsysinfo_linux_provider.inc"

#elif defined(OS_WIN)

static system_memory_provider_result_t systemMemoryWindowsRead(void *userdata, system_memory_snapshot_t *snapshot)
{
    discard        userdata;
    MEMORYSTATUSEX memory_status;
    memoryZero(&memory_status, sizeof(memory_status));
    memory_status.dwLength = sizeof(memory_status);
    if (! GlobalMemoryStatusEx(&memory_status) || memory_status.ullTotalPhys == 0)
    {
        return kSystemMemoryProviderUnavailable;
    }
    snapshot->host_total_bytes     = memory_status.ullTotalPhys;
    snapshot->host_available_bytes = memory_status.ullAvailPhys;
    snapshot->cgroup_limited       = false;
    return kSystemMemoryProviderOk;
}

static bool systemMemoryDefaultProviderInit(system_load_state_t *state)
{
    state->memory_provider          = systemMemoryWindowsRead;
    state->memory_provider_userdata = NULL;
    return true;
}

static void systemMemoryDefaultProviderDestroy(system_load_state_t *state)
{
    discard state;
}

#else

static bool systemMemoryDefaultProviderInit(system_load_state_t *state)
{
    discard state;
    return false;
}

static void systemMemoryDefaultProviderDestroy(system_load_state_t *state)
{
    discard state;
}

#endif

static void systemMemoryPublish(system_load_state_t *state, const system_memory_snapshot_t *snapshot)
{
    uint64_t generation = atomicLoadU64Relaxed(&state->memory_generation);
    if (UNLIKELY((generation & 1U) != 0 || generation > UINT64_MAX - 2U))
    {
        printError("System memory snapshot generation invariant failed");
        abortProgramNow(1);
    }

    /* Keep the sequence and tuple fields in one sequentially consistent order.
     * A reader that observes any field from this publication must therefore
     * observe either the odd marker or the final even generation, never accept
     * a mixture under the preceding even generation. */
    atomicStoreU64Explicit(&state->memory_generation, generation + 1U, memory_order_seq_cst);
    atomicStoreU64Explicit(&state->memory_sampled_at_ms, snapshot->sampled_at_ms, memory_order_seq_cst);
    atomicStoreU64Explicit(&state->memory_host_total_bytes, snapshot->host_total_bytes, memory_order_seq_cst);
    atomicStoreU64Explicit(&state->memory_host_available_bytes, snapshot->host_available_bytes, memory_order_seq_cst);
    atomicStoreU64Explicit(&state->memory_cgroup_limit_bytes, snapshot->cgroup_limit_bytes, memory_order_seq_cst);
    atomicStoreU64Explicit(&state->memory_cgroup_current_bytes, snapshot->cgroup_current_bytes, memory_order_seq_cst);
    atomicStoreU64Explicit(
        &state->memory_cgroup_available_bytes, snapshot->cgroup_available_bytes, memory_order_seq_cst);
    atomicStoreU64Explicit(
        &state->memory_effective_available_bytes, snapshot->effective_available_bytes, memory_order_seq_cst);
    atomicStoreExplicit(&state->memory_host_used_basis_points, snapshot->host_used_basis_points, memory_order_seq_cst);
    atomicStoreExplicit(
        &state->memory_cgroup_used_basis_points, snapshot->cgroup_used_basis_points, memory_order_seq_cst);
    atomicStoreExplicit(&state->memory_cgroup_limited, snapshot->cgroup_limited, memory_order_seq_cst);
    atomicStoreU64Explicit(&state->memory_generation, generation + 2U, memory_order_seq_cst);
}

static void systemLoadTimerHandle(wtimer_t *timer)
{
    system_load_state_t *state = weventGetUserdata(timer);
    if (state == NULL)
    {
        return;
    }

    systemLoadSamplerUpdate(state);
}

bool systemLoadSamplerTryInit(system_load_state_t *state)
{
    if (state == NULL)
    {
        return false;
    }
    *state = (system_load_state_t) {0};
    if (UNLIKELY(! mutexTryInit(&state->mutex)))
    {
        return false;
    }
    state->initialized   = true;
    state->supported     = true;
    state->memory_now_ms = systemMemoryDefaultNowMS;
    atomicStoreU64Relaxed(&state->memory_generation, 0);
    atomicStoreRelaxed(&state->memory_provider_unavailable, true);
    const bool memory_supported = systemMemoryDefaultProviderInit(state);
    atomicStoreRelaxed(&state->memory_provider_supported, memory_supported);
    discard systemLoadSamplerUpdate(state);
    return true;
}

void systemLoadSamplerInit(system_load_state_t *state)
{
    wSyncInitRequire(systemLoadSamplerTryInit(state));
}

bool systemLoadSamplerStart(system_load_state_t *state, wloop_t *loop)
{
    assert(state != NULL);
    if (! state->initialized)
    {
        systemLoadSamplerInit(state);
    }

    mutexLock(&state->mutex);
    if (! state->supported && ! atomicLoadRelaxed(&state->memory_provider_supported))
    {
        mutexUnlock(&state->mutex);
        return true;
    }

    if (state->timer != NULL)
    {
        mutexUnlock(&state->mutex);
        return true;
    }

    if (loop == NULL)
    {
        state->sample_error      = true;
        state->sample_warming_up = false;
        mutexUnlock(&state->mutex);
        return false;
    }

    wtimer_t *timer = wtimerAdd(loop, systemLoadTimerHandle, SYSTEM_LOAD_SAMPLER_INTERVAL_MS, INFINITE);
    if (timer == NULL)
    {
        state->sample_error      = true;
        state->sample_warming_up = false;
        mutexUnlock(&state->mutex);
        return false;
    }

    weventSetUserData(timer, state);
    state->timer = timer;
    mutexUnlock(&state->mutex);
    return true;
}

void systemLoadSamplerStop(system_load_state_t *state)
{
    if (state == NULL || ! state->initialized)
    {
        return;
    }

    mutexLock(&state->mutex);
    wtimer_t *timer = state->timer;
    state->timer    = NULL;
    mutexUnlock(&state->mutex);

    if (timer != NULL)
    {
        weventSetUserData(timer, NULL);
        wtimerDelete(timer);
    }
}

void systemLoadSamplerDestroy(system_load_state_t *state)
{
    if (state == NULL || ! state->initialized)
    {
        return;
    }

    systemLoadSamplerStop(state);
    systemMemoryDefaultProviderDestroy(state);
    mutexDestroy(&state->mutex);
    *state = (system_load_state_t) {0};
}

bool systemLoadSamplerUpdate(system_load_state_t *state)
{
    assert(state != NULL);

    system_memory_snapshot_t        memory_snapshot = {0};
    system_memory_provider_result_t memory_result   = kSystemMemoryProviderUnsupported;
    const uint64_t memory_now_ms = state->memory_now_ms != NULL ? state->memory_now_ms(state->memory_now_userdata)
                                                                : systemMemoryDefaultNowMS(NULL);
    if (state->memory_provider != NULL)
    {
        memory_result = state->memory_provider(state->memory_provider_userdata, &memory_snapshot);
        if (memory_result == kSystemMemoryProviderOk && ! systemMemoryFinalizeSnapshot(&memory_snapshot, memory_now_ms))
        {
            memory_result = kSystemMemoryProviderUnavailable;
        }
    }

    uint64_t                  total  = 0;
    uint64_t                  idle   = 0;
    const uint64_t            now_ms = systemLoadNowMS();
    system_load_read_result_t rc     = readCpuTimes(&total, &idle);

    mutexLock(&state->mutex);

    atomicStoreRelaxed(&state->memory_provider_supported, memory_result != kSystemMemoryProviderUnsupported);
    atomicStoreRelaxed(&state->memory_provider_unavailable, memory_result == kSystemMemoryProviderUnavailable);
    state->memory_sample_valid = memory_result == kSystemMemoryProviderOk;
    if (memory_result == kSystemMemoryProviderOk)
    {
        systemMemoryPublish(state, &memory_snapshot);
        const uint32_t used_basis_points =
            max(memory_snapshot.host_used_basis_points,
                memory_snapshot.cgroup_limited ? memory_snapshot.cgroup_used_basis_points : 0U);
        state->cached_memory_load = (double) used_basis_points / 10000.0;
    }

    if (rc == kSystemLoadReadUnsupported)
    {
        if (! state->unsupported_logged)
        {
            printError("System CPU load sampling is unsupported on this platform\n");
            state->unsupported_logged = true;
        }
        state->supported         = false;
        state->sample_error      = false;
        state->sample_valid      = false;
        state->sample_warming_up = false;
        state->have_previous     = false;
        mutexUnlock(&state->mutex);
        return memory_result == kSystemMemoryProviderOk;
    }

    state->supported = true;
    if (rc == kSystemLoadReadError)
    {
        state->sample_error      = true;
        state->sample_valid      = false;
        state->sample_warming_up = false;
        state->have_previous     = false;
        mutexUnlock(&state->mutex);
        return memory_result == kSystemMemoryProviderOk;
    }

    state->sample_error = false;
    if (! state->have_previous)
    {
        state->prev_total        = total;
        state->prev_idle         = idle;
        state->prev_read_ms      = now_ms;
        state->have_previous     = true;
        state->sample_valid      = false;
        state->sample_warming_up = true;
        mutexUnlock(&state->mutex);
        return memory_result == kSystemMemoryProviderOk;
    }

    bool counters_ok = total > state->prev_total && idle >= state->prev_idle;
    bool interval_ok = systemLoadSampleIsFresh(now_ms, state->prev_read_ms);

    if (counters_ok && interval_ok)
    {
        const uint64_t total_delta = total - state->prev_total;
        const uint64_t idle_delta  = idle - state->prev_idle;

        if (idle_delta > total_delta)
        {
            counters_ok = false;
        }
        else
        {
            state->cached_cpu_load   = 1.0 - ((double) idle_delta / (double) total_delta);
            state->last_valid_ms     = now_ms;
            state->sample_valid      = true;
            state->sample_warming_up = false;
        }
    }

    if (! counters_ok || ! interval_ok)
    {
        state->sample_valid      = false;
        state->sample_warming_up = false;
    }

    state->prev_total    = total;
    state->prev_idle     = idle;
    state->prev_read_ms  = now_ms;
    state->have_previous = true;

    const bool valid = state->sample_valid || memory_result == kSystemMemoryProviderOk;
    mutexUnlock(&state->mutex);
    return valid;
}

void systemLoadSamplerSetForceUnderLoad(system_load_state_t *state, bool force_under_load)
{
    if (state == NULL || ! state->initialized)
    {
        return;
    }

    mutexLock(&state->mutex);
    state->force_under_load = force_under_load;
    mutexUnlock(&state->mutex);
}

#ifdef WW_SYSINFO_TEST_SEAM
void systemLoadSamplerSetMemoryTestHooks(system_load_state_t *state, SystemMemoryProviderFn provider,
                                         SystemMemoryNowMsFn now_ms, void *userdata)
{
    assert(state != NULL);
    assert(state->initialized);

    systemMemoryDefaultProviderDestroy(state);
    state->memory_provider          = provider;
    state->memory_provider_userdata = userdata;
    state->memory_now_ms            = now_ms != NULL ? now_ms : systemMemoryDefaultNowMS;
    state->memory_now_userdata      = userdata;
    atomicStoreU64Relaxed(&state->memory_generation, 0);
    atomicStoreRelaxed(&state->memory_provider_supported, provider != NULL);
    atomicStoreRelaxed(&state->memory_provider_unavailable, provider != NULL);
    state->memory_sample_valid = false;
}
#endif

system_memory_snapshot_status_t systemMemorySnapshotGet(system_memory_snapshot_t *snapshot)
{
    if (snapshot == NULL)
    {
        return kSystemMemorySnapshotUnavailable;
    }
    *snapshot = (system_memory_snapshot_t) {0};

    system_load_state_t *state = GSTATE.system_load;
    if (state == NULL || ! state->initialized)
    {
        return kSystemMemorySnapshotUnavailable;
    }

    for (unsigned int attempt = 0; attempt < 8U; ++attempt)
    {
        const uint64_t before = atomicLoadU64Explicit(&state->memory_generation, memory_order_seq_cst);
        if (before == 0)
        {
            if (! atomicLoadRelaxed(&state->memory_provider_supported))
            {
                return kSystemMemorySnapshotUnsupported;
            }
            return kSystemMemorySnapshotUnavailable;
        }
        if ((before & 1U) != 0)
        {
            continue;
        }

        system_memory_snapshot_t candidate = {
            .generation           = before,
            .sampled_at_ms        = atomicLoadU64Explicit(&state->memory_sampled_at_ms, memory_order_seq_cst),
            .host_total_bytes     = atomicLoadU64Explicit(&state->memory_host_total_bytes, memory_order_seq_cst),
            .host_available_bytes = atomicLoadU64Explicit(&state->memory_host_available_bytes, memory_order_seq_cst),
            .cgroup_limit_bytes   = atomicLoadU64Explicit(&state->memory_cgroup_limit_bytes, memory_order_seq_cst),
            .cgroup_current_bytes = atomicLoadU64Explicit(&state->memory_cgroup_current_bytes, memory_order_seq_cst),
            .cgroup_available_bytes =
                atomicLoadU64Explicit(&state->memory_cgroup_available_bytes, memory_order_seq_cst),
            .effective_available_bytes =
                atomicLoadU64Explicit(&state->memory_effective_available_bytes, memory_order_seq_cst),
            .host_used_basis_points =
                (uint32_t) atomicLoadExplicit(&state->memory_host_used_basis_points, memory_order_seq_cst),
            .cgroup_used_basis_points =
                (uint32_t) atomicLoadExplicit(&state->memory_cgroup_used_basis_points, memory_order_seq_cst),
            .cgroup_limited = atomicLoadExplicit(&state->memory_cgroup_limited, memory_order_seq_cst),
        };

        const uint64_t after = atomicLoadU64Explicit(&state->memory_generation, memory_order_seq_cst);
        if (before != after || (after & 1U) != 0)
        {
            continue;
        }

        *snapshot             = candidate;
        const uint64_t now_ms = state->memory_now_ms != NULL ? state->memory_now_ms(state->memory_now_userdata)
                                                             : systemMemoryDefaultNowMS(NULL);
        return systemLoadSampleIsFresh(now_ms, candidate.sampled_at_ms) ? kSystemMemorySnapshotFresh
                                                                        : kSystemMemorySnapshotStale;
    }

    return kSystemMemorySnapshotUnavailable;
}

bool isSystemUnderLoad(double threshold)
{
    threshold = normalizeLoadThreshold(threshold);

    system_load_state_t *state = GSTATE.system_load;
    if (state == NULL || ! state->initialized)
    {
        return false;
    }

    mutexLock(&state->mutex);
    bool     supported         = state->supported;
    bool     sample_valid      = state->sample_valid;
    bool     sample_error      = state->sample_error;
    bool     sample_warming_up = state->sample_warming_up;
    bool     force_under_load  = state->force_under_load;
    uint64_t prev_read_ms      = state->prev_read_ms;
    uint64_t last_valid_ms     = state->last_valid_ms;
    double   cached_cpu_load   = state->cached_cpu_load;
    mutexUnlock(&state->mutex);

    if (force_under_load)
    {
        return true;
    }

    if (! supported)
    {
        system_memory_snapshot_t memory_snapshot;
        if (systemMemorySnapshotGet(&memory_snapshot) != kSystemMemorySnapshotFresh)
        {
            return false;
        }
        const uint32_t used_basis_points =
            max(memory_snapshot.host_used_basis_points,
                memory_snapshot.cgroup_limited ? memory_snapshot.cgroup_used_basis_points : 0U);
        return used_basis_points > (uint32_t) (threshold * 10000.0);
    }

    uint64_t now_ms = systemLoadNowMS();
    if (sample_warming_up && ! sample_error && ! sample_valid && last_valid_ms == 0 &&
        systemLoadSampleIsFresh(now_ms, prev_read_ms))
    {
        return false;
    }

    if (sample_error || ! sample_valid || ! systemLoadSampleIsFresh(now_ms, last_valid_ms))
    {
        return true;
    }

    if (sample_valid && cached_cpu_load > threshold)
    {
        return true;
    }

    system_memory_snapshot_t memory_snapshot;
    if (systemMemorySnapshotGet(&memory_snapshot) != kSystemMemorySnapshotFresh)
    {
        return false;
    }
    const uint32_t used_basis_points =
        max(memory_snapshot.host_used_basis_points,
            memory_snapshot.cgroup_limited ? memory_snapshot.cgroup_used_basis_points : 0U);
    return used_basis_points > (uint32_t) (threshold * 10000.0);
}

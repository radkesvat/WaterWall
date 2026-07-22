/**
 * @file wsysinfo.c
 * @brief Platform-specific implementation of system load checks.
 */

#include "wsysinfo.h"
#include "global_state.h"
#include "wevent.h"
#include "wlibc.h"

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
    unsigned long long user = 0;
    unsigned long long nice = 0;
    unsigned long long system = 0;
    unsigned long long idle_ticks = 0;
    unsigned long long iowait = 0;
    unsigned long long irq = 0;
    unsigned long long softirq = 0;
    unsigned long long steal = 0;
    unsigned long long guest = 0;
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
#include <sys/types.h>
#include <sys/resource.h>
#include <sys/sysctl.h>

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
#include <sys/types.h>
#include <sys/sched.h>
#include <sys/sysctl.h>

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
#include <sys/types.h>
#include <sys/sched.h>
#include <sys/sysctl.h>

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

static void systemLoadTimerHandle(wtimer_t *timer)
{
    system_load_state_t *state = weventGetUserdata(timer);
    if (state == NULL || isApplicationTerminating())
    {
        return;
    }

    systemLoadSamplerUpdate(state);
}

void systemLoadSamplerInit(system_load_state_t *state)
{
    assert(state != NULL);
    *state = (system_load_state_t) {0};
    mutexInit(&state->mutex);
    state->initialized = true;
    state->supported   = true;
    discard systemLoadSamplerUpdate(state);
}

bool systemLoadSamplerStart(system_load_state_t *state, wloop_t *loop)
{
    assert(state != NULL);
    if (! state->initialized)
    {
        systemLoadSamplerInit(state);
    }

    mutexLock(&state->mutex);
    if (! state->supported)
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
    mutexDestroy(&state->mutex);
    *state = (system_load_state_t) {0};
}

bool systemLoadSamplerUpdate(system_load_state_t *state)
{
    assert(state != NULL);

    mutexLock(&state->mutex);

    uint64_t                  total = 0;
    uint64_t                  idle  = 0;
    uint64_t                  now_ms = systemLoadNowMS();
    system_load_read_result_t rc    = readCpuTimes(&total, &idle);

    double memory_load  = 0.0;
    bool   memory_valid = readMemoryLoad(&memory_load);

    state->memory_sample_valid = memory_valid;
    if (memory_valid)
    {
        state->cached_memory_load = memory_load;
    }

    if (rc == kSystemLoadReadUnsupported)
    {
        if (! state->unsupported_logged)
        {
            printError("System load sampler is unsupported on this platform; isSystemUnderLoad() will fail open\n");
            state->unsupported_logged = true;
        }
        state->supported         = false;
        state->sample_error      = false;
        state->sample_valid      = false;
        state->sample_warming_up = false;
        state->have_previous     = false;
        mutexUnlock(&state->mutex);
        return false;
    }

    state->supported = true;
    if (rc == kSystemLoadReadError)
    {
        state->sample_error      = true;
        state->sample_valid      = false;
        state->sample_warming_up = false;
        state->have_previous     = false;
        mutexUnlock(&state->mutex);
        return false;
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
        return false;
    }

    bool counters_ok = total > state->prev_total && idle >= state->prev_idle;
    bool interval_ok = systemLoadSampleIsFresh(now_ms, state->prev_read_ms);

    if (counters_ok && interval_ok)
    {
        uint64_t total_delta = total - state->prev_total;
        uint64_t idle_delta  = idle - state->prev_idle;

        if (idle_delta > total_delta)
        {
            counters_ok = false;
        }
        else
        {
            state->cached_cpu_load  = 1.0 - ((double) idle_delta / (double) total_delta);
            state->last_valid_ms    = now_ms;
            state->sample_valid     = true;
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

    bool valid = state->sample_valid;
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

bool isSystemUnderLoad(double threshold)
{
    threshold = normalizeLoadThreshold(threshold);

    system_load_state_t *state = GSTATE.system_load;
    if (state == NULL || ! state->initialized)
    {
        return false;
    }

    mutexLock(&state->mutex);
    bool     supported          = state->supported;
    bool     sample_valid       = state->sample_valid;
    bool     sample_error       = state->sample_error;
    bool     sample_warming_up  = state->sample_warming_up;
    bool     force_under_load   = state->force_under_load;
    bool     memory_valid       = state->memory_sample_valid;
    uint64_t prev_read_ms       = state->prev_read_ms;
    uint64_t last_valid_ms      = state->last_valid_ms;
    double   cached_cpu_load    = state->cached_cpu_load;
    double   cached_memory_load = state->cached_memory_load;
    mutexUnlock(&state->mutex);

    if (force_under_load)
    {
        return true;
    }

    if (! supported)
    {
        // Unsupported platforms fail open; supported platforms fail closed below.
        return false;
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

    return memory_valid && cached_memory_load > threshold;
}

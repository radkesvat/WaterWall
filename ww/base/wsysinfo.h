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
    mem->free = ((uint64_t)info.free_count * (uint64_t)sysconf(_SC_PAGESIZE)) >> 10;
    return 0;
#else
    discard (mem);
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

#endif // WW_SYS_INFO_H_

#include "wsysinfo.h"
#include "wlibc.h"

#if defined(OS_MAC)
#include <mach/host_info.h>
#include <mach/mach_host.h>

bool isSystemUnderLoad(double threshold)
{
    host_cpu_load_info_data_t cpuinfo;
    mach_msg_type_number_t    count = HOST_CPU_LOAD_INFO_COUNT;

    if (host_statistics(mach_host_self(), HOST_CPU_LOAD_INFO, (host_info_t) &cpuinfo, &count) != KERN_SUCCESS)
    {
        perror("Failed to get host statistics");
        return -1; // Error
    }

    unsigned long long total_ticks = 0;
    for (int i = 0; i < CPU_STATE_MAX; i++)
    {
        total_ticks += cpuinfo.cpu_ticks[i];
    }

    unsigned long long idle_ticks = cpuinfo.cpu_ticks[CPU_STATE_IDLE];
    double             load       = 100.0 * (1.0 - ((double) idle_ticks / total_ticks));

    // Check if the load exceeds the threshold
    return load > threshold ? 1 : 0;
}

#elif defined(OS_LINUX)

bool isSystemUnderLoad(double threshold)
{
    FILE *fp = fopen("/proc/stat", "r");
    if (! fp)
    {
        perror("Failed to open /proc/stat");
        return -1; // Error
    }

    char      line[256];
    long long user, nice, system, idle, iowait, irq, softirq, steal, guest, guest_nice;
    double    total_cpu_time, idle_cpu_time, load;

    // Read the first line of /proc/stat which contains CPU stats
    if (fgets(line, sizeof(line), fp))
    {
        sscanf(line, "cpu %lld %lld %lld %lld %lld %lld %lld %lld %lld %lld", &user, &nice, &system, &idle, &iowait,
               &irq, &softirq, &steal, &guest, &guest_nice);

        total_cpu_time = user + nice + system + idle + iowait + irq + softirq + steal;
        idle_cpu_time  = idle + iowait;

        load = 100.0 * (1.0 - (idle_cpu_time / total_cpu_time));
    }
    else
    {
        fclose(fp);
        return -1; // Error
    }

    fclose(fp);

    // Check if the load exceeds the threshold
    return load > threshold ? 1 : 0;
}

#elif defined(OS_WIN)
#pragma comment(lib, "pdh.lib")
#include <pdh.h>
#include <pdhmsg.h>
bool isSystemUnderLoad(double threshold)
{
    static PDH_HQUERY   cpu_query   = NULL;
    static PDH_HCOUNTER cpu_counter = NULL;
    static int          initialized = 0;

    // Initialize the CPU query and counter if not already done
    if (! initialized)
    {
        if (PdhOpenQuery(NULL, 0, &cpu_query) != ERROR_SUCCESS)
        {
            fprintf(stderr, "Failed to open PDH query\n");
            return -1; // Error
        }

        if (PdhAddCounter(cpu_query, "\\Processor(_Total)\\% Processor Time", 0, &cpu_counter) != ERROR_SUCCESS)
        {
            fprintf(stderr, "Failed to add counter\n");
            PdhCloseQuery(cpu_query);
            return -1; // Error
        }

        initialized = 1;
    }

    // Collect the CPU data
    if (PdhCollectQueryData(cpu_query) != ERROR_SUCCESS)
    {
        fprintf(stderr, "Failed to collect CPU query data\n");
        return -1; // Error
    }

    // Retrieve the formatted CPU counter value
    PDH_FMT_COUNTERVALUE cpu_value;
    if (PdhGetFormattedCounterValue(cpu_counter, PDH_FMT_DOUBLE, NULL, &cpu_value) != ERROR_SUCCESS)
    {
        fprintf(stderr, "Failed to get CPU counter value\n");
        return -1; // Error
    }

    // Check CPU usage against the threshold
    double cpu_usage = cpu_value.doubleValue;
    if (cpu_usage > threshold)
    {
        return 1; // System is under heavy CPU load
    }

    // Check memory usage
    MEMORYSTATUSEX mem_status;
    mem_status.dwLength = sizeof(mem_status);
    if (! GlobalMemoryStatusEx(&mem_status))
    {
        fprintf(stderr, "Failed to get memory status\n");
        return -1; // Error
    }

    // Calculate memory usage as a percentage
    double memory_usage = (1.0 - ((double) mem_status.ullAvailPhys / mem_status.ullTotalPhys));
    if (memory_usage > threshold)
    {
        return 1; // System is under heavy memory load
    }

    return 0; // System is not under heavy load
}

#else

bool isSystemUnderLoad(double threshold)
{
    return false;
}

#endif

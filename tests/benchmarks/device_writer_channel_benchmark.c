/*
 * Diagnostic benchmark for the device-writer producer path.
 *
 * This target is deliberately excluded from normal builds and CTest. It uses
 * the same workload before and after writer-channel lifetime changes so review
 * can compare throughput and process CPU time without turning machine-specific
 * timing into a correctness threshold.
 *
 * Build and run from the repository root:
 *
 *   cmake --build --preset linux --target device_writer_channel_benchmark
 *   ./build/linux/tests/benchmarks/Release/device_writer_channel_benchmark [duration_ms]
 */

#include "devices/device_writer_channel.h"

#include "watomic.h"
#include "wchan.h"
#include "wthread.h"
#include "wtime.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

enum
{
    kMostlyEmptyQueueCapacity = 128 * 1024,
    kSaturatedQueueCapacity   = 32,
    kDefaultDurationMs        = 1000,
    kClosedObservationMs      = 25
};

typedef struct benchmark_shared_s
{
    device_writer_channel_t writer_channel;
    atomic_bool             start;
    atomic_bool             stop;
    atomic_uint             ready;
    bool                    saturated;
} benchmark_shared_t;

typedef struct producer_probe_s
{
    benchmark_shared_t *shared;
    uint64_t            sent;
    uint64_t            down;
    uint64_t            closed;
    uint64_t            full;
} producer_probe_t;

static uint64_t benchmarkClockNs(clockid_t clock_id)
{
    struct timespec ts;
    if (clock_gettime(clock_id, &ts) != 0)
    {
        perror("clock_gettime");
        exit(1);
    }
    return (uint64_t) ts.tv_sec * UINT64_C(1000000000) + (uint64_t) ts.tv_nsec;
}

static WTHREAD_ROUTINE(benchmarkProducer)
{
    producer_probe_t   *probe  = userdata;
    benchmark_shared_t *shared = probe->shared;

    atomicIncRelaxed(&shared->ready);
    while (! atomicLoadRelaxed(&shared->start))
    {
        YIELD_CPU();
    }

    while (! atomicLoadRelaxed(&shared->stop))
    {
        switch (deviceWriterChannelTrySend(&shared->writer_channel, (sbuf_t *) (void *) probe))
        {
        case kDeviceWriterSendOk:
            probe->sent++;
            break;
        case kDeviceWriterSendDown:
            probe->down++;
            break;
        case kDeviceWriterSendClosed:
            probe->closed++;
            break;
        case kDeviceWriterSendFull:
            probe->full++;
            break;
        }
    }

    return 0;
}

static WTHREAD_ROUTINE(benchmarkConsumer)
{
    benchmark_shared_t *shared = userdata;
    sbuf_t             *buf;

    atomicIncRelaxed(&shared->ready);
    while (! atomicLoadRelaxed(&shared->start))
    {
        YIELD_CPU();
    }

    struct wchan_s *channel = deviceWriterChannelGetConsumerChannel(&shared->writer_channel);
    while (chanRecv(channel, &buf))
    {
        discard buf;
        if (shared->saturated)
        {
            wwSleepMS(1);
        }
    }
    return 0;
}

static void benchmarkRunCase(unsigned int producer_count, bool saturated, unsigned int duration_ms)
{
    const size_t queue_capacity = saturated ? kSaturatedQueueCapacity : kMostlyEmptyQueueCapacity;

    benchmark_shared_t shared = {
        .start     = false,
        .stop      = false,
        .ready     = 0,
        .saturated = saturated,
    };
    deviceWriterChannelInit(&shared.writer_channel);
    if (! deviceWriterChannelOpen(&shared.writer_channel, queue_capacity))
    {
        fprintf(stderr, "device_writer_channel_benchmark: failed to open writer channel\n");
        exit(1);
    }

    producer_probe_t *probes           = calloc(producer_count, sizeof(*probes));
    wthread_t        *producer_threads = calloc(producer_count, sizeof(*producer_threads));
    if (probes == NULL || producer_threads == NULL)
    {
        fprintf(stderr, "device_writer_channel_benchmark: allocation failed\n");
        exit(1);
    }

    wthread_t consumer_thread;
    if (threadCreate(&consumer_thread, benchmarkConsumer, &shared) != kWThreadErrorNone)
    {
        fprintf(stderr, "device_writer_channel_benchmark: failed to create consumer\n");
        exit(1);
    }
    for (unsigned int i = 0; i < producer_count; i++)
    {
        probes[i].shared = &shared;
        if (threadCreate(&producer_threads[i], benchmarkProducer, &probes[i]) != kWThreadErrorNone)
        {
            fprintf(stderr, "device_writer_channel_benchmark: failed to create producer\n");
            exit(1);
        }
    }

    while (atomicLoadRelaxed(&shared.ready) != producer_count + 1)
    {
        YIELD_CPU();
    }

    const uint64_t wall_start = benchmarkClockNs(CLOCK_MONOTONIC);
    const uint64_t cpu_start  = benchmarkClockNs(CLOCK_PROCESS_CPUTIME_ID);
    atomicStoreRelaxed(&shared.start, true);
    wwSleepMS(duration_ms);

    deviceWriterChannelClose(&shared.writer_channel);
    wwSleepMS(kClosedObservationMs);
    atomicStoreRelaxed(&shared.stop, true);

    for (unsigned int i = 0; i < producer_count; i++)
    {
        if (threadJoin(producer_threads[i]) != 0)
        {
            fprintf(stderr, "device_writer_channel_benchmark: failed to join producer\n");
            exit(1);
        }
    }
    if (threadJoin(consumer_thread) != 0)
    {
        fprintf(stderr, "device_writer_channel_benchmark: failed to join consumer\n");
        exit(1);
    }

    const uint64_t cpu_ns  = benchmarkClockNs(CLOCK_PROCESS_CPUTIME_ID) - cpu_start;
    const uint64_t wall_ns = benchmarkClockNs(CLOCK_MONOTONIC) - wall_start;

    uint64_t sent   = 0;
    uint64_t down   = 0;
    uint64_t closed = 0;
    uint64_t full   = 0;
    for (unsigned int i = 0; i < producer_count; i++)
    {
        sent += probes[i].sent;
        down += probes[i].down;
        closed += probes[i].closed;
        full += probes[i].full;
    }

    if (! deviceWriterChannelRetireCurrent(&shared.writer_channel) ||
        ! deviceWriterChannelDestroy(&shared.writer_channel))
    {
        fprintf(stderr, "device_writer_channel_benchmark: failed to destroy writer channel\n");
        exit(1);
    }
    free(producer_threads);
    free(probes);

    const double elapsed_seconds = (double) duration_ms / 1000.0;
    printf("%-12s producers=%u capacity=%zu sent/s=%12.0f full=%" PRIu64 " closed=%" PRIu64 " down=%" PRIu64
           " cpu_ms=%9.2f wall_ms=%9.2f\n",
           saturated ? "saturated" : "mostly-empty",
           producer_count,
           queue_capacity,
           (double) sent / elapsed_seconds,
           full,
           closed,
           down,
           (double) cpu_ns / 1000000.0,
           (double) wall_ns / 1000000.0);
}

int main(int argc, char **argv)
{
    unsigned int duration_ms = kDefaultDurationMs;
    if (argc > 2)
    {
        fprintf(stderr, "usage: %s [duration_ms]\n", argv[0]);
        return 2;
    }
    if (argc == 2)
    {
        const unsigned long requested = strtoul(argv[1], NULL, 10);
        if (requested == 0 || requested > UINT_MAX)
        {
            fprintf(stderr, "duration_ms must be between 1 and %u\n", UINT_MAX);
            return 2;
        }
        duration_ms = (unsigned int) requested;
    }

    const unsigned int producer_counts[] = {1, 2, 4, 8};
    for (size_t i = 0; i < ARRAY_SIZE(producer_counts); i++)
    {
        benchmarkRunCase(producer_counts[i], false, duration_ms);
    }
    for (size_t i = 0; i < ARRAY_SIZE(producer_counts); i++)
    {
        benchmarkRunCase(producer_counts[i], true, duration_ms);
    }
    return 0;
}

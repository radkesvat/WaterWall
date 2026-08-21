/*
 * Diagnostic worker-message benchmark. This is intentionally an excluded,
 * non-CTest target: results are comparative measurements for one host, not
 * machine-independent correctness thresholds.
 *
 * Examples:
 *
 *   cmake --preset linux
 *   cmake --build --preset linux --target worker_message_benchmark -j8
 *   ./build/linux/tests/benchmarks/Release/worker_message_benchmark 20000
 *
 * To include mailbox diagnostics, use a separate build directory/configure
 * with -DWW_WORKER_MESSAGE_BENCHMARK_INSTRUMENTATION=ON. That option compiles
 * the counter fields and hot-path increments into ww; production builds leave
 * both out completely.
 *
 * For a batch-size comparison, hold compiler, CMake preset, CPU affinity,
 * workload, and instrumentation mode constant; warm each binary, alternate
 * candidates, and collect at least five samples. Keep host-specific tables in
 * review material rather than turning them into repository thresholds.
 */

#include "global_state.h"
#include "wloop_internal.h"
#include "worker.h"
#include "worker_message_batch.h"
#include "worker_messages.h"
#include "wwapi.h"

#if defined(__linux__)
#include <sched.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

#ifndef WW_WORKER_MESSAGE_BENCHMARK_COMPILER
#define WW_WORKER_MESSAGE_BENCHMARK_COMPILER "unknown"
#endif
#ifndef WW_WORKER_MESSAGE_BENCHMARK_BUILD_TYPE
#define WW_WORKER_MESSAGE_BENCHMARK_BUILD_TYPE "unknown"
#endif
#ifndef WW_WORKER_MESSAGE_BENCHMARK_SOURCE_COMMIT
#define WW_WORKER_MESSAGE_BENCHMARK_SOURCE_COMMIT "unknown"
#endif
#ifndef WW_WORKER_MESSAGE_BENCHMARK_SOURCE_DIRTY
#define WW_WORKER_MESSAGE_BENCHMARK_SOURCE_DIRTY 1
#endif

enum
{
    kTargetWID                   = 1,
    kDefaultMessages             = 20000,
    kWarmupMessages              = 2000,
    kPacedMessagesCeiling        = 5000,
    kDelayedMessagesCeiling      = 10000,
    kLongDelayMs                 = 60000,
    kBenchmarkWaitMs             = 30000,
    kPreloadedTimerMs            = 1,
    kPollerProbeIntervalUs       = 1000,
    kPollerProbeBlockMs          = 20,
    kDefaultFairnessDurationMs   = 1000,
    kSustainedOutstandingLimit   = 4096,
    kMinimumPollerSampleCapacity = 4096,
};

typedef struct benchmark_payload_s
{
    void *arg1;
    void *arg2;
    void *arg3;
} benchmark_payload_t;

typedef struct benchmark_line_ref_s
{
    atomic_uint_fast64_t references;
    atomic_bool          alive;
} benchmark_line_ref_t;

typedef struct benchmark_case_s
{
    atomic_uint_fast64_t attempted;
    atomic_uint_fast64_t accepted;
    atomic_uint_fast64_t callbacks;
    atomic_uint_fast64_t cleanups;
    atomic_uint_fast64_t caller_retained;
    atomic_uint_fast64_t outstanding;
    atomic_uint_fast64_t sink;
    atomic_uint_fast64_t line_task_allocations;
    atomic_uint_fast64_t line_task_releases;
    atomic_uint_fast64_t line_task_peak_checked_out;
    atomic_bool          submissions_finished;
    atomic_bool          completion_claimed;
    atomic_bool          complete;
    uint64_t             start_ns;
    uint64_t             end_ns;
    uint64_t             producer_start_ns;
    uint64_t             producer_end_ns;
    benchmark_payload_t  payload;
    benchmark_line_ref_t line_ref;
} benchmark_case_t;

typedef union benchmark_line_task_callback_u {
    void (*no_buffer)(void);
    void (*with_buffer)(void);
} benchmark_line_task_callback_t;

/*
 * This mirrors the four-pointer line_task_msg_t payload used by
 * lineScheduleTask()/lineScheduleTaskWithBuf(). It deliberately uses the same
 * master pool, takes a line-reference-shaped ownership token, invokes a task,
 * and releases both after callback-or-cleanup settlement without needing a
 * tunnel-chain fixture.
 */
typedef struct benchmark_line_task_msg_s
{
    benchmark_line_task_callback_t callback;
    void                          *tunnel;
    benchmark_line_ref_t          *line;
    void                          *buf;
} benchmark_line_task_msg_t;

static_assert(sizeof(benchmark_line_task_msg_t) == sizeof(worker_msg_t),
              "line-task-shaped benchmark payload must match line_task_msg_t");

typedef enum benchmark_workload_e
{
    kBenchmarkWorkloadOwnership = 0,
    kBenchmarkWorkloadNoop,
    kBenchmarkWorkloadLineTask,
} benchmark_workload_e;

typedef struct benchmark_affinity_s
{
    bool        requested;
    bool        active;
    bool        isolated;
    bool        oversubscribed;
    uint32_t    available_cpus;
    int         target_cpu;
    int         pacing_cpu;
    atomic_bool target_pin_complete;
    atomic_bool runtime_pin_failed;
#if defined(__linux__)
    cpu_set_t producer_cpus;
#endif
} benchmark_affinity_t;

typedef struct benchmark_producer_s
{
    benchmark_case_t           *benchmark;
    benchmark_workload_e        workload;
    uint64_t                    messages;
    uint64_t                    deadline_ns;
    uint32_t                    delay_ms;
    bool                        timed;
    bool                        sustained;
    atomic_bool                *start;
    atomic_uint                *ready;
    atomic_bool                *failed;
    const benchmark_affinity_t *affinity;
    wthread_t                   thread;
} benchmark_producer_t;

typedef struct benchmark_driver_s
{
    benchmark_case_t *benchmark;
    uint64_t          messages;
    uint32_t          delay_ms;
    bool              force_queue;
    bool              timed;
} benchmark_driver_t;

typedef struct benchmark_paced_message_s
{
    benchmark_case_t *benchmark;
    atomic_bool       settled;
    uint64_t          sent_ns;
    uint64_t          latency_ns;
} benchmark_paced_message_t;

typedef struct benchmark_preloaded_probe_s
{
    benchmark_case_t *benchmark;
    atomic_bool       blocker_entered;
    atomic_bool       arm_timer;
    atomic_bool       timer_armed;
    atomic_bool       release_blocker;
    atomic_bool       timer_ran;
    uint64_t          timer_scheduled_ns;
    uint64_t          timer_latency_ns;
} benchmark_preloaded_probe_t;

typedef struct benchmark_recursive_s
{
    benchmark_case_t *benchmark;
    uint64_t          messages;
    uint64_t          count;
} benchmark_recursive_t;

typedef struct benchmark_poller_packet_s
{
    uint64_t sequence;
    uint64_t scheduled_ns;
} benchmark_poller_packet_t;

typedef struct benchmark_poller_probe_s
{
    benchmark_affinity_t *affinity;
    int                   read_fd;
    int                   write_fd;
    wio_t                *read_io;
    wthread_t             pacing_thread;
    atomic_bool           reader_ready;
    atomic_bool           reader_closed;
    atomic_bool           pacing_ready;
    atomic_bool           start;
    atomic_bool           stop;
    atomic_bool           pacing_done;
    atomic_uint_fast64_t  attempted;
    atomic_uint_fast64_t  sent;
    atomic_uint_fast64_t  received;
    atomic_uint_fast64_t  malformed;
    uint64_t             *latencies;
    size_t                capacity;
    size_t                count;
    uint64_t              duration_ns;
    uint64_t              start_ns;
} benchmark_poller_probe_t;

typedef struct benchmark_recursive_fairness_s
{
    benchmark_case_t *benchmark;
    uint64_t          deadline_ns;
} benchmark_recursive_fairness_t;

typedef struct benchmark_cancellation_control_s
{
    atomic_bool complete;
} benchmark_cancellation_control_t;

typedef struct benchmark_options_s
{
    uint64_t messages;
    uint32_t fairness_duration_ms;
    uint32_t cases;
    bool     affinity_requested;
} benchmark_options_t;

typedef enum benchmark_case_flags_e
{
    kBenchmarkCaseWarmup       = 1U << 0,
    kBenchmarkCaseInline       = 1U << 1,
    kBenchmarkCaseForced       = 1U << 2,
    kBenchmarkCaseBurst        = 1U << 3,
    kBenchmarkCasePreloaded    = 1U << 4,
    kBenchmarkCasePaced        = 1U << 5,
    kBenchmarkCaseRecursive    = 1U << 6,
    kBenchmarkCaseFairness     = 1U << 7,
    kBenchmarkCaseDelayed      = 1U << 8,
    kBenchmarkCaseCancellation = 1U << 9,
    kBenchmarkCaseAll          = (1U << 10) - 1U,
} benchmark_case_flags_e;

static const ww_lifecycle_context_t *benchmarkShutdownContext(void)
{
    static const ww_lifecycle_context_t context = {
        .scope        = kWwLifecycleProcessShutdown,
        .close_policy = kWwLifecycleCloseGraceful,
    };
    return &context;
}

static void benchmarkFail(const char *message)
{
    fprintf(stderr, "worker_message_benchmark: %s\n", message);
    abort();
}

static uint64_t benchmarkClockNS(clockid_t clock_id)
{
    struct timespec ts;
    if (clock_gettime(clock_id, &ts) != 0)
    {
        benchmarkFail("clock_gettime failed");
    }
    return (uint64_t) ts.tv_sec * UINT64_C(1000000000) + (uint64_t) ts.tv_nsec;
}

static void benchmarkWaitFor(atomic_bool *complete, const char *what)
{
    for (uint32_t waited = 0; waited < kBenchmarkWaitMs; ++waited)
    {
        if (atomic_load_explicit(complete, memory_order_acquire))
        {
            return;
        }
        wwSleepMS(1);
    }
    fprintf(stderr, "worker_message_benchmark: timed out waiting for %s\n", what);
    abort();
}

static void benchmarkWaitForFlag(const atomic_bool *flag, const char *what)
{
    benchmarkWaitFor((atomic_bool *) flag, what);
}

/* The preloaded-drain timer must be armed immediately before the target is
 * released. A millisecond sleep here would become part of the drain interval. */
static void benchmarkSpinWaitForFlag(const atomic_bool *flag, const char *what)
{
    const uint64_t deadline_ns = benchmarkClockNS(CLOCK_MONOTONIC) + (uint64_t) kBenchmarkWaitMs * 1000000U;
    while (! atomic_load_explicit((atomic_bool *) flag, memory_order_acquire))
    {
        if (benchmarkClockNS(CLOCK_MONOTONIC) >= deadline_ns)
        {
            fprintf(stderr, "worker_message_benchmark: timed out waiting for %s\n", what);
            abort();
        }
        YIELD_CPU();
    }
}

static void benchmarkAffinityInitialize(benchmark_affinity_t *affinity, bool requested)
{
    memoryZero(affinity, sizeof(*affinity));
    affinity->requested  = requested;
    affinity->target_cpu = -1;
    affinity->pacing_cpu = -1;
    atomic_init(&affinity->target_pin_complete, false);
    atomic_init(&affinity->runtime_pin_failed, false);

#if defined(__linux__)
    cpu_set_t available;
    CPU_ZERO(&available);
    if (sched_getaffinity(0, sizeof(available), &available) != 0)
    {
        affinity->oversubscribed = requested;
        return;
    }

    int allowed[CPU_SETSIZE];
    for (int cpu = 0; cpu < CPU_SETSIZE; ++cpu)
    {
        if (CPU_ISSET(cpu, &available))
        {
            allowed[affinity->available_cpus++] = cpu;
        }
    }
    if (! requested)
    {
        return;
    }
    if (affinity->available_cpus < 2)
    {
        affinity->oversubscribed = true;
        return;
    }

    affinity->target_cpu = allowed[0];
    affinity->pacing_cpu = allowed[1];
    CPU_ZERO(&affinity->producer_cpus);
    for (uint32_t i = 2; i < affinity->available_cpus; ++i)
    {
        CPU_SET(allowed[i], &affinity->producer_cpus);
    }
    if (affinity->available_cpus < 3)
    {
        /* Keep the target isolated even when pacing and producers must share
         * one CPU; these samples are explicitly excluded from selection. */
        CPU_SET(affinity->pacing_cpu, &affinity->producer_cpus);
        affinity->oversubscribed = true;
    }
    else
    {
        affinity->isolated = true;
    }
    affinity->active = true;
#else
    discard requested;
#endif
}

static bool benchmarkAffinityPinCurrentThreadToCpu(int cpu)
{
#if defined(__linux__)
    if (cpu < 0)
    {
        return false;
    }
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    return sched_setaffinity(0, sizeof(set), &set) == 0;
#else
    discard cpu;
    return false;
#endif
}

static bool benchmarkAffinityPinCurrentProducer(const benchmark_affinity_t *affinity)
{
    if (affinity == NULL || ! affinity->active)
    {
        return true;
    }
#if defined(__linux__)
    return sched_setaffinity(0, sizeof(affinity->producer_cpus), &affinity->producer_cpus) == 0;
#else
    return false;
#endif
}

static void benchmarkPinTargetWorker(worker_t *worker, void *arg1, void *arg2, void *arg3)
{
    benchmark_affinity_t *affinity = arg1;
    discard               arg2;
    discard               arg3;

    if (worker->wid != kTargetWID)
    {
        benchmarkFail("target-affinity callback ran on the wrong worker");
    }
    if (! benchmarkAffinityPinCurrentThreadToCpu(affinity->target_cpu))
    {
        atomic_store_explicit(&affinity->runtime_pin_failed, true, memory_order_release);
    }
    atomic_store_explicit(&affinity->target_pin_complete, true, memory_order_release);
}

static void benchmarkApplyTargetAffinity(benchmark_affinity_t *affinity)
{
    if (! affinity->active)
    {
        return;
    }
    if (sendWorkerMessageForceQueueWithCleanup(
            kTargetWID, (WorkerMessageCallback) benchmarkPinTargetWorker, NULL, affinity, NULL, NULL) !=
        kWorkerMessageSubmitAccepted)
    {
        benchmarkFail("target-affinity submission was refused");
    }
    benchmarkWaitForFlag(&affinity->target_pin_complete, "target worker affinity");
}

static void benchmarkPrintAffinity(const benchmark_affinity_t *affinity)
{
    if (! affinity->requested)
    {
        printf("worker_message_benchmark: affinity=off cpu-count=%u; fairness percentiles are observational\n",
               affinity->available_cpus);
        return;
    }
    if (! affinity->active)
    {
        printf("worker_message_benchmark: affinity unavailable cpu-count=%u; fairness percentiles are excluded from "
               "batch selection\n",
               affinity->available_cpus);
        return;
    }

    printf("worker_message_benchmark: affinity target=cpu%d pacing=cpu%d producers={",
           affinity->target_cpu,
           affinity->pacing_cpu);
#if defined(__linux__)
    bool first = true;
    for (int cpu = 0; cpu < CPU_SETSIZE; ++cpu)
    {
        if (CPU_ISSET(cpu, &affinity->producer_cpus))
        {
            printf("%s%d", first ? "" : ",", cpu);
            first = false;
        }
    }
#endif
    printf("} cpu-count=%u %s\n",
           affinity->available_cpus,
           affinity->isolated && ! atomic_load_explicit(&affinity->runtime_pin_failed, memory_order_acquire)
               ? "isolated"
               : "oversubscribed/excluded-from-selection");
}

static void benchmarkCaseInit(benchmark_case_t *benchmark)
{
    memoryZero(benchmark, sizeof(*benchmark));
    atomic_init(&benchmark->attempted, 0);
    atomic_init(&benchmark->accepted, 0);
    atomic_init(&benchmark->callbacks, 0);
    atomic_init(&benchmark->cleanups, 0);
    atomic_init(&benchmark->caller_retained, 0);
    atomic_init(&benchmark->outstanding, 0);
    atomic_init(&benchmark->sink, 0);
    atomic_init(&benchmark->line_task_allocations, 0);
    atomic_init(&benchmark->line_task_releases, 0);
    atomic_init(&benchmark->line_task_peak_checked_out, 0);
    atomic_init(&benchmark->submissions_finished, false);
    atomic_init(&benchmark->completion_claimed, false);
    atomic_init(&benchmark->complete, false);
    atomic_init(&benchmark->line_ref.references, 1);
    atomic_init(&benchmark->line_ref.alive, true);
    benchmark->payload = (benchmark_payload_t) {
        .arg1 = benchmark,
        .arg2 = &benchmark->callbacks,
        .arg3 = &benchmark->cleanups,
    };
}

static void benchmarkCaseStart(benchmark_case_t *benchmark)
{
    benchmark->start_ns = benchmarkClockNS(CLOCK_MONOTONIC);
}

static void benchmarkCaseComplete(benchmark_case_t *benchmark)
{
    bool expected = false;
    if (! atomic_compare_exchange_strong_explicit(
            &benchmark->completion_claimed, &expected, true, memory_order_acq_rel, memory_order_acquire))
    {
        return;
    }
    benchmark->end_ns = benchmarkClockNS(CLOCK_MONOTONIC);
    atomic_store_explicit(&benchmark->complete, true, memory_order_release);
}

static void benchmarkCaseTryComplete(benchmark_case_t *benchmark)
{
    if (! atomic_load_explicit(&benchmark->submissions_finished, memory_order_acquire) ||
        atomic_load_explicit(&benchmark->outstanding, memory_order_acquire) != 0)
    {
        return;
    }
    benchmarkCaseComplete(benchmark);
}

static void benchmarkCaseBeginSubmission(benchmark_case_t *benchmark)
{
    atomic_fetch_add_explicit(&benchmark->attempted, 1, memory_order_relaxed);
    atomic_fetch_add_explicit(&benchmark->outstanding, 1, memory_order_relaxed);
}

static void benchmarkCaseSettle(benchmark_case_t *benchmark, bool callback)
{
    if (callback)
    {
        atomic_fetch_add_explicit(&benchmark->callbacks, 1, memory_order_relaxed);
    }
    else
    {
        atomic_fetch_add_explicit(&benchmark->cleanups, 1, memory_order_relaxed);
    }

    const uint_fast64_t previous = atomic_fetch_sub_explicit(&benchmark->outstanding, 1, memory_order_acq_rel);
    if (previous == 0)
    {
        benchmarkFail("callback-or-cleanup settlement underflow");
    }
    if (previous == 1)
    {
        benchmarkCaseTryComplete(benchmark);
    }
}

static bool benchmarkCaseRecordResult(benchmark_case_t *benchmark, worker_message_submit_result_e result)
{
    if (result == kWorkerMessageSubmitAccepted)
    {
        atomic_fetch_add_explicit(&benchmark->accepted, 1, memory_order_relaxed);
        return true;
    }

    if (result == kWorkerMessageSubmitRejectedCallerRetains)
    {
        atomic_fetch_add_explicit(&benchmark->caller_retained, 1, memory_order_relaxed);
        const uint_fast64_t previous = atomic_fetch_sub_explicit(&benchmark->outstanding, 1, memory_order_acq_rel);
        if (previous == 0)
        {
            benchmarkFail("caller-retained settlement underflow");
        }
        if (previous == 1)
        {
            benchmarkCaseTryComplete(benchmark);
        }
    }
    return false;
}

static void benchmarkCaseFinishSubmissions(benchmark_case_t *benchmark)
{
    atomic_store_explicit(&benchmark->submissions_finished, true, memory_order_release);
    benchmarkCaseTryComplete(benchmark);
}

static uint64_t benchmarkLoadCounter(const atomic_uint_fast64_t *counter)
{
    return (uint64_t) atomic_load_explicit((atomic_uint_fast64_t *) counter, memory_order_acquire);
}

static void benchmarkVerifyCase(const benchmark_case_t *benchmark)
{
    const uint64_t attempted       = benchmarkLoadCounter(&benchmark->attempted);
    const uint64_t accepted        = benchmarkLoadCounter(&benchmark->accepted);
    const uint64_t callbacks       = benchmarkLoadCounter(&benchmark->callbacks);
    const uint64_t cleanups        = benchmarkLoadCounter(&benchmark->cleanups);
    const uint64_t caller_retained = benchmarkLoadCounter(&benchmark->caller_retained);

    if (attempted != accepted + caller_retained)
    {
        benchmarkFail("attempted messages do not partition into accepted and caller-retained ownership");
    }
    if (accepted != callbacks + cleanups)
    {
        benchmarkFail("accepted messages did not settle through exactly one callback-or-cleanup path");
    }
    if (atomic_load_explicit((atomic_uint_fast64_t *) &benchmark->outstanding, memory_order_acquire) != 0)
    {
        benchmarkFail("benchmark completed with unsettled accepted work");
    }
    if (benchmarkLoadCounter(&benchmark->line_task_allocations) != 0 &&
        atomic_load_explicit((atomic_uint_fast64_t *) &benchmark->line_ref.references, memory_order_acquire) != 1)
    {
        benchmarkFail("line-task-shaped workload leaked a line-reference-shaped ownership token");
    }
}

#ifdef WW_WORKER_MESSAGE_BENCHMARK_INSTRUMENTATION
static void benchmarkResetDiagnostics(void)
{
    workerMessagesBenchmarkResetCounters(getWorker(kTargetWID));
}

static void benchmarkPrintDiagnostics(void)
{
    worker_message_benchmark_counters_t counters;
    workerMessagesBenchmarkGetCounters(getWorker(kTargetWID), &counters);

    const double captured_mean = counters.worker_drain_callbacks == 0 ? 0.0
                                                                      : (double) counters.messages_captured_by_drains /
                                                                            (double) counters.worker_drain_callbacks;
    printf("  mailbox: high-water=%" PRIu64 " drains=%" PRIu64 " captured=%.1f/%" PRIu64 " wake-posts=initial:%" PRIu64
           " successor:%" PRIu64 " fallback:%" PRIu64 " os-writes=%" PRIu64 "\n",
           counters.ordinary_queue_high_watermark,
           counters.worker_drain_callbacks,
           captured_mean,
           counters.maximum_messages_captured_by_one_drain,
           counters.initial_wake_post_attempts,
           counters.successor_wake_post_attempts,
           counters.hard_successor_wake_fallbacks,
           counters.loop_os_wake_write_attempts);
    printf("  delayed: setup=%" PRIu64 " complete=%" PRIu64 " rearm=%" PRIu64 " cancel=%" PRIu64
           " records=timed:%zu/%zuB (requested/usable) line-task:%zu/%zuB (payload/effective-pool-usable)\n",
           counters.delayed_timer_setups,
           counters.delayed_timer_completions,
           counters.delayed_timer_rearms,
           counters.delayed_timer_cancellations,
           counters.timed_record_size,
           counters.timed_record_usable_size,
           counters.line_task_record_size,
           counters.line_task_effective_pool_item_usable_size);
}
#else
static void benchmarkResetDiagnostics(void)
{
}

static void benchmarkPrintDiagnostics(void)
{
}
#endif

static void benchmarkPrintCase(const char *name, const benchmark_case_t *benchmark, uint64_t cpu_ns)
{
    benchmarkVerifyCase(benchmark);

    const uint64_t attempted         = benchmarkLoadCounter(&benchmark->attempted);
    const uint64_t accepted          = benchmarkLoadCounter(&benchmark->accepted);
    const uint64_t callbacks         = benchmarkLoadCounter(&benchmark->callbacks);
    const uint64_t cleanups          = benchmarkLoadCounter(&benchmark->cleanups);
    const uint64_t caller_retained   = benchmarkLoadCounter(&benchmark->caller_retained);
    const uint64_t elapsed_ns        = benchmark->end_ns - benchmark->start_ns;
    const double   elapsed_seconds   = (double) elapsed_ns / 1000000000.0;
    const double messages_per_second = elapsed_seconds == 0.0 ? 0.0 : (double) (callbacks + cleanups) / elapsed_seconds;
    const double cpu_per_message     = accepted == 0 ? 0.0 : (double) cpu_ns / (double) accepted;

    printf("%-34s attempted=%9" PRIu64 " accepted=%9" PRIu64 " callback=%9" PRIu64 " cleanup=%9" PRIu64
           " retained=%9" PRIu64 " msg/s=%12.0f cpu-ns/msg=%9.1f\n",
           name,
           attempted,
           accepted,
           callbacks,
           cleanups,
           caller_retained,
           messages_per_second,
           cpu_per_message);

    if (benchmark->producer_end_ns > benchmark->producer_start_ns)
    {
        const uint64_t producer_elapsed_ns = benchmark->producer_end_ns - benchmark->producer_start_ns;
        const double   producer_seconds    = (double) producer_elapsed_ns / 1000000000.0;
        const double   producer_rate       = producer_seconds == 0.0 ? 0.0 : (double) attempted / producer_seconds;
        printf("  producer/enqueue: %.0f msg/s (%" PRIu64 " ns)\n", producer_rate, producer_elapsed_ns);
    }

    const uint64_t line_task_allocations = benchmarkLoadCounter(&benchmark->line_task_allocations);
    if (line_task_allocations != 0)
    {
        printf("  line-task shape: allocations=%" PRIu64 " releases=%" PRIu64 " peak-checked-out=%" PRIu64 "\n",
               line_task_allocations,
               benchmarkLoadCounter(&benchmark->line_task_releases),
               benchmarkLoadCounter(&benchmark->line_task_peak_checked_out));
    }
    benchmarkPrintDiagnostics();
}

static void benchmarkMessageCallback(worker_t *worker, void *arg1, void *arg2, void *arg3)
{
    benchmark_case_t    *benchmark = arg1;
    benchmark_payload_t *payload   = arg2;

    if (worker->wid != kTargetWID || payload == NULL || arg3 != payload)
    {
        benchmarkFail("ownership-bearing callback lost target affinity or payload shape");
    }
    atomic_fetch_xor_explicit(&benchmark->sink,
                              (uint_fast64_t) (uintptr_t) payload->arg1 ^ (uint_fast64_t) (uintptr_t) payload->arg2 ^
                                  (uint_fast64_t) (uintptr_t) payload->arg3,
                              memory_order_relaxed);
    benchmarkCaseSettle(benchmark, true);
}

static void benchmarkMessageCleanup(void *arg1, void *arg2, void *arg3, worker_message_cancel_reason_e reason)
{
    benchmark_case_t    *benchmark = arg1;
    benchmark_payload_t *payload   = arg2;
    discard              reason;

    if (payload == NULL || arg3 != payload)
    {
        benchmarkFail("ownership-bearing cleanup lost payload shape");
    }
    atomic_fetch_xor_explicit(&benchmark->sink,
                              (uint_fast64_t) (uintptr_t) payload->arg1 ^ (uint_fast64_t) (uintptr_t) payload->arg2 ^
                                  (uint_fast64_t) (uintptr_t) payload->arg3,
                              memory_order_relaxed);
    benchmarkCaseSettle(benchmark, false);
}

static bool benchmarkSubmitWorkerMessage(benchmark_case_t *benchmark, WorkerMessageCallback callback,
                                         WorkerMessageCleanupCallback cleanup, void *arg1, void *arg2, void *arg3,
                                         bool timed, uint32_t delay_ms)
{
    benchmarkCaseBeginSubmission(benchmark);
    const worker_message_submit_result_e result =
        timed ? sendWorkerMessageTimedWithCleanup(kTargetWID, callback, cleanup, delay_ms, arg1, arg2, arg3)
              : sendWorkerMessageForceQueueWithCleanup(kTargetWID, callback, cleanup, arg1, arg2, arg3);
    return benchmarkCaseRecordResult(benchmark, result);
}

static bool benchmarkSubmitOwnership(benchmark_case_t *benchmark, bool timed, uint32_t delay_ms)
{
    return benchmarkSubmitWorkerMessage(benchmark,
                                        (WorkerMessageCallback) benchmarkMessageCallback,
                                        benchmarkMessageCleanup,
                                        benchmark,
                                        &benchmark->payload,
                                        &benchmark->payload,
                                        timed,
                                        delay_ms);
}

static bool benchmarkSubmitInlineOwnership(benchmark_case_t *benchmark)
{
    /*
     * This branch is entered only inside an admitted callback on the target
     * worker, so the public inline API is guaranteed to settle synchronously.
     */
    benchmarkCaseBeginSubmission(benchmark);
    sendWorkerMessageWithCleanup(kTargetWID,
                                 (WorkerMessageCallback) benchmarkMessageCallback,
                                 benchmarkMessageCleanup,
                                 benchmark,
                                 &benchmark->payload,
                                 &benchmark->payload);
    atomic_fetch_add_explicit(&benchmark->accepted, 1, memory_order_relaxed);
    return true;
}

static void benchmarkNoopCallback(worker_t *worker, void *arg1, void *arg2, void *arg3)
{
    discard worker;
    discard arg1;
    discard arg2;
    discard arg3;
}

static bool benchmarkSubmitNoop(benchmark_case_t *benchmark)
{
    atomic_fetch_add_explicit(&benchmark->attempted, 1, memory_order_relaxed);
    const worker_message_submit_result_e result = sendWorkerMessageForceQueueWithCleanup(
        kTargetWID, (WorkerMessageCallback) benchmarkNoopCallback, NULL, NULL, NULL, NULL);
    if (result == kWorkerMessageSubmitAccepted)
    {
        atomic_fetch_add_explicit(&benchmark->accepted, 1, memory_order_relaxed);
        return true;
    }
    if (result == kWorkerMessageSubmitRejectedCallerRetains)
    {
        atomic_fetch_add_explicit(&benchmark->caller_retained, 1, memory_order_relaxed);
    }
    return false;
}

static void benchmarkNoopSentinel(worker_t *worker, void *arg1, void *arg2, void *arg3)
{
    benchmark_case_t *benchmark = arg1;
    discard           arg2;
    discard           arg3;

    if (worker->wid != kTargetWID)
    {
        benchmarkFail("no-op sentinel ran on the wrong worker");
    }
    atomic_store_explicit(
        &benchmark->callbacks, atomic_load_explicit(&benchmark->accepted, memory_order_relaxed), memory_order_relaxed);
    benchmarkCaseComplete(benchmark);
}

static void benchmarkLineTaskOperation(void)
{
}

static void benchmarkTrackLineTaskPeak(benchmark_case_t *benchmark, uint64_t checked_out)
{
    uint_fast64_t observed = atomic_load_explicit(&benchmark->line_task_peak_checked_out, memory_order_relaxed);
    while (
        observed < checked_out &&
        ! atomic_compare_exchange_weak_explicit(
            &benchmark->line_task_peak_checked_out, &observed, checked_out, memory_order_relaxed, memory_order_relaxed))
    {
    }
}

static benchmark_line_task_msg_t *benchmarkLineTaskCreate(benchmark_case_t *benchmark)
{
    benchmark_line_task_msg_t *message;
    masterpoolGetItems(GSTATE.masterpool_messages, (void **) &message, 1, NULL);
    *message = (benchmark_line_task_msg_t) {
        .callback.no_buffer = benchmarkLineTaskOperation,
        .tunnel             = benchmark,
        .line               = &benchmark->line_ref,
        .buf                = NULL,
    };

    atomic_fetch_add_explicit(&benchmark->line_ref.references, 1, memory_order_relaxed);
    const uint64_t checked_out =
        atomic_fetch_add_explicit(&benchmark->line_task_allocations, 1, memory_order_relaxed) + 1;
    const uint64_t released = benchmarkLoadCounter(&benchmark->line_task_releases);
    benchmarkTrackLineTaskPeak(benchmark, checked_out - released);
    return message;
}

static void benchmarkLineTaskRelease(benchmark_case_t *benchmark, benchmark_line_task_msg_t *message)
{
    const uint_fast64_t previous = atomic_fetch_sub_explicit(&benchmark->line_ref.references, 1, memory_order_acq_rel);
    if (previous <= 1)
    {
        benchmarkFail("line-task-shaped release underflow");
    }
    masterpoolReuseItems(GSTATE.masterpool_messages, (void **) &message, 1);
    atomic_fetch_add_explicit(&benchmark->line_task_releases, 1, memory_order_relaxed);
}

static void benchmarkLineTaskCallback(worker_t *worker, void *arg1, void *arg2, void *arg3)
{
    benchmark_line_task_msg_t *message   = arg1;
    benchmark_case_t          *benchmark = message == NULL ? NULL : message->tunnel;
    discard                    arg2;
    discard                    arg3;

    if (worker->wid != kTargetWID || benchmark == NULL || message->line != &benchmark->line_ref ||
        ! atomic_load_explicit(&benchmark->line_ref.alive, memory_order_acquire))
    {
        benchmarkFail("line-task-shaped callback lost affinity or stable payload ownership");
    }
    message->callback.no_buffer();
    atomic_fetch_xor_explicit(&benchmark->sink, (uint_fast64_t) (uintptr_t) message, memory_order_relaxed);
    benchmarkLineTaskRelease(benchmark, message);
    benchmarkCaseSettle(benchmark, true);
}

static void benchmarkLineTaskCleanup(void *arg1, void *arg2, void *arg3, worker_message_cancel_reason_e reason)
{
    benchmark_line_task_msg_t *message   = arg1;
    benchmark_case_t          *benchmark = message == NULL ? NULL : message->tunnel;
    discard                    arg2;
    discard                    arg3;
    discard                    reason;

    if (benchmark == NULL || message->line != &benchmark->line_ref)
    {
        benchmarkFail("line-task-shaped cleanup lost stable payload ownership");
    }
    benchmarkLineTaskRelease(benchmark, message);
    benchmarkCaseSettle(benchmark, false);
}

static bool benchmarkSubmitLineTask(benchmark_case_t *benchmark)
{
    benchmark_line_task_msg_t *message = benchmarkLineTaskCreate(benchmark);
    return benchmarkSubmitWorkerMessage(benchmark,
                                        (WorkerMessageCallback) benchmarkLineTaskCallback,
                                        benchmarkLineTaskCleanup,
                                        message,
                                        NULL,
                                        NULL,
                                        false,
                                        0);
}

static WTHREAD_ROUTINE(benchmarkProducerMain)
{
    benchmark_producer_t *producer = userdata;

    if (! benchmarkAffinityPinCurrentProducer(producer->affinity))
    {
        atomic_store_explicit(&producer->affinity->runtime_pin_failed, true, memory_order_release);
    }
    atomic_fetch_add_explicit(producer->ready, 1, memory_order_release);
    while (! atomic_load_explicit(producer->start, memory_order_acquire))
    {
        YIELD_CPU();
    }

    for (uint64_t i = 0; ! producer->sustained || benchmarkClockNS(CLOCK_MONOTONIC) < producer->deadline_ns; ++i)
    {
        if (! producer->sustained && i == producer->messages)
        {
            break;
        }
        if (producer->sustained &&
            atomic_load_explicit(&producer->benchmark->outstanding, memory_order_relaxed) >= kSustainedOutstandingLimit)
        {
            YIELD_CPU();
            continue;
        }

        bool accepted;
        switch (producer->workload)
        {
        case kBenchmarkWorkloadOwnership:
            accepted = benchmarkSubmitOwnership(producer->benchmark, producer->timed, producer->delay_ms);
            break;
        case kBenchmarkWorkloadNoop:
            accepted = benchmarkSubmitNoop(producer->benchmark);
            break;
        case kBenchmarkWorkloadLineTask:
            accepted = benchmarkSubmitLineTask(producer->benchmark);
            break;
        default:
            benchmarkFail("unknown benchmark workload");
            return 0;
        }

        if (! accepted)
        {
            atomic_store_explicit(producer->failed, true, memory_order_release);
            return 0;
        }
    }
    return 0;
}

static void benchmarkRunBurst(const char *name, uint32_t producers, uint64_t messages, benchmark_workload_e workload,
                              bool timed, uint32_t delay_ms, const benchmark_affinity_t *affinity)
{
    benchmark_case_t benchmark;
    benchmarkCaseInit(&benchmark);
    benchmarkResetDiagnostics();

    benchmark_producer_t *producer = calloc(producers, sizeof(*producer));
    if (producer == NULL)
    {
        benchmarkFail("producer allocation failed");
    }
    atomic_bool start;
    atomic_bool failed;
    atomic_uint ready;
    atomic_init(&start, false);
    atomic_init(&failed, false);
    atomic_init(&ready, 0);

    for (uint32_t i = 0; i < producers; ++i)
    {
        producer[i] = (benchmark_producer_t) {
            .benchmark = &benchmark,
            .workload  = workload,
            .messages  = messages,
            .delay_ms  = delay_ms,
            .timed     = timed,
            .start     = &start,
            .ready     = &ready,
            .failed    = &failed,
            .affinity  = affinity,
        };
        if (threadCreate(&producer[i].thread, benchmarkProducerMain, &producer[i]) != kWThreadErrorNone)
        {
            benchmarkFail("producer thread creation failed");
        }
    }
    while (atomic_load_explicit(&ready, memory_order_acquire) != producers)
    {
        YIELD_CPU();
    }

    const uint64_t cpu_start = benchmarkClockNS(CLOCK_PROCESS_CPUTIME_ID);
    benchmarkCaseStart(&benchmark);
    benchmark.producer_start_ns = benchmark.start_ns;
    atomic_store_explicit(&start, true, memory_order_release);
    for (uint32_t i = 0; i < producers; ++i)
    {
        if (threadJoin(producer[i].thread) != 0)
        {
            benchmarkFail("producer thread join failed");
        }
    }
    benchmark.producer_end_ns = benchmarkClockNS(CLOCK_MONOTONIC);
    if (atomic_load_explicit(&failed, memory_order_acquire))
    {
        benchmarkFail("benchmark producer submission was refused");
    }

    if (workload == kBenchmarkWorkloadNoop)
    {
        if (sendWorkerMessageForceQueueWithCleanup(
                kTargetWID, (WorkerMessageCallback) benchmarkNoopSentinel, NULL, &benchmark, NULL, NULL) !=
            kWorkerMessageSubmitAccepted)
        {
            benchmarkFail("no-op sentinel submission was refused");
        }
    }
    else
    {
        benchmarkCaseFinishSubmissions(&benchmark);
    }

    benchmarkWaitFor(&benchmark.complete, name);
    const uint64_t cpu_ns = benchmarkClockNS(CLOCK_PROCESS_CPUTIME_ID) - cpu_start;
    benchmarkPrintCase(name, &benchmark, cpu_ns);
    free(producer);
}

static void benchmarkDriverCallback(worker_t *worker, void *arg1, void *arg2, void *arg3)
{
    benchmark_driver_t *driver = arg1;
    discard             arg2;
    discard             arg3;

    if (worker->wid != kTargetWID)
    {
        benchmarkFail("same-worker driver ran on the wrong worker");
    }

    benchmarkCaseStart(driver->benchmark);
    driver->benchmark->producer_start_ns = driver->benchmark->start_ns;
    for (uint64_t i = 0; i < driver->messages; ++i)
    {
        bool accepted;
        if (driver->timed)
        {
            accepted = benchmarkSubmitOwnership(driver->benchmark, true, driver->delay_ms);
        }
        else if (driver->force_queue)
        {
            accepted = benchmarkSubmitOwnership(driver->benchmark, false, 0);
        }
        else
        {
            accepted = benchmarkSubmitInlineOwnership(driver->benchmark);
        }
        if (! accepted)
        {
            benchmarkFail("same-worker driver submission was refused");
        }
    }
    driver->benchmark->producer_end_ns = benchmarkClockNS(CLOCK_MONOTONIC);
    benchmarkCaseFinishSubmissions(driver->benchmark);
}

static void benchmarkRunDriverCase(const char *name, benchmark_driver_t *driver)
{
    benchmarkResetDiagnostics();
    const uint64_t cpu_start = benchmarkClockNS(CLOCK_PROCESS_CPUTIME_ID);
    if (sendWorkerMessageForceQueueWithCleanup(
            kTargetWID, (WorkerMessageCallback) benchmarkDriverCallback, NULL, driver, NULL, NULL) !=
        kWorkerMessageSubmitAccepted)
    {
        benchmarkFail("same-worker driver submission was refused");
    }
    benchmarkWaitFor(&driver->benchmark->complete, name);
    const uint64_t cpu_ns = benchmarkClockNS(CLOCK_PROCESS_CPUTIME_ID) - cpu_start;
    benchmarkPrintCase(name, driver->benchmark, cpu_ns);
}

static int benchmarkCompareU64(const void *lhs, const void *rhs)
{
    const uint64_t a = *(const uint64_t *) lhs;
    const uint64_t b = *(const uint64_t *) rhs;
    return (a > b) - (a < b);
}

static void benchmarkPacedCallback(worker_t *worker, void *arg1, void *arg2, void *arg3)
{
    benchmark_case_t          *benchmark = arg1;
    benchmark_paced_message_t *message   = arg2;
    discard                    arg3;

    if (worker->wid != kTargetWID)
    {
        benchmarkFail("paced callback ran on the wrong worker");
    }
    message->latency_ns = benchmarkClockNS(CLOCK_MONOTONIC) - message->sent_ns;
    atomic_store_explicit(&message->settled, true, memory_order_release);
    benchmarkCaseSettle(benchmark, true);
}

static void benchmarkPacedCleanup(void *arg1, void *arg2, void *arg3, worker_message_cancel_reason_e reason)
{
    benchmark_case_t          *benchmark = arg1;
    benchmark_paced_message_t *message   = arg2;
    discard                    arg3;
    discard                    reason;

    atomic_store_explicit(&message->settled, true, memory_order_release);
    benchmarkCaseSettle(benchmark, false);
}

static void benchmarkRunPaced(uint64_t messages)
{
    benchmark_case_t benchmark;
    benchmarkCaseInit(&benchmark);
    benchmarkResetDiagnostics();

    uint64_t *latencies = calloc(messages, sizeof(*latencies));
    if (latencies == NULL)
    {
        benchmarkFail("paced latency allocation failed");
    }

    const uint64_t cpu_start = benchmarkClockNS(CLOCK_PROCESS_CPUTIME_ID);
    benchmarkCaseStart(&benchmark);
    for (uint64_t i = 0; i < messages; ++i)
    {
        benchmark_paced_message_t message;
        memoryZero(&message, sizeof(message));
        atomic_init(&message.settled, false);
        message.benchmark = &benchmark;
        message.sent_ns   = benchmarkClockNS(CLOCK_MONOTONIC);

        if (! benchmarkSubmitWorkerMessage(&benchmark,
                                           (WorkerMessageCallback) benchmarkPacedCallback,
                                           benchmarkPacedCleanup,
                                           &benchmark,
                                           &message,
                                           NULL,
                                           false,
                                           0))
        {
            benchmarkFail("paced submission was refused");
        }
        benchmarkWaitForFlag(&message.settled, "paced callback");
        latencies[i] = message.latency_ns;
    }
    benchmarkCaseFinishSubmissions(&benchmark);
    benchmarkWaitFor(&benchmark.complete, "paced callbacks");
    const uint64_t cpu_ns = benchmarkClockNS(CLOCK_PROCESS_CPUTIME_ID) - cpu_start;

    qsort(latencies, messages, sizeof(*latencies), benchmarkCompareU64);
    benchmarkPrintCase("foreign producer / paced ownership", &benchmark, cpu_ns);
    printf("  latency: p50=%8.1fus p95=%8.1fus p99=%8.1fus max=%8.1fus\n",
           (double) latencies[(messages * 50U) / 100U] / 1000.0,
           (double) latencies[(messages * 95U) / 100U] / 1000.0,
           (double) latencies[(messages * 99U) / 100U] / 1000.0,
           (double) latencies[messages - 1] / 1000.0);
    free(latencies);
}

static void benchmarkPreloadedTimerCallback(wtimer_t *timer)
{
    benchmark_preloaded_probe_t *probe = weventGetUserdata(timer);
    probe->timer_latency_ns            = benchmarkClockNS(CLOCK_MONOTONIC) - probe->timer_scheduled_ns;
    atomic_store_explicit(&probe->timer_ran, true, memory_order_release);
}

static void benchmarkPreloadedBlocker(worker_t *worker, void *arg1, void *arg2, void *arg3)
{
    benchmark_preloaded_probe_t *probe = arg1;
    discard                      arg2;
    discard                      arg3;

    if (worker->wid != kTargetWID)
    {
        benchmarkFail("preloaded blocker ran on the wrong worker");
    }
    atomic_store_explicit(&probe->blocker_entered, true, memory_order_release);
    while (! atomic_load_explicit(&probe->arm_timer, memory_order_acquire))
    {
        YIELD_THREAD();
    }

    probe->timer_scheduled_ns = benchmarkClockNS(CLOCK_MONOTONIC);
    wtimer_t *timer           = wtimerAdd(worker->loop, benchmarkPreloadedTimerCallback, kPreloadedTimerMs, 1);
    if (timer == NULL)
    {
        benchmarkFail("failed to arm the preloaded consumer timer");
    }
    weventSetUserData(timer, probe);
    atomic_store_explicit(&probe->timer_armed, true, memory_order_release);

    while (! atomic_load_explicit(&probe->release_blocker, memory_order_acquire))
    {
        YIELD_THREAD();
    }
    /* Exclude only the producer-to-consumer hand-off: the worker begins its
     * measured drain immediately before this callback yields the queue. */
    probe->benchmark->start_ns = benchmarkClockNS(CLOCK_MONOTONIC);
}

static void benchmarkRunPreloaded(uint64_t messages)
{
    benchmark_case_t            benchmark;
    benchmark_preloaded_probe_t probe;
    benchmarkCaseInit(&benchmark);
    memoryZero(&probe, sizeof(probe));
    probe.benchmark = &benchmark;
    atomic_init(&probe.blocker_entered, false);
    atomic_init(&probe.arm_timer, false);
    atomic_init(&probe.timer_armed, false);
    atomic_init(&probe.release_blocker, false);
    atomic_init(&probe.timer_ran, false);
    benchmarkResetDiagnostics();

    if (sendWorkerMessageForceQueueWithCleanup(
            kTargetWID, (WorkerMessageCallback) benchmarkPreloadedBlocker, NULL, &probe, NULL, NULL) !=
        kWorkerMessageSubmitAccepted)
    {
        benchmarkFail("preloaded blocker submission was refused");
    }
    benchmarkWaitForFlag(&probe.blocker_entered, "preloaded blocker");

    const uint64_t cpu_start    = benchmarkClockNS(CLOCK_PROCESS_CPUTIME_ID);
    benchmark.producer_start_ns = benchmarkClockNS(CLOCK_MONOTONIC);
    for (uint64_t i = 0; i < messages; ++i)
    {
        if (! benchmarkSubmitOwnership(&benchmark, false, 0))
        {
            benchmarkFail("preloaded finite-burst submission was refused");
        }
    }
    benchmark.producer_end_ns = benchmarkClockNS(CLOCK_MONOTONIC);

    /*
     * The target worker arms this real timer just before the blocker is
     * released. Producer time above is intentionally kept separate from the
     * consumer drain interval beginning at benchmark.start_ns.
     */
    atomic_store_explicit(&probe.arm_timer, true, memory_order_release);
    benchmarkSpinWaitForFlag(&probe.timer_armed, "preloaded consumer timer arm");
    benchmarkCaseFinishSubmissions(&benchmark);
    atomic_store_explicit(&probe.release_blocker, true, memory_order_release);

    benchmarkWaitFor(&benchmark.complete, "preloaded finite burst drain");
    benchmarkWaitForFlag(&probe.timer_ran, "preloaded consumer timer callback");
    const uint64_t cpu_ns = benchmarkClockNS(CLOCK_PROCESS_CPUTIME_ID) - cpu_start;
    benchmarkPrintCase("preloaded finite burst / ownership", &benchmark, cpu_ns);
    printf("  unrelated timer after release: %.1fus\n", (double) probe.timer_latency_ns / 1000.0);
}

static void benchmarkRecursiveCallback(worker_t *worker, void *arg1, void *arg2, void *arg3)
{
    benchmark_recursive_t *recursive = arg1;
    discard                arg2;
    discard                arg3;

    if (worker->wid != kTargetWID)
    {
        benchmarkFail("recursive callback ran on the wrong worker");
    }
    ++recursive->count;
    if (recursive->count < recursive->messages)
    {
        if (! benchmarkSubmitWorkerMessage(recursive->benchmark,
                                           (WorkerMessageCallback) benchmarkRecursiveCallback,
                                           NULL,
                                           recursive,
                                           NULL,
                                           NULL,
                                           false,
                                           0))
        {
            benchmarkFail("recursive successor was refused");
        }
    }
    else
    {
        benchmarkCaseFinishSubmissions(recursive->benchmark);
    }
    benchmarkCaseSettle(recursive->benchmark, true);
}

static void benchmarkRecursiveCleanup(void *arg1, void *arg2, void *arg3, worker_message_cancel_reason_e reason)
{
    benchmark_recursive_t *recursive = arg1;
    discard                arg2;
    discard                arg3;
    discard                reason;

    benchmarkCaseSettle(recursive->benchmark, false);
}

static void benchmarkRunRecursive(uint64_t messages)
{
    benchmark_case_t      benchmark;
    benchmark_recursive_t recursive;
    benchmarkCaseInit(&benchmark);
    recursive = (benchmark_recursive_t) {
        .benchmark = &benchmark,
        .messages  = messages,
    };
    benchmarkResetDiagnostics();

    const uint64_t cpu_start = benchmarkClockNS(CLOCK_PROCESS_CPUTIME_ID);
    benchmarkCaseStart(&benchmark);
    if (! benchmarkSubmitWorkerMessage(&benchmark,
                                       (WorkerMessageCallback) benchmarkRecursiveCallback,
                                       benchmarkRecursiveCleanup,
                                       &recursive,
                                       NULL,
                                       NULL,
                                       false,
                                       0))
    {
        benchmarkFail("initial recursive submission was refused");
    }
    benchmarkWaitFor(&benchmark.complete, "recursive callbacks");
    const uint64_t cpu_ns = benchmarkClockNS(CLOCK_PROCESS_CPUTIME_ID) - cpu_start;
    if (recursive.count != messages)
    {
        benchmarkFail("recursive workload did not execute its requested callback count");
    }
    benchmarkPrintCase("recursive forced queue / ownership", &benchmark, cpu_ns);
}

static void benchmarkPollerProbeRead(wio_t *io, sbuf_t *buf)
{
    benchmark_poller_probe_t *probe = weventGetUserdata(io);
    if (probe == NULL || sbufGetLength(buf) != sizeof(benchmark_poller_packet_t))
    {
        if (probe != NULL)
        {
            atomic_fetch_add_explicit(&probe->malformed, 1, memory_order_relaxed);
        }
        bufferpoolReuseBuffer(io->loop->bufpool, buf);
        return;
    }

    benchmark_poller_packet_t packet;
    memoryCopy(&packet, sbufGetRawPtr(buf), sizeof(packet));
    const uint64_t now_ns = benchmarkClockNS(CLOCK_MONOTONIC);
    if (probe->count < probe->capacity)
    {
        probe->latencies[probe->count++] = now_ns > packet.scheduled_ns ? now_ns - packet.scheduled_ns : 0;
    }
    atomic_fetch_add_explicit(&probe->received, 1, memory_order_relaxed);
    bufferpoolReuseBuffer(io->loop->bufpool, buf);
}

static void benchmarkPollerProbeClosed(wio_t *io)
{
    benchmark_poller_probe_t *probe = weventGetUserdata(io);
    if (probe != NULL)
    {
        atomic_store_explicit(&probe->reader_closed, true, memory_order_release);
    }
}

static void benchmarkPollerProbeSetupOnTarget(worker_t *worker, void *arg1, void *arg2, void *arg3)
{
    benchmark_poller_probe_t *probe = arg1;
    discard                   arg2;
    discard                   arg3;

    if (worker->wid != kTargetWID)
    {
        benchmarkFail("poller probe setup ran on the wrong worker");
    }
    probe->read_io = wioGet(worker->loop, probe->read_fd);
    if (probe->read_io == NULL)
    {
        benchmarkFail("failed to create poller probe watcher");
    }
    weventSetUserData(probe->read_io, probe);
    wioSetCallBackRead(probe->read_io, benchmarkPollerProbeRead);
    wioSetCallBackClose(probe->read_io, benchmarkPollerProbeClosed);
    if (wioRead(probe->read_io) != 0)
    {
        benchmarkFail("failed to arm poller probe watcher");
    }
    atomic_store_explicit(&probe->reader_ready, true, memory_order_release);
}

static WTHREAD_ROUTINE(benchmarkPollerProbePacerMain)
{
    benchmark_poller_probe_t *probe = userdata;
    if (! benchmarkAffinityPinCurrentThreadToCpu(probe->affinity == NULL ? -1 : probe->affinity->pacing_cpu) &&
        probe->affinity != NULL && probe->affinity->active)
    {
        atomic_store_explicit(&probe->affinity->runtime_pin_failed, true, memory_order_release);
    }
    atomic_store_explicit(&probe->pacing_ready, true, memory_order_release);

    while (! atomic_load_explicit(&probe->start, memory_order_acquire))
    {
        YIELD_CPU();
    }

    const uint64_t interval_ns = (uint64_t) kPollerProbeIntervalUs * 1000U;
    uint64_t       deadline_ns = probe->start_ns + interval_ns;
    const uint64_t end_ns      = probe->start_ns + probe->duration_ns;
    uint64_t       sequence    = 0;
    while (! atomic_load_explicit(&probe->stop, memory_order_acquire) && deadline_ns <= end_ns)
    {
#if defined(__linux__)
        const struct timespec deadline = {
            .tv_sec  = (time_t) (deadline_ns / UINT64_C(1000000000)),
            .tv_nsec = (long) (deadline_ns % UINT64_C(1000000000)),
        };
        discard clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &deadline, NULL);
#else
        const uint64_t now_ns = benchmarkClockNS(CLOCK_MONOTONIC);
        if (deadline_ns > now_ns)
        {
            wwSleepMS((uint32_t) ((deadline_ns - now_ns + 999999U) / 1000000U));
        }
#endif
        if (atomic_load_explicit(&probe->stop, memory_order_acquire))
        {
            break;
        }

        benchmark_poller_packet_t packet = {.sequence = sequence++, .scheduled_ns = deadline_ns};
        atomic_fetch_add_explicit(&probe->attempted, 1, memory_order_relaxed);
        if (send(probe->write_fd, &packet, sizeof(packet), MSG_DONTWAIT) == (ssize_t) sizeof(packet))
        {
            atomic_fetch_add_explicit(&probe->sent, 1, memory_order_relaxed);
        }
        deadline_ns += interval_ns;
    }
    atomic_store_explicit(&probe->pacing_done, true, memory_order_release);
    return 0;
}

static void benchmarkPollerProbeSetup(benchmark_poller_probe_t *probe, benchmark_affinity_t *affinity,
                                      uint32_t duration_ms)
{
    memoryZero(probe, sizeof(*probe));
    probe->affinity    = affinity;
    probe->read_fd     = -1;
    probe->write_fd    = -1;
    probe->duration_ns = (uint64_t) duration_ms * 1000000U;
    probe->capacity =
        max((size_t) kMinimumPollerSampleCapacity, (size_t) duration_ms * 4U + kMinimumPollerSampleCapacity);
    probe->latencies = calloc(probe->capacity, sizeof(*probe->latencies));
    if (probe->latencies == NULL)
    {
        benchmarkFail("poller probe latency allocation failed");
    }
    atomic_init(&probe->reader_ready, false);
    atomic_init(&probe->reader_closed, false);
    atomic_init(&probe->pacing_ready, false);
    atomic_init(&probe->start, false);
    atomic_init(&probe->stop, false);
    atomic_init(&probe->pacing_done, false);
    atomic_init(&probe->attempted, 0);
    atomic_init(&probe->sent, 0);
    atomic_init(&probe->received, 0);
    atomic_init(&probe->malformed, 0);

#if defined(__linux__)
    int sockets[2];
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sockets) != 0 || nonBlocking(sockets[1]) != 0)
    {
        benchmarkFail("failed to create nonblocking poller probe socketpair");
    }
    probe->read_fd  = sockets[0];
    probe->write_fd = sockets[1];
#else
    benchmarkFail("poller fairness probe is currently supported on Linux only");
#endif

    if (sendWorkerMessageForceQueueWithCleanup(
            kTargetWID, (WorkerMessageCallback) benchmarkPollerProbeSetupOnTarget, NULL, probe, NULL, NULL) !=
        kWorkerMessageSubmitAccepted)
    {
        benchmarkFail("poller probe setup submission was refused");
    }
    benchmarkWaitForFlag(&probe->reader_ready, "poller probe watcher setup");
    if (threadCreate(&probe->pacing_thread, benchmarkPollerProbePacerMain, probe) != kWThreadErrorNone)
    {
        benchmarkFail("poller probe pacing thread creation failed");
    }
    benchmarkWaitForFlag(&probe->pacing_ready, "poller probe pacing thread");
}

static void benchmarkPollerProbeStart(benchmark_poller_probe_t *probe, uint64_t start_ns)
{
    probe->start_ns = start_ns;
    atomic_store_explicit(&probe->start, true, memory_order_release);
}

static void benchmarkPollerProbeStop(benchmark_poller_probe_t *probe)
{
    atomic_store_explicit(&probe->stop, true, memory_order_release);
    if (threadJoin(probe->pacing_thread) != 0)
    {
        benchmarkFail("poller probe pacing thread join failed");
    }

    const uint64_t sent = atomic_load_explicit(&probe->sent, memory_order_acquire);
    for (uint32_t waited = 0; waited < 50 && atomic_load_explicit(&probe->received, memory_order_acquire) < sent;
         ++waited)
    {
        wwSleepMS(1);
    }
    if (probe->write_fd >= 0)
    {
        closesocket(probe->write_fd);
        probe->write_fd = -1;
    }
    if (wioCloseAsync(probe->read_io) != 0)
    {
        benchmarkFail("poller probe watcher close was refused");
    }
    benchmarkWaitForFlag(&probe->reader_closed, "poller probe watcher close");
}

static void benchmarkPollerProbeDestroy(benchmark_poller_probe_t *probe)
{
    free(probe->latencies);
    probe->latencies = NULL;
}

static void benchmarkPrintPollerProbe(const char *name, benchmark_case_t *benchmark, benchmark_poller_probe_t *probe,
                                      uint64_t cpu_ns)
{
    benchmarkPrintCase(name, benchmark, cpu_ns);
    if (probe->count == 0)
    {
        benchmarkFail("poller fairness workload did not receive a socket-read callback");
    }

    qsort(probe->latencies, probe->count, sizeof(*probe->latencies), benchmarkCompareU64);
    const uint64_t attempted = atomic_load_explicit(&probe->attempted, memory_order_acquire);
    const uint64_t sent      = atomic_load_explicit(&probe->sent, memory_order_acquire);
    const uint64_t received  = atomic_load_explicit(&probe->received, memory_order_acquire);
    const uint64_t missed    = attempted > received ? attempted - received : 0;
    printf("  poller socket schedule-to-callback: expected=%" PRIu64 " sent=%" PRIu64 " received=%" PRIu64
           " missed/coalesced=%" PRIu64 " malformed=%" PRIu64
           " samples=%zu p50=%8.1fus p95=%8.1fus p99=%8.1fus max=%8.1fus %s\n",
           attempted,
           sent,
           received,
           missed,
           atomic_load_explicit(&probe->malformed, memory_order_acquire),
           probe->count,
           (double) probe->latencies[(probe->count * 50U) / 100U] / 1000.0,
           (double) probe->latencies[(probe->count * 95U) / 100U] / 1000.0,
           (double) probe->latencies[(probe->count * 99U) / 100U] / 1000.0,
           (double) probe->latencies[probe->count - 1] / 1000.0,
           probe->affinity != NULL && probe->affinity->isolated &&
                   ! atomic_load_explicit(&probe->affinity->runtime_pin_failed, memory_order_acquire)
               ? "isolated"
               : "observational/excluded-from-selection");
}

typedef struct benchmark_poller_busy_s
{
    atomic_bool complete;
} benchmark_poller_busy_t;

static void benchmarkPollerBusyWorker(worker_t *worker, void *arg1, void *arg2, void *arg3)
{
    benchmark_poller_busy_t *busy = arg1;
    discard                  arg2;
    discard                  arg3;

    if (worker->wid != kTargetWID)
    {
        benchmarkFail("poller occupancy callback ran on the wrong worker");
    }
    const uint64_t deadline = benchmarkClockNS(CLOCK_MONOTONIC) + (uint64_t) kPollerProbeBlockMs * 1000000U;
    while (benchmarkClockNS(CLOCK_MONOTONIC) < deadline)
    {
        YIELD_CPU();
    }
    atomic_store_explicit(&busy->complete, true, memory_order_release);
}

static void benchmarkRunPollerForeign(const char *name, uint32_t producers, uint32_t duration_ms,
                                      benchmark_affinity_t *affinity, bool inject_occupancy_block)
{
    benchmark_case_t         benchmark;
    benchmark_poller_probe_t probe;
    benchmark_poller_busy_t  busy;
    benchmark_producer_t    *producer = NULL;
    atomic_bool              start;
    atomic_bool              failed;
    atomic_uint              ready;

    benchmarkCaseInit(&benchmark);
    benchmarkPollerProbeSetup(&probe, affinity, duration_ms);
    benchmarkResetDiagnostics();
    atomic_init(&start, false);
    atomic_init(&failed, false);
    atomic_init(&ready, 0);
    atomic_init(&busy.complete, false);

    if (producers != 0)
    {
        producer = calloc(producers, sizeof(*producer));
        if (producer == NULL)
        {
            benchmarkFail("sustained producer allocation failed");
        }
        for (uint32_t i = 0; i < producers; ++i)
        {
            producer[i] = (benchmark_producer_t) {
                .benchmark = &benchmark,
                .workload  = kBenchmarkWorkloadOwnership,
                .sustained = true,
                .start     = &start,
                .ready     = &ready,
                .failed    = &failed,
                .affinity  = affinity,
            };
            if (threadCreate(&producer[i].thread, benchmarkProducerMain, &producer[i]) != kWThreadErrorNone)
            {
                benchmarkFail("sustained producer thread creation failed");
            }
        }
        while (atomic_load_explicit(&ready, memory_order_acquire) != producers)
        {
            YIELD_CPU();
        }
    }

    const uint64_t cpu_start = benchmarkClockNS(CLOCK_PROCESS_CPUTIME_ID);
    benchmarkCaseStart(&benchmark);
    benchmark.producer_start_ns = benchmark.start_ns;
    const uint64_t deadline_ns  = benchmark.start_ns + (uint64_t) duration_ms * 1000000U;
    for (uint32_t i = 0; i < producers; ++i)
    {
        producer[i].deadline_ns = deadline_ns;
    }
    benchmarkPollerProbeStart(&probe, benchmark.start_ns);
    atomic_store_explicit(&start, true, memory_order_release);

    if (inject_occupancy_block)
    {
        wwSleepMS(5);
        if (sendWorkerMessageForceQueueWithCleanup(
                kTargetWID, (WorkerMessageCallback) benchmarkPollerBusyWorker, NULL, &busy, NULL, NULL) !=
            kWorkerMessageSubmitAccepted)
        {
            benchmarkFail("poller occupancy callback submission was refused");
        }
    }

    for (uint32_t i = 0; i < producers; ++i)
    {
        if (threadJoin(producer[i].thread) != 0)
        {
            benchmarkFail("sustained producer thread join failed");
        }
    }
    if (producers == 0)
    {
        benchmarkWaitForFlag(&probe.pacing_done, "poller no-load pacing");
    }
    if (inject_occupancy_block)
    {
        benchmarkWaitForFlag(&busy.complete, "poller occupancy callback");
    }
    benchmark.producer_end_ns = benchmarkClockNS(CLOCK_MONOTONIC);
    if (atomic_load_explicit(&failed, memory_order_acquire))
    {
        benchmarkFail("sustained foreign producer submission was refused");
    }
    benchmarkCaseFinishSubmissions(&benchmark);
    benchmarkWaitFor(&benchmark.complete, "sustained foreign mailbox drain");
    benchmarkPollerProbeStop(&probe);
    const uint64_t cpu_ns = benchmarkClockNS(CLOCK_PROCESS_CPUTIME_ID) - cpu_start;
    benchmarkPrintPollerProbe(name, &benchmark, &probe, cpu_ns);
    benchmarkPollerProbeDestroy(&probe);
    free(producer);
}

static void benchmarkRecursiveFairnessCallback(worker_t *worker, void *arg1, void *arg2, void *arg3)
{
    benchmark_recursive_fairness_t *recursive = arg1;
    discard                         arg2;
    discard                         arg3;

    if (worker->wid != kTargetWID)
    {
        benchmarkFail("recursive fairness callback ran on the wrong worker");
    }
    if (benchmarkClockNS(CLOCK_MONOTONIC) < recursive->deadline_ns)
    {
        if (! benchmarkSubmitWorkerMessage(recursive->benchmark,
                                           (WorkerMessageCallback) benchmarkRecursiveFairnessCallback,
                                           NULL,
                                           recursive,
                                           NULL,
                                           NULL,
                                           false,
                                           0))
        {
            benchmarkFail("recursive fairness successor was refused");
        }
    }
    else
    {
        benchmarkCaseFinishSubmissions(recursive->benchmark);
    }
    benchmarkCaseSettle(recursive->benchmark, true);
}

static void benchmarkRecursiveFairnessCleanup(void *arg1, void *arg2, void *arg3, worker_message_cancel_reason_e reason)
{
    benchmark_recursive_fairness_t *recursive = arg1;
    discard                         arg2;
    discard                         arg3;
    discard                         reason;

    benchmarkCaseSettle(recursive->benchmark, false);
}

static void benchmarkRunPollerRecursive(uint32_t duration_ms, benchmark_affinity_t *affinity)
{
    benchmark_case_t               benchmark;
    benchmark_poller_probe_t       probe;
    benchmark_recursive_fairness_t recursive;
    benchmarkCaseInit(&benchmark);
    benchmarkPollerProbeSetup(&probe, affinity, duration_ms);
    benchmarkResetDiagnostics();

    recursive.benchmark      = &benchmark;
    const uint64_t cpu_start = benchmarkClockNS(CLOCK_PROCESS_CPUTIME_ID);
    benchmarkCaseStart(&benchmark);
    recursive.deadline_ns = benchmark.start_ns + (uint64_t) duration_ms * 1000000U;
    benchmarkPollerProbeStart(&probe, benchmark.start_ns);
    if (! benchmarkSubmitWorkerMessage(&benchmark,
                                       (WorkerMessageCallback) benchmarkRecursiveFairnessCallback,
                                       benchmarkRecursiveFairnessCleanup,
                                       &recursive,
                                       NULL,
                                       NULL,
                                       false,
                                       0))
    {
        benchmarkFail("initial recursive fairness submission was refused");
    }
    benchmarkWaitFor(&benchmark.complete, "sustained recursive mailbox drain");
    benchmarkPollerProbeStop(&probe);
    const uint64_t cpu_ns = benchmarkClockNS(CLOCK_PROCESS_CPUTIME_ID) - cpu_start;
    benchmarkPrintPollerProbe("poller recursive forced queue", &benchmark, &probe, cpu_ns);
    benchmarkPollerProbeDestroy(&probe);
}

static void benchmarkCancellationControlEvent(wevent_t *event)
{
    benchmark_cancellation_control_t *control = weventGetUserdata(event);
    const wid_t                       wid     = (wid_t) wloopGetWid(weventGetLoop(event));
    if (wid != kTargetWID)
    {
        benchmarkFail("cancellation control event ran on the wrong worker");
    }
    workerMessagesCleanupPending(getWorker(wid));
    atomic_store_explicit(&control->complete, true, memory_order_release);
}

static void benchmarkRunCancellation(uint64_t messages)
{
    benchmark_case_t                 benchmark;
    benchmark_cancellation_control_t control;
    benchmarkCaseInit(&benchmark);
    atomic_init(&control.complete, false);
    benchmarkResetDiagnostics();

    const uint64_t cpu_start = benchmarkClockNS(CLOCK_PROCESS_CPUTIME_ID);
    benchmarkCaseStart(&benchmark);
    for (uint64_t i = 0; i < messages; ++i)
    {
        if (! benchmarkSubmitOwnership(&benchmark, true, kLongDelayMs))
        {
            benchmarkFail("admission-close cancellation submission was refused");
        }
    }
    benchmarkCaseFinishSubmissions(&benchmark);
    workerMessagesCloseAdmission(getWorker(kTargetWID));

    wevent_t event;
    memoryZero(&event, sizeof(event));
    event.cb       = benchmarkCancellationControlEvent;
    event.userdata = &control;
    if (! wloopPostControlEvent(getWorkerLoop(kTargetWID), &event))
    {
        benchmarkFail("cancellation control event was refused");
    }
    benchmarkWaitFor(&control.complete, "admission-close cancellation control event");
    benchmarkWaitFor(&benchmark.complete, "admission-close cancellation settlement");
    const uint64_t cpu_ns = benchmarkClockNS(CLOCK_PROCESS_CPUTIME_ID) - cpu_start;
    benchmarkPrintCase("admission close / cancellation", &benchmark, cpu_ns);
}

static void benchmarkInitializeRuntime(benchmark_affinity_t *affinity)
{
    static char            log_off[]         = "OFF";
    ww_construction_data_t init_data         = {0};
    init_data.workers_count                  = 2;
    init_data.ram_profile                    = 4;
    init_data.mtu_size                       = 1500;
    init_data.internal_logger_data.log_level = log_off;
    init_data.core_logger_data.log_level     = log_off;
    init_data.network_logger_data.log_level  = log_off;
    init_data.dns_logger_data.log_level      = log_off;

    if (! wwStartupSucceeded(createGlobalState(init_data)))
    {
        benchmarkFail("failed to create the benchmark worker runtime");
    }
    if (! workerWaitForPhase(getWorker(kTargetWID), kWorkerLifecycleRunning, 5000))
    {
        benchmarkFail("target worker did not enter its runtime phase");
    }
    atomic_store_explicit(&GSTATE.workers_run_flag, true, memory_order_release);
    benchmarkApplyTargetAffinity(affinity);
}

static void benchmarkDestroyRuntime(void)
{
    if (! workerExitJoin(getWorker(kTargetWID)))
    {
        benchmarkFail("failed to stop target worker");
    }

    worker_t *worker0 = getWorker(0);
    if (! atomic_load_explicit(&worker0->resources_destroyed, memory_order_relaxed))
    {
        if (workerInstallApplicationQuiesceRequest(worker0, benchmarkShutdownContext()) ==
            kWorkerQuiesceRequestUnavailable)
        {
            benchmarkFail("failed to install main-worker benchmark shutdown request");
        }
        workerPerformQuiesce(worker0, benchmarkShutdownContext());
        if (! workerRequestDrain(worker0))
        {
            benchmarkFail("failed to request main-worker benchmark drain");
        }
        workerPerformDrain(worker0, benchmarkShutdownContext());
        if (! workerRequestTeardown(worker0))
        {
            benchmarkFail("failed to request main-worker benchmark teardown");
        }
        workerPerformTeardown(worker0);
    }
    workerDestroyPseudoWorkerResources(getWorker(getTotalWorkersCount() - 1));
    destroyGlobalState();
}

static bool benchmarkParsePositiveU64(const char *text, uint64_t *value)
{
    char *end = NULL;
    *value    = strtoull(text, &end, 10);
    return *value != 0 && end != text && *end == '\0';
}

static bool benchmarkParsePositiveU32(const char *text, uint32_t *value)
{
    uint64_t parsed;
    if (! benchmarkParsePositiveU64(text, &parsed) || parsed > UINT32_MAX)
    {
        return false;
    }
    *value = (uint32_t) parsed;
    return true;
}

static bool benchmarkParseCaseName(const char *name, size_t length, uint32_t *cases)
{
#define BENCHMARK_CASE_NAME(value, flag)                                                                               \
    if (length == sizeof(value) - 1U && memoryCompare(name, value, sizeof(value) - 1U) == 0)                           \
    {                                                                                                                  \
        *cases |= flag;                                                                                                \
        return true;                                                                                                   \
    }
    BENCHMARK_CASE_NAME("warmup", kBenchmarkCaseWarmup)
    BENCHMARK_CASE_NAME("inline", kBenchmarkCaseInline)
    BENCHMARK_CASE_NAME("forced", kBenchmarkCaseForced)
    BENCHMARK_CASE_NAME("burst", kBenchmarkCaseBurst)
    BENCHMARK_CASE_NAME("preloaded", kBenchmarkCasePreloaded)
    BENCHMARK_CASE_NAME("paced", kBenchmarkCasePaced)
    BENCHMARK_CASE_NAME("recursive", kBenchmarkCaseRecursive)
    BENCHMARK_CASE_NAME("fairness", kBenchmarkCaseFairness)
    BENCHMARK_CASE_NAME("delayed", kBenchmarkCaseDelayed)
    BENCHMARK_CASE_NAME("cancellation", kBenchmarkCaseCancellation)
#undef BENCHMARK_CASE_NAME
    return false;
}

static bool benchmarkParseCases(const char *text, uint32_t *cases)
{
    if (text == NULL || text[0] == '\0')
    {
        return false;
    }
    if (stringCompare(text, "all") == 0)
    {
        *cases = kBenchmarkCaseAll;
        return true;
    }

    *cases            = 0;
    const char *token = text;
    for (const char *cursor = text;; ++cursor)
    {
        if (*cursor != ',' && *cursor != '\0')
        {
            continue;
        }
        if (cursor == token || ! benchmarkParseCaseName(token, (size_t) (cursor - token), cases))
        {
            return false;
        }
        if (*cursor == '\0')
        {
            return true;
        }
        token = cursor + 1;
    }
}

static benchmark_options_t benchmarkParseOptions(int argc, char **argv)
{
    benchmark_options_t options = {
        .messages             = kDefaultMessages,
        .fairness_duration_ms = kDefaultFairnessDurationMs,
        .cases                = kBenchmarkCaseAll,
        .affinity_requested   = true,
    };
    bool positional_messages = false;

    for (int i = 1; i < argc; ++i)
    {
        if (strcmp(argv[i], "--duration-ms") == 0)
        {
            if (++i == argc || ! benchmarkParsePositiveU32(argv[i], &options.fairness_duration_ms))
            {
                fprintf(stderr, "--duration-ms must be a positive uint32 value\n");
                exit(2);
            }
            continue;
        }
        if (strcmp(argv[i], "--cases") == 0)
        {
            if (++i == argc || ! benchmarkParseCases(argv[i], &options.cases))
            {
                fprintf(stderr,
                        "--cases must be a comma-separated subset of "
                        "warmup,inline,forced,burst,preloaded,paced,recursive,fairness,delayed,cancellation,all\n");
                exit(2);
            }
            continue;
        }
        if (strcmp(argv[i], "--affinity") == 0)
        {
            if (++i == argc || (strcmp(argv[i], "auto") != 0 && strcmp(argv[i], "off") != 0))
            {
                fprintf(stderr, "--affinity must be auto or off\n");
                exit(2);
            }
            options.affinity_requested = stringCompare(argv[i], "auto") == 0;
            continue;
        }
        if (positional_messages || ! benchmarkParsePositiveU64(argv[i], &options.messages))
        {
            fprintf(stderr, "usage: %s [messages] [--duration-ms N] [--cases LIST] [--affinity auto|off]\n", argv[0]);
            exit(2);
        }
        positional_messages = true;
    }
    return options;
}

int main(int argc, char **argv)
{
    const benchmark_options_t options          = benchmarkParseOptions(argc, argv);
    const uint64_t            messages         = options.messages;
    const uint64_t            paced_messages   = min(messages, (uint64_t) kPacedMessagesCeiling);
    const uint64_t            delayed_messages = min(messages, (uint64_t) kDelayedMessagesCeiling);
    benchmark_affinity_t      affinity;
    benchmarkAffinityInitialize(&affinity, options.affinity_requested);

    printf("worker_message_benchmark: mutex mailbox, drain-batch=%d, messages=%" PRIu64 ", sustained-duration=%ums\n",
           kWorkerMessageDrainBatchSize,
           messages,
           options.fairness_duration_ms);
    printf("worker_message_benchmark: compiler=%s build=%s source=%s%s cases=0x%03x\n",
           WW_WORKER_MESSAGE_BENCHMARK_COMPILER,
           WW_WORKER_MESSAGE_BENCHMARK_BUILD_TYPE,
           WW_WORKER_MESSAGE_BENCHMARK_SOURCE_COMMIT,
           WW_WORKER_MESSAGE_BENCHMARK_SOURCE_DIRTY ? "-dirty" : "",
           options.cases);
    printf("worker_message_benchmark: selection rule: smallest batch within 5%% of the seven-workload aggregate "
           "(foreign burst 1+4, line-task, preloaded, sustained foreign 1+4, direct-pair SpeedTest) with isolated "
           "poller p99 <= 2000us and max <= 20000us\n");
#ifdef WW_WORKER_MESSAGE_BENCHMARK_INSTRUMENTATION
    printf("worker_message_benchmark: benchmark instrumentation ENABLED\n");
#else
    printf("worker_message_benchmark: benchmark instrumentation disabled "
           "(configure -DWW_WORKER_MESSAGE_BENCHMARK_INSTRUMENTATION=ON for mailbox counters)\n");
#endif

    benchmarkInitializeRuntime(&affinity);
    benchmarkPrintAffinity(&affinity);

    /* Warm the real worker loop, deque capacity, wake transport, and shared
     * master pool before comparing fixed workloads. */
    if ((options.cases & kBenchmarkCaseWarmup) != 0)
    {
        benchmarkRunBurst("warmup / ownership",
                          1,
                          min(messages, (uint64_t) kWarmupMessages),
                          kBenchmarkWorkloadOwnership,
                          false,
                          0,
                          &affinity);
    }

    if ((options.cases & kBenchmarkCaseInline) != 0)
    {
        benchmark_case_t inline_benchmark;
        benchmarkCaseInit(&inline_benchmark);
        benchmark_driver_t inline_driver = {
            .benchmark = &inline_benchmark,
            .messages  = messages,
        };
        benchmarkRunDriverCase("same worker / admitted inline", &inline_driver);
    }

    if ((options.cases & kBenchmarkCaseForced) != 0)
    {
        benchmark_case_t forced_benchmark;
        benchmarkCaseInit(&forced_benchmark);
        benchmark_driver_t forced_driver = {
            .benchmark   = &forced_benchmark,
            .messages    = messages,
            .force_queue = true,
        };
        benchmarkRunDriverCase("same worker / forced queue", &forced_driver);
    }

    if ((options.cases & kBenchmarkCaseBurst) != 0)
    {
        benchmarkRunBurst("foreign burst / no-op callback", 1, messages, kBenchmarkWorkloadNoop, false, 0, &affinity);
        for (uint32_t producers = 1; producers <= 8; producers *= 2)
        {
            char name[64];
            snprintf(name, sizeof(name), "foreign burst / %u producers", producers);
            benchmarkRunBurst(name, producers, messages, kBenchmarkWorkloadOwnership, false, 0, &affinity);
        }
        benchmarkRunBurst(
            "foreign burst / line-task shape", 1, messages, kBenchmarkWorkloadLineTask, false, 0, &affinity);
    }
    if ((options.cases & kBenchmarkCasePreloaded) != 0)
    {
        benchmarkRunPreloaded(messages);
    }
    if ((options.cases & kBenchmarkCasePaced) != 0)
    {
        benchmarkRunPaced(paced_messages);
    }
    if ((options.cases & kBenchmarkCaseRecursive) != 0)
    {
        benchmarkRunRecursive(messages);
    }
    if ((options.cases & kBenchmarkCaseFairness) != 0)
    {
        benchmarkRunPollerForeign("poller socket / no load", 0, options.fairness_duration_ms, &affinity, false);
        benchmarkRunPollerForeign("poller socket / occupied target", 0, options.fairness_duration_ms, &affinity, true);
        benchmarkRunPollerForeign(
            "poller socket / sustained foreign 1 producer", 1, options.fairness_duration_ms, &affinity, false);
        benchmarkRunPollerForeign(
            "poller socket / sustained foreign 4 producers", 4, options.fairness_duration_ms, &affinity, false);
        benchmarkRunPollerRecursive(options.fairness_duration_ms, &affinity);
    }

    if ((options.cases & kBenchmarkCaseDelayed) != 0)
    {
        benchmarkRunBurst("delay=0 / forced next turn", 1, messages, kBenchmarkWorkloadOwnership, true, 0, &affinity);

        benchmark_case_t owner_delayed;
        benchmarkCaseInit(&owner_delayed);
        benchmark_driver_t owner_driver = {
            .benchmark = &owner_delayed,
            .messages  = delayed_messages,
            .delay_ms  = 1,
            .timed     = true,
        };
        benchmarkRunDriverCase("positive delay / owner setup", &owner_driver);
        benchmarkRunBurst(
            "positive delay / foreign setup", 1, delayed_messages, kBenchmarkWorkloadOwnership, true, 1, &affinity);
        benchmarkRunBurst(
            "many outstanding delayed", 1, delayed_messages, kBenchmarkWorkloadOwnership, true, 20, &affinity);
    }

    /* Closing admission is deliberately last: it demonstrates exact
     * cancellation settlement and leaves the target unavailable afterward. */
    if ((options.cases & kBenchmarkCaseCancellation) != 0)
    {
        benchmarkRunCancellation(delayed_messages);
    }
    benchmarkDestroyRuntime();
    return 0;
}

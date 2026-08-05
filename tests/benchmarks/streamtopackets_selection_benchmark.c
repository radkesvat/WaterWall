/*
 * Diagnostic benchmark for StreamToPackets return-line selection.
 *
 * Selection scans the active pool under the registry read lock and picks the
 * rendezvous winner, which is O(active_lines) per return packet. The expected
 * pool is small, so the linear scan is the clearest correct implementation; this
 * target exists so that assumption can be re-checked with numbers before anyone
 * replaces the list with a reference-counted snapshot.
 *
 * It measures the whole published entry point - read lock, registry traversal,
 * every membership filter, the rendezvous scoring and the reference the winner
 * is handed back with - because those are what a return packet actually pays.
 * The second half puts several threads on that path at once while a writer
 * repeatedly takes ownership, which is the case where a shared/exclusive lock
 * can starve someone.
 *
 * It is deliberately excluded from normal builds and from CTest: wall-clock
 * results are machine-specific and are not a correctness threshold.
 *
 * Build and run from the repository root:
 *
 *   cmake --build --preset linux --target streamtopackets_selection_benchmark
 *   ./build/linux/tests/benchmarks/Release/streamtopackets_selection_benchmark [iterations]
 */

#include "StreamToPackets/structure.h"

#include "wthread.h"

enum
{
    kDefaultIterations  = 2000000,
    kMaxPoolSize        = 64,
    kContentionReaders  = 4,
    kContentionPoolSize = 8
};

static const uint32_t kPoolSizes[] = {1, 4, 16, 64};

static uint64_t nowNanoseconds(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ((uint64_t) ts.tv_sec * UINT64_C(1000000000)) + (uint64_t) ts.tv_nsec;
}

static void requireOrExit(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "FAIL: %s\n", message);
        exit(1);
    }
}

// ---------------------------------------------------------------------------
// a real registry
// ---------------------------------------------------------------------------
//
// Nothing here needs a published worker table: the ownership module only reads
// line state, line WIDs and source address contexts, so a bare line allocation
// is enough to build the same registry a running instance would have.

typedef struct selection_fixture_s
{
    tunnel_t *tunnel;
    line_t   *lines[kMaxPoolSize];
    uint32_t  count;
} selection_fixture_t;

static line_t *benchmarkLineCreate(uint32_t lstate_size, const char *source_ip)
{
    line_t *l = memoryAllocateCacheAlignedZero(sizeof(line_t) + lstate_size);

    requireOrExit(l != NULL, "failed to allocate a benchmark line");
    atomic_init(&l->refc, 1);
    l->alive = true;
    l->wid   = 0;
    requireOrExit(addresscontextSetIpAddress(lineGetSourceAddressContext(l), source_ip),
                  "failed to set a benchmark source IP");
    return l;
}

static void fixtureSetup(selection_fixture_t *fixture, uint32_t count, const char *source_ip)
{
    requireOrExit(count <= kMaxPoolSize, "benchmark pool size is out of range");

    memoryZero(fixture, sizeof(*fixture));
    fixture->tunnel = tunnelCreate(NULL, sizeof(streamtopackets_tstate_t), sizeof(streamtopackets_lstate_t));
    requireOrExit(fixture->tunnel != NULL, "failed to create the benchmark tunnel");
    fixture->count = count;

    streamtopacketsOwnershipInitialize(tunnelGetState(fixture->tunnel));

    for (uint32_t i = 0; i < count; ++i)
    {
        fixture->lines[i] = benchmarkLineCreate(fixture->tunnel->lstate_size, source_ip);
        requireOrExit(streamtopacketsRegisterCandidateLine(fixture->tunnel, fixture->lines[i]),
                      "failed to register a benchmark line");
        requireOrExit(streamtopacketsAuthorizeLine(fixture->tunnel, fixture->lines[i]) != 0,
                      "failed to activate a benchmark line");
    }
}

static void fixtureTeardown(selection_fixture_t *fixture)
{
    for (uint32_t i = 0; i < fixture->count; ++i)
    {
        streamtopacketsUnregisterLine(fixture->tunnel, fixture->lines[i]);
        memoryFreeAligned(fixture->lines[i]);
    }

    streamtopacketsOwnershipDestroy(fixture->tunnel);
    tunnelDestroy(fixture->tunnel);
}

// ---------------------------------------------------------------------------
// single-threaded cost per pool size
// ---------------------------------------------------------------------------

static void benchmarkPoolSizes(uint64_t iterations)
{
    printf("Uncontended selection, %llu iterations per pool size\n", (unsigned long long) iterations);

    for (uint32_t p = 0; p < sizeof(kPoolSizes) / sizeof(kPoolSizes[0]); ++p)
    {
        selection_fixture_t fixture;
        fixtureSetup(&fixture, kPoolSizes[p], "10.0.0.1");

        uint64_t       selected = 0;
        const uint64_t started  = nowNanoseconds();

        for (uint64_t i = 0; i < iterations; ++i)
        {
            streamtopackets_selected_line_t out;

            // A fresh flow hash every iteration, so no winner is ever cached.
            if (streamtopacketsSelectReturnLine(fixture.tunnel, i * UINT64_C(0x9E3779B97F4A7C15), &out))
            {
                ++selected;
                lineUnlock(out.line);
            }
        }

        const uint64_t elapsed_ns = nowNanoseconds() - started;

        printf("  pool=%2u  %8.2f ns/selection  (%llu selected)\n",
               (unsigned int) kPoolSizes[p],
               (double) elapsed_ns / (double) iterations,
               (unsigned long long) selected);

        fixtureTeardown(&fixture);
    }
}

// ---------------------------------------------------------------------------
// readers against a writer
// ---------------------------------------------------------------------------
//
// Return traffic takes the registry read lock on every packet; every ownership
// change takes the write lock. A reader-preferring lock can starve the writer
// under sustained traffic and a writer-preferring one can stall every reader, so
// both sides are measured while they run together.
//
// The writer here pauses and resumes one pool line, because that is the write
// lock acquisition with nothing else attached to it. Takeover takes the same
// lock for one extra registry traversal and then posts one close message per
// evicted line after releasing it; measuring that end to end would need a
// published worker table, which this diagnostic deliberately does not build.
// Takeover would also empty the pool on its first round, which would quietly
// turn the reader measurement into a one-line pool.
//
// Read the writer latency as a worst case and nothing more: these readers do
// nothing but select, so they hold the read lock at close to a 100% duty cycle.
// Real return traffic spends far more time per packet outside this lock, so the
// writer waits behind a small fraction of that.

typedef struct contention_state_s
{
    selection_fixture_t *fixture;
    atomic_bool          running;
    atomic_ullong        reader_selections;
} contention_state_t;

static contention_state_t g_contention;

static WTHREAD_ROUTINE(contentionReader)
{
    discard userdata;

    uint64_t local = 0;

    for (uint64_t i = 0; atomicLoadRelaxed(&g_contention.running); ++i)
    {
        streamtopackets_selected_line_t out;

        if (streamtopacketsSelectReturnLine(g_contention.fixture->tunnel, i * UINT64_C(0x9E3779B97F4A7C15), &out))
        {
            ++local;
            lineUnlock(out.line);
        }
    }

    atomicAddU64Explicit(&g_contention.reader_selections, local, memory_order_relaxed);
    return 0;
}

static void benchmarkContention(uint64_t duration_ms)
{
    selection_fixture_t fixture;
    fixtureSetup(&fixture, kContentionPoolSize, "10.0.0.1");

    memoryZero(&g_contention, sizeof(g_contention));
    g_contention.fixture = &fixture;
    atomic_init(&g_contention.running, true);
    atomic_init(&g_contention.reader_selections, 0);

    wthread_t readers[kContentionReaders];
    for (unsigned int i = 0; i < kContentionReaders; ++i)
    {
        requireOrExit(threadCreate(&readers[i], contentionReader, NULL) == kWThreadErrorNone,
                      "failed to start a benchmark reader thread");
    }

    const uint64_t deadline_ns   = nowNanoseconds() + (duration_ms * UINT64_C(1000000));
    uint64_t       acquisitions  = 0;
    uint64_t       max_writer_ns = 0;

    while (nowNanoseconds() < deadline_ns)
    {
        const bool     paused  = (acquisitions & 1U) != 0;
        const uint64_t started = nowNanoseconds();

        streamtopacketsSetLinePaused(fixture.tunnel, fixture.lines[0], paused);

        max_writer_ns = max(max_writer_ns, nowNanoseconds() - started);
        ++acquisitions;
    }

    // Leave the pool unpaused so teardown sees the state it expects.
    streamtopacketsSetLinePaused(fixture.tunnel, fixture.lines[0], false);

    atomicStoreRelaxed(&g_contention.running, false);
    for (unsigned int i = 0; i < kContentionReaders; ++i)
    {
        requireOrExit(safeThreadJoin(readers[i]), "failed to join a benchmark reader thread");
    }

    const uint64_t reader_selections = atomicLoadRelaxed(&g_contention.reader_selections);

    printf("\n%u readers over a %u-line pool against a continuous writer for %llums\n",
           (unsigned int) kContentionReaders,
           (unsigned int) kContentionPoolSize,
           (unsigned long long) duration_ms);
    printf("  reader selections   %llu (%.2f M/s)\n",
           (unsigned long long) reader_selections,
           (double) reader_selections / ((double) duration_ms * 1000.0));
    printf("  writer acquisitions %llu (%.2f k/s)\n",
           (unsigned long long) acquisitions,
           (double) acquisitions / (double) duration_ms);
    printf("  slowest acquisition %.2f us\n", (double) max_writer_ns / 1000.0);

    requireOrExit(acquisitions > 0, "the writer never made progress against sustained readers");
    requireOrExit(reader_selections > 0, "the readers never made progress against a continuous writer");

    fixtureTeardown(&fixture);
}

int main(int argc, char **argv)
{
    uint64_t iterations = kDefaultIterations;

    if (argc > 1)
    {
        const long long parsed = atoll(argv[1]);

        if (parsed > 0)
        {
            iterations = (uint64_t) parsed;
        }
    }

    benchmarkPoolSizes(iterations);
    benchmarkContention(2000);
    return 0;
}

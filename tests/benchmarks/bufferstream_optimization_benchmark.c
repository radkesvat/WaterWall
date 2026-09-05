/* Frozen, non-gating BufferStream benchmark; rebuild to compare C1/C2 or P0/P1. */

#include "wwapi.h"

#include <strings.h>
#include <sys/utsname.h>
#include <unistd.h>

enum
{
    kSamples       = 7,
    kTargetBytes   = 64 * 1024 * 1024,
    kRecordSize    = 4096,
    kPadding       = 64,
    kFragmentWidth = 2048,
    kSmallWidth    = 8,
    kTailSize      = 17,
};

typedef enum workload_e
{
    kExact,
    kIdeal,
    kOverCap,
} workload_t;

typedef struct geometry_s
{
    const char *name;
    uint32_t    large;
    uint32_t    small;
} geometry_t;

typedef struct pool_fixture_s
{
    master_pool_t *large;
    master_pool_t *small;
    buffer_pool_t *pool;
} pool_fixture_t;

typedef struct result_s
{
    uint64_t ns;
    uint64_t bytes;
    uint64_t copied;
    uint64_t digest;
    uint64_t expected_digest;
    uint64_t peak_capacity;
    uint64_t queued_capacity;
    size_t   peak_entries;
    size_t   entries;
    uint32_t returned_capacity;
    bool     equal;
} result_t;

static const geometry_t kGeometry[] = {
    {.name = "low", .large = 4096, .small = 4096},
    {.name = "high", .large = 32768, .small = 4096},
};
static bool failed;

static void fatal(const char *message)
{
    fprintf(stderr, "bufferstream_optimization_benchmark: %s\n", message);
    exit(1);
}

static uint64_t nowNs(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
    {
        fatal("clock_gettime failed");
    }
    return (uint64_t) ts.tv_sec * UINT64_C(1000000000) + (uint64_t) ts.tv_nsec;
}

static uint64_t digestBytes(uint64_t digest, const uint8_t *bytes, size_t length)
{
    for (size_t i = 0; i < length; ++i)
    {
        digest = (digest ^ bytes[i]) * UINT64_C(1099511628211);
    }
    return digest;
}

static void fillBytes(uint8_t *bytes, size_t length, uint32_t seed)
{
    uint32_t value = seed | 1U;
    for (size_t i = 0; i < length; ++i)
    {
        value    = value * UINT32_C(1664525) + UINT32_C(1013904223);
        bytes[i] = (uint8_t) (value >> 24U);
    }
}

static pool_fixture_t makePool(const geometry_t *geometry, uint32_t width)
{
    pool_fixture_t fixture = {
        .large = masterpoolCreateWithCapacity(width),
        .small = masterpoolCreateWithCapacity(width),
    };
    if (fixture.large == NULL || fixture.small == NULL)
    {
        fatal("master-pool allocation failed");
    }
    fixture.pool = bufferpoolCreate(fixture.large, fixture.small, width, geometry->large, geometry->small);
    if (fixture.pool == NULL)
    {
        fatal("buffer-pool allocation failed");
    }
    bufferpoolUpdateAllocationPaddings(fixture.pool, kPadding, kPadding);
    return fixture;
}

static void freePool(pool_fixture_t *fixture)
{
    bufferpoolDestroy(fixture->pool);
    masterpoolMakeEmpty(fixture->large);
    masterpoolMakeEmpty(fixture->small);
    masterpoolDestroy(fixture->large);
    masterpoolDestroy(fixture->small);
}

static sbuf_t *makeBuffer(buffer_pool_t *pool, const uint8_t *bytes, uint32_t length, bool best_fit)
{
    sbuf_t *buffer = best_fit ? bufferpoolGetBestFit(pool, length, kPadding) : bufferpoolGetLargeBuffer(pool);
    if (length > sbufGetMaximumWriteableSize(buffer))
    {
        fatal("frozen input does not fit its selected buffer");
    }
    sbufSetLength(buffer, length);
    memoryCopy(sbufGetMutablePtr(buffer), bytes, length);
    return buffer;
}

static void pushBuffer(buffer_stream_t *stream, sbuf_t *buffer, bool coalescing, result_t *result)
{
    const uint32_t length   = sbufGetLength(buffer);
    const uint32_t capacity = sbufGetTotalCapacity(buffer);
    if (coalescing)
    {
        bufferstreamPushCoalescing(stream, buffer);
    }
    else
    {
        bufferstreamPush(stream, buffer);
    }

    const size_t entries = bs_doublequeue_t_size(&stream->q);
    if (entries == result->entries + 1U)
    {
        result->queued_capacity += capacity;
    }
    else if (entries == result->entries)
    {
        result->copied += length;
    }
    else
    {
        fatal("push changed the deque by an unexpected entry count");
    }
    result->entries       = entries;
    result->peak_entries  = max(result->peak_entries, entries);
    result->peak_capacity = max(result->peak_capacity, result->queued_capacity);
}

static void checkBytes(result_t *result, const void *actual, const void *expected, uint32_t length)
{
    result->equal &= memcmp(actual, expected, length) == 0;
    result->digest          = digestBytes(result->digest, actual, length);
    result->expected_digest = digestBytes(result->expected_digest, expected, length);
}

static void drained(buffer_stream_t *stream, result_t *result)
{
    if (! bufferstreamIsEmpty(stream) || bs_doublequeue_t_size(&stream->q) != 0)
    {
        fatal("workload did not drain its stream");
    }
    result->entries         = 0;
    result->queued_capacity = 0;
}

static result_t runStreamCase(const geometry_t *geometry, workload_t workload, uint32_t parameter, bool coalescing)
{
    const uint32_t  record_size = workload == kOverCap ? parameter : kRecordSize;
    const uint32_t  fragment    = workload == kOverCap ? record_size : parameter;
    const uint64_t  repeats     = (kTargetBytes + record_size - 1U) / record_size;
    pool_fixture_t  fixture     = makePool(geometry, workload == kOverCap ? kSmallWidth : kFragmentWidth);
    buffer_stream_t stream      = bufferstreamCreate(fixture.pool, 0);
    result_t        result      = {
                    .digest          = UINT64_C(1469598103934665603),
                    .expected_digest = UINT64_C(1469598103934665603),
                    .equal           = true,
    };
    uint8_t *record = memoryAllocate(record_size);
    if (record == NULL)
    {
        fatal("record allocation failed");
    }
    fillBytes(record, record_size, record_size ^ fragment);

    const uint64_t start = nowNs();
    for (uint64_t repetition = 0; repetition < repeats; ++repetition)
    {
        for (uint32_t offset = 0; offset < record_size; offset += fragment)
        {
            const uint32_t length = min(fragment, record_size - offset);
            sbuf_t        *input  = makeBuffer(fixture.pool, record + offset, length, workload == kOverCap);
            pushBuffer(&stream, input, coalescing, &result);
        }

        if (workload == kIdeal)
        {
            uint32_t offset = 0;
            while (! bufferstreamIsEmpty(&stream))
            {
                sbuf_t        *output = bufferstreamIdealRead(&stream);
                const uint32_t length = sbufGetLength(output);
                if (length > record_size - offset)
                {
                    fatal("IdealRead crossed a record boundary");
                }
                checkBytes(&result, sbufGetRawPtr(output), record + offset, length);
                offset += length;
                bufferpoolReuseBuffer(fixture.pool, output);
            }
            result.equal &= offset == record_size;
        }
        else
        {
            sbuf_t *output = bufferstreamReadExact(&stream, record_size);
            checkBytes(&result, sbufGetRawPtr(output), record, record_size);
            bufferpoolReuseBuffer(fixture.pool, output);
        }
        result.bytes += record_size;
        drained(&stream, &result);
    }
    result.ns = nowNs() - start;

    memoryFree(record);
    bufferstreamDestroy(&stream);
    freePool(&fixture);
    return result;
}

static int compareDouble(const void *left, const void *right)
{
    const double a = *(const double *) left;
    const double b = *(const double *) right;
    return (a > b) - (a < b);
}

static void report(const char *identity, const result_t samples[kSamples])
{
    double spread[kSamples];
    double sorted[kSamples];
    bool   equal = true;
    for (size_t i = 0; i < kSamples; ++i)
    {
        spread[i] = (double) samples[i].ns / (double) samples[i].bytes;
        sorted[i] = spread[i];
        equal &= samples[i].equal && samples[i].digest == samples[i].expected_digest;
        equal &= samples[i].bytes == samples[0].bytes && samples[i].copied == samples[0].copied &&
                 samples[i].peak_entries == samples[0].peak_entries &&
                 samples[i].peak_capacity == samples[0].peak_capacity &&
                 samples[i].returned_capacity == samples[0].returned_capacity;
    }
    qsort(sorted, kSamples, sizeof(sorted[0]), compareDouble);
    const double median = sorted[kSamples / 2U];
    printf("result %s median_ns_per_byte=%.6f throughput_mib_s=%.3f min_ns_per_byte=%.6f "
           "max_ns_per_byte=%.6f peak_entries=%zu peak_queued_capacity=%" PRIu64 " logical_bytes=%" PRIu64
           " eagerly_copied_bytes=%" PRIu64 " returned_capacity=%u digest=0x%016" PRIx64
           " expected_digest=0x%016" PRIx64 " equality=%s spread_ns_per_byte=[",
           identity,
           median,
           (UINT64_C(1000000000) / median) / (1024.0 * 1024.0),
           sorted[0],
           sorted[kSamples - 1U],
           samples[0].peak_entries,
           samples[0].peak_capacity,
           samples[0].bytes,
           samples[0].copied,
           samples[0].returned_capacity,
           samples[0].digest,
           samples[0].expected_digest,
           equal ? "PASS" : "FAIL");
    for (size_t i = 0; i < kSamples; ++i)
    {
        printf("%s%.6f", i == 0 ? "" : ",", spread[i]);
    }
    puts("]");
    failed |= ! equal;
}

static void runPair(const geometry_t *geometry, workload_t workload, uint32_t parameter)
{
    static const char *const names[] = {"exact", "ideal", "over-cap"};
    result_t                 samples[2][kSamples];
    (void) runStreamCase(geometry, workload, parameter, false);
    (void) runStreamCase(geometry, workload, parameter, true);
    for (size_t sample = 0; sample < kSamples; ++sample)
    {
        const bool first         = sample % 2U != 0;
        samples[first][sample]   = runStreamCase(geometry, workload, parameter, first);
        samples[! first][sample] = runStreamCase(geometry, workload, parameter, ! first);
    }
    char identity[160];
    (void) snprintf(identity,
                    sizeof(identity),
                    "suite=coalescing workload=%s geometry=%s variant=A parameter_bytes=%u",
                    names[workload],
                    geometry->name,
                    parameter);
    report(identity, samples[0]);
    (void) snprintf(identity,
                    sizeof(identity),
                    "suite=coalescing workload=%s geometry=%s variant=C1-or-C2 parameter_bytes=%u",
                    names[workload],
                    geometry->name,
                    parameter);
    report(identity, samples[1]);
}

static sbuf_t *offsetBuffer(buffer_pool_t *pool, const uint8_t *bytes, uint32_t length, uint32_t offset)
{
    sbuf_t *buffer = bufferpoolGetLargeBuffer(pool);
    if (offset + length > sbufGetMaximumWriteableSize(buffer))
    {
        fatal("copy-crossover offset does not fit");
    }
    memoryCopy(sbufGetMutablePtr(buffer) + offset, bytes, length);
    sbufSetLength(buffer, offset + length);
    sbufShiftRight(buffer, offset);
    return buffer;
}

static result_t runCrossoverCase(uint32_t source_size)
{
    static const uint32_t offsets[]    = {0, 1, 15, 31, 32, 63};
    const uint64_t        combinations = ARRAY_SIZE(offsets) * ARRAY_SIZE(offsets);
    const uint64_t        repeats = (kTargetBytes + source_size * combinations - 1U) / (source_size * combinations);
    pool_fixture_t        fixture = makePool(&kGeometry[1], kSmallWidth);
    buffer_stream_t       stream  = bufferstreamCreate(fixture.pool, 0);
    result_t              result  = {
                      .digest          = UINT64_C(1469598103934665603),
                      .expected_digest = UINT64_C(1469598103934665603),
                      .equal           = true,
    };
    uint8_t tail[kTailSize];
    uint8_t source[kRecordSize];
    fillBytes(tail, sizeof(tail), UINT32_C(0x5441494c));
    fillBytes(source, source_size, source_size);

    const uint64_t start = nowNs();
    for (uint64_t repetition = 0; repetition < repeats; ++repetition)
    {
        for (size_t destination_i = 0; destination_i < ARRAY_SIZE(offsets); ++destination_i)
        {
            for (size_t source_i = 0; source_i < ARRAY_SIZE(offsets); ++source_i)
            {
                pushBuffer(
                    &stream, offsetBuffer(fixture.pool, tail, sizeof(tail), offsets[destination_i]), true, &result);
                pushBuffer(&stream, offsetBuffer(fixture.pool, source, source_size, offsets[source_i]), true, &result);
                sbuf_t *output = bufferstreamReadExact(&stream, sizeof(tail) + source_size);
                checkBytes(&result, sbufGetRawPtr(output), tail, sizeof(tail));
                checkBytes(&result, (const uint8_t *) sbufGetRawPtr(output) + sizeof(tail), source, source_size);
                bufferpoolReuseBuffer(fixture.pool, output);
                result.bytes += sizeof(tail) + source_size;
                drained(&stream, &result);
            }
        }
    }
    result.ns = nowNs() - start;
    bufferstreamDestroy(&stream);
    freePool(&fixture);
    return result;
}

static result_t runPaddingCase(const geometry_t *geometry, uint16_t padding, uint32_t requested)
{
    const uint32_t  source_length = requested + 1U;
    const uint64_t  repeats       = (kTargetBytes + requested - 1U) / requested;
    pool_fixture_t  fixture       = makePool(geometry, kSmallWidth);
    buffer_stream_t stream        = bufferstreamCreate(fixture.pool, padding);
    result_t        result        = {
                      .digest          = UINT64_C(1469598103934665603),
                      .expected_digest = UINT64_C(1469598103934665603),
                      .equal           = true,
    };
    uint8_t *reference = memoryAllocate(source_length);
    if (reference == NULL)
    {
        fatal("padding reference allocation failed");
    }
    fillBytes(reference, source_length, requested ^ padding);

    const uint64_t start = nowNs();
    for (uint64_t repetition = 0; repetition < repeats; ++repetition)
    {
        pushBuffer(&stream, makeBuffer(fixture.pool, reference, source_length, true), false, &result);
        sbuf_t        *output   = bufferstreamReadExact(&stream, requested);
        const uint32_t capacity = sbufGetTotalCapacityNoPadding(output);
        result.equal &= result.returned_capacity == 0 || result.returned_capacity == capacity;
        result.returned_capacity = capacity;
        checkBytes(&result, sbufGetRawPtr(output), reference, requested);
        bufferpoolReuseBuffer(fixture.pool, output);
        output = bufferstreamReadExact(&stream, 1);
        result.equal &= *(const uint8_t *) sbufGetRawPtr(output) == reference[requested];
        bufferpoolReuseBuffer(fixture.pool, output);
        result.bytes += requested;
        drained(&stream, &result);
    }
    result.ns = nowNs() - start;
    memoryFree(reference);
    bufferstreamDestroy(&stream);
    freePool(&fixture);
    return result;
}

static void runCoalescingSuite(void)
{
    static const uint32_t fragments[] = {1, 16, 64, 128, 255, 256, 257, 512, 1024, 4096};
    static const uint32_t over_caps[] = {8192, 32768};
    for (size_t geometry = 0; geometry < ARRAY_SIZE(kGeometry); ++geometry)
    {
        for (size_t fragment = 0; fragment < ARRAY_SIZE(fragments); ++fragment)
        {
            runPair(&kGeometry[geometry], kExact, fragments[fragment]);
            runPair(&kGeometry[geometry], kIdeal, fragments[fragment]);
        }
        for (size_t over_cap = 0; over_cap < ARRAY_SIZE(over_caps); ++over_cap)
        {
            runPair(&kGeometry[geometry], kOverCap, over_caps[over_cap]);
        }
    }
}

static void runCrossoverSuite(void)
{
    static const uint32_t sizes[] = {255, 256, 257, 512, 1024, 4096};
    for (size_t size = 0; size < ARRAY_SIZE(sizes); ++size)
    {
        result_t samples[kSamples];
        (void) runCrossoverCase(sizes[size]);
        for (size_t sample = 0; sample < kSamples; ++sample)
        {
            samples[sample] = runCrossoverCase(sizes[size]);
        }
        char identity[160];
        (void) snprintf(identity,
                        sizeof(identity),
                        "suite=copy-crossover workload=coalesce-one geometry=high variant=source-state source_bytes=%u",
                        sizes[size]);
        report(identity, samples);
    }
}

static void runPaddingSuite(void)
{
    static const uint16_t    paddings[] = {2, 8, 17, 21};
    static const char *const names[]    = {"S", "S+1", "S+U-1", "S+U", "S+U+1"};
    for (size_t geometry = 0; geometry < ARRAY_SIZE(kGeometry); ++geometry)
    {
        for (size_t p = 0; p < ARRAY_SIZE(paddings); ++p)
        {
            const uint32_t boundaries[] = {
                kRecordSize,
                kRecordSize + 1U,
                kRecordSize + paddings[p] - 1U,
                kRecordSize + paddings[p],
                kRecordSize + paddings[p] + 1U,
            };
            for (size_t boundary = 0; boundary < ARRAY_SIZE(boundaries); ++boundary)
            {
                result_t samples[kSamples];
                (void) runPaddingCase(&kGeometry[geometry], paddings[p], boundaries[boundary]);
                for (size_t sample = 0; sample < kSamples; ++sample)
                {
                    samples[sample] = runPaddingCase(&kGeometry[geometry], paddings[p], boundaries[boundary]);
                }
                char identity[160];
                (void) snprintf(identity,
                                sizeof(identity),
                                "suite=padding workload=exact-U%u-%s geometry=%s variant=source-state bytes=%u",
                                paddings[p],
                                names[boundary],
                                kGeometry[geometry].name,
                                boundaries[boundary]);
                report(identity, samples);
            }
        }
    }
}

static bool printProcCpuContext(void)
{
    bool  model_found    = false;
    bool  features_found = false;
    FILE *cpuinfo        = fopen("/proc/cpuinfo", "r");
    if (cpuinfo == NULL)
    {
        return false;
    }

    char line[4096];
    while (fgets(line, sizeof(line), cpuinfo) != NULL)
    {
        const bool model = strncasecmp(line, "model name", 10) == 0 || strncasecmp(line, "hardware", 8) == 0 ||
                           strncasecmp(line, "uarch", 5) == 0 || strncasecmp(line, "cpu model", 9) == 0;
        const bool features = strncasecmp(line, "flags", 5) == 0 || strncasecmp(line, "features", 8) == 0 ||
                              strncasecmp(line, "isa", 3) == 0;
        if ((! model_found && model) || (! features_found && features))
        {
            line[strcspn(line, "\r\n")] = '\0';
            printf("context cpu_%s\n", line);
            model_found |= model;
            features_found |= features;
        }
        if (model_found && features_found)
        {
            break;
        }
    }
    (void) fclose(cpuinfo);
    return model_found && features_found;
}

static bool printCommandContext(const char *label, const char *command)
{
    FILE *pipe = popen(command, "r");
    if (pipe == NULL)
    {
        return false;
    }

    bool found = false;
    char line[4096];
    while (fgets(line, sizeof(line), pipe) != NULL)
    {
        line[strcspn(line, "\r\n")] = '\0';
        if (line[0] != '\0')
        {
            printf("context %s=%s\n", label, line);
            found = true;
        }
    }
    (void) pclose(pipe);
    return found;
}

static bool printSysctlCpuContext(void)
{
    const char *const model_commands[] = {
        "sysctl -n machdep.cpu.brand_string 2>/dev/null",
        "sysctl -n hw.model 2>/dev/null",
        "sysctl -n hw.machine 2>/dev/null",
    };
    bool model_found = false;
    for (size_t i = 0; i < ARRAY_SIZE(model_commands) && ! model_found; ++i)
    {
        model_found = printCommandContext("cpu_model", model_commands[i]);
    }

    bool features_found = false;
    features_found |= printCommandContext("cpu_features", "sysctl -n machdep.cpu.features 2>/dev/null");
    features_found |= printCommandContext("cpu_features", "sysctl -n machdep.cpu.leaf7_features 2>/dev/null");
    features_found |= printCommandContext("cpu_features", "sysctl -n machdep.cpu_extfeatures 2>/dev/null");
    if (! features_found)
    {
        features_found = printCommandContext("cpu_features", "sysctl -a 2>/dev/null | grep '^hw.optional' 2>/dev/null");
    }
    return model_found && features_found;
}

static uint64_t hostRamBytes(void)
{
    uint64_t ram = 0;
#if defined(_SC_PHYS_PAGES) && defined(_SC_PAGESIZE)
    const long pages     = sysconf(_SC_PHYS_PAGES);
    const long page_size = sysconf(_SC_PAGESIZE);
    if (pages > 0 && page_size > 0)
    {
        ram = (uint64_t) pages * (uint64_t) page_size;
    }
#endif
    if (ram == 0)
    {
        FILE *pipe = popen("sysctl -n hw.memsize 2>/dev/null", "r");
        if (pipe != NULL)
        {
            unsigned long long value = 0;
            if (fscanf(pipe, "%llu", &value) == 1)
            {
                ram = (uint64_t) value;
            }
            (void) pclose(pipe);
        }
    }
    return ram;
}

static void printHostContext(void)
{
    struct utsname system;
    if (uname(&system) == 0)
    {
        printf("context host=%s-%s architecture=%s\n", system.sysname, system.release, system.machine);
    }

    bool cpu_context_complete = printProcCpuContext();
    if (! cpu_context_complete)
    {
        cpu_context_complete = printSysctlCpuContext();
    }
    printf("context cpu_context_status=%s\n", cpu_context_complete ? "complete" : "inconclusive");

    const uint64_t ram = hostRamBytes();
    printf("context host_ram_bytes=%" PRIu64 " ram_profile_context=frozen-workload-geometries-not-runtime-global "
           "ram_profiles=low{large=4096,small=4096,padding=64},high{large=32768,small=4096,padding=64}\n",
           ram);
}

static void usage(const char *program)
{
    fprintf(stderr,
            "usage: %s [--suite all|coalescing|copy-crossover|padding] "
            "[--source-state LABEL] [--build-preset LABEL]\n",
            program);
}

int main(int argc, char **argv)
{
    const char *suite        = "all";
    const char *source_state = getenv("WW_BENCHMARK_SOURCE_STATE");
    const char *preset       = getenv("WW_BENCHMARK_BUILD_PRESET");
    source_state             = source_state != NULL ? source_state : "unlabeled-working-tree";
    preset                   = preset != NULL ? preset : WW_BENCHMARK_BUILD_TREE;
    for (int i = 1; i < argc; ++i)
    {
        const bool has_value = i + 1 < argc;
        if (strcmp(argv[i], "--suite") == 0 && has_value)
        {
            suite = argv[++i];
        }
        else if (strcmp(argv[i], "--source-state") == 0 && has_value)
        {
            source_state = argv[++i];
        }
        else if (strcmp(argv[i], "--build-preset") == 0 && has_value)
        {
            preset = argv[++i];
        }
        else if (strcmp(argv[i], "--help") == 0)
        {
            usage(argv[0]);
            return 0;
        }
        else
        {
            usage(argv[0]);
            return 2;
        }
    }
    const bool all = strcmp(suite, "all") == 0;
    if (! all && strcmp(suite, "coalescing") != 0 && strcmp(suite, "copy-crossover") != 0 &&
        strcmp(suite, "padding") != 0)
    {
        usage(argv[0]);
        return 2;
    }

    printf("context source_state=%s compiler=%s-%s build_preset=%s build_config=%s\n",
           source_state,
           WW_BENCHMARK_COMPILER_ID,
           WW_BENCHMARK_COMPILER_VERSION,
           preset,
           WW_BENCHMARK_BUILD_CONFIG);
    puts("context target_bytes_per_case=67108864 warmups=1 samples=7 "
         "paired_order=A/C1,C1/A,A/C1,C1/A,A/C1,C1/A,A/C1 external_source_order=alternate-where-practical");
    printHostContext();
    if (all || strcmp(suite, "coalescing") == 0)
    {
        runCoalescingSuite();
    }
    if (all || strcmp(suite, "copy-crossover") == 0)
    {
        runCrossoverSuite();
    }
    if (all || strcmp(suite, "padding") == 0)
    {
        runPaddingSuite();
    }
    return failed ? 1 : 0;
}

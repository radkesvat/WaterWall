// Boundary coverage for the sbuf_t capacity domain.
//
// sbufCreateWithPadding() rounds a requested capacity up to a cache line and
// then adds the aligned left padding. Doing that round-up in 32-bit arithmetic
// wrapped: a request just below UINT32_MAX collapsed to a capacity of 0, the
// "capacity overflow" check could never fire, and the caller received a buffer
// of only pad_left bytes whose reported capacity satisfied every later bounds
// check. A caller that had already committed to the requested length then wrote
// far past the allocation.
//
// The arithmetic now lives in sbufTryComputeCapacity(), so the boundary is
// testable without allocating 4 GiB.
//
// BufferPool sized its buffers with a second copy of the same 32-bit round-up,
// so it is covered here too: the cases at the bottom drive bufferpoolCreate()
// directly to pin its delegation to the shared helper.

#include "wwapi.h"

#include <sys/wait.h>
#include <unistd.h>

enum
{
    // Exit statuses the forked children use when the rejected request wrongly
    // returned instead of aborting.
    kChildAllocationSucceeded    = 66,
    kChildAllocationReturnedNull = 67
};

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "FAIL: %s\n", message);
        exit(1);
    }
}

// Cache-line size is 64 or 128 depending on the target, so every expectation is
// derived from kCpuLineCacheSize rather than hard-coded.
static const uint64_t kLine = (uint64_t) kCpuLineCacheSize;

// Largest capacity that is both cache-line aligned and representable.
static uint32_t maxAlignedCapacity(void)
{
    return (uint32_t) (UINT32_MAX - (UINT32_MAX % kLine));
}

static uint32_t computeOrFail(uint64_t minimum_capacity, uint16_t pad_left, const char *message)
{
    uint32_t capacity = 0;
    require(sbufTryComputeCapacity(minimum_capacity, pad_left, &capacity), message);
    return capacity;
}

// Rounding: 0 stays 0, anything else is raised to a whole number of cache lines.
static void testRoundsUpToCacheLines(void)
{
    require(computeOrFail(0, 0, "a zero-capacity request was rejected") == 0,
            "a zero-capacity request did not stay zero");
    require(computeOrFail(1, 0, "a one-byte request was rejected") == kLine,
            "a one-byte request was not raised to a full cache line");
    require(computeOrFail(kLine - 1, 0, "a sub-line request was rejected") == kLine,
            "a sub-line request was not raised to a full cache line");
    require(computeOrFail(kLine, 0, "an exactly aligned request was rejected") == kLine,
            "an exactly aligned request was rounded further");
    require(computeOrFail(kLine + 1, 0, "a request just over one line was rejected") == 2 * kLine,
            "a request just over one line did not round to two lines");
    require(computeOrFail(4096, 0, "an aligned 4096-byte request was rejected") == 4096,
            "an aligned 4096-byte request was rounded further");
}

// Left padding is aligned to 32 bytes and added on top of the rounded capacity.
static void testPaddingIsAlignedAndAdded(void)
{
    require(computeOrFail(kLine, 1, "a padded request was rejected") == kLine + 32,
            "one byte of padding was not aligned up to 32");
    require(computeOrFail(kLine, 32, "a 32-byte padded request was rejected") == kLine + 32,
            "exactly aligned padding was rounded further");
    require(computeOrFail(kLine, 33, "a 33-byte padded request was rejected") == kLine + 64,
            "33 bytes of padding did not align up to 64");

    // Padding whose alignment leaves the uint16_t domain cannot be honoured.
    uint32_t capacity = 0;
    require(! sbufTryComputeCapacity(kLine, UINT16_MAX, &capacity),
            "padding that overflows uint16_t on alignment was accepted");
}

/*
 * The regression.
 *
 * Every value above the largest aligned capacity must be rejected. These are
 * exactly the requests whose 32-bit round-up wrapped: UINT32_MAX became 0.
 */
static void testUnrepresentableRequestsAreRejected(void)
{
    const uint32_t max_aligned = maxAlignedCapacity();

    require(computeOrFail(max_aligned, 0, "the largest aligned capacity was rejected") == max_aligned,
            "the largest aligned capacity did not round to itself");

    for (uint64_t request = (uint64_t) max_aligned + 1; request <= (uint64_t) UINT32_MAX; request++)
    {
        uint32_t capacity = 0xA5A5A5A5U;
        require(! sbufTryComputeCapacity(request, 0, &capacity),
                "a request whose cache-line round-up overflows uint32_t was accepted");
        require(capacity == 0xA5A5A5A5U, "a rejected request still wrote an output capacity");
    }

    // Padding shrinks the representable range by its aligned size.
    require(computeOrFail(max_aligned, 32, "the largest aligned capacity plus 32 padding was rejected") ==
                max_aligned + 32,
            "the largest aligned capacity plus 32 padding computed the wrong total");

    uint32_t capacity = 0;
    require(! sbufTryComputeCapacity(max_aligned, (uint16_t) kLine, &capacity),
            "a capacity that only overflows once padding is added was accepted");

    // Values beyond the uint32_t domain entirely, which is why the parameter is
    // uint64_t: an already-overflowing computation is handed in without a lossy
    // narrowing that would hide it.
    require(! sbufTryComputeCapacity((uint64_t) UINT32_MAX + 1, 0, &capacity),
            "a request above the uint32_t domain was accepted");
    require(! sbufTryComputeCapacity(UINT64_MAX, 0, &capacity), "a UINT64_MAX request was accepted");
}

// Everything the allocation costs beyond the capacity itself: the sbuf_t header
// plus the over-allocation memoryAllocateAligned() makes to place the aligned
// pointer and its back-pointer.
static const uint64_t kAllocationOverhead = (uint64_t) sizeof(sbuf_t) + (uint64_t) kSbufAllocationAlignment;

/*
 * size_t is 32 bits on the supported 32-bit targets (Windows x86/ARM32, Android
 * x86/ARM32). There, a capacity the uint32_t domain accepts can still overflow
 * the real allocation, either wrapping it to zero (producing an empty buffer
 * that reports a 4 GiB capacity) or making memoryAllocateAligned() refuse it -
 * which turns a rejection the caller could have handled locally into a
 * process-wide failure.
 *
 * A 64-bit host can never reach that boundary, so the ceiling is injected rather
 * than left implicit - otherwise this case would only be reachable from a native
 * 32-bit build and would go untested everywhere else.
 */
static void testFullAllocationMustFitInSizeT(void)
{
    const uint64_t simulated_32bit_size_max = (uint64_t) UINT32_MAX;
    const uint64_t largest_total            = simulated_32bit_size_max - kAllocationOverhead;
    // Largest cache-line aligned capacity whose whole allocation still fits.
    const uint32_t largest_ok = (uint32_t) (largest_total - (largest_total % kLine));
    uint32_t       capacity   = 0;

    require(sbufTryComputeCapacityWithin(largest_ok, 0, simulated_32bit_size_max, &capacity),
            "the largest fully representable capacity was rejected on a 32-bit size_t");
    require(capacity == largest_ok, "the largest fully representable capacity computed the wrong total");
    require((uint64_t) capacity + kAllocationOverhead <= simulated_32bit_size_max,
            "an accepted capacity does not leave room for the header and alignment overhead");

    /*
     * Padding that pushes the total past that limit must be rejected, and it has
     * to be the allocation-overhead check doing it: the total still fits in
     * uint32_t, so the capacity-domain check above would have let it through.
     */
    const uint16_t overflowing_pad   = (uint16_t) (2 * kSbufAllocationAlignment);
    const uint64_t overflowing_total = (uint64_t) largest_ok + overflowing_pad;
    require(overflowing_total <= (uint64_t) UINT32_MAX,
            "the padded boundary case is not reaching the allocation-overhead check");
    require(overflowing_total > largest_total, "the padded boundary case does not exceed the allocation limit");

    capacity = 0xA5A5A5A5U;
    require(! sbufTryComputeCapacityWithin(largest_ok, overflowing_pad, simulated_32bit_size_max, &capacity),
            "a capacity whose allocation overhead overflows size_t on a 32-bit target was accepted");
    require(capacity == 0xA5A5A5A5U, "a rejected 32-bit-target request still wrote an output capacity");

    /*
     * The largest cache-line aligned capacity with zero padding. Whether its
     * whole allocation fits depends on the cache-line size, so assert the
     * property rather than a fixed verdict: with 64-byte lines it does not fit
     * and must be rejected, which the header-only check used to allow.
     */
    const uint32_t max_aligned      = maxAlignedCapacity();
    const bool     max_aligned_fits = ((uint64_t) max_aligned + kAllocationOverhead) <= simulated_32bit_size_max;
    capacity                        = 0;
    require(sbufTryComputeCapacityWithin(max_aligned, 0, simulated_32bit_size_max, &capacity) == max_aligned_fits,
            "the largest aligned capacity was not judged by whether its whole allocation fits");

    // A ceiling smaller than the overhead itself must be refused, not underflow.
    capacity = 0xA5A5A5A5U;
    require(! sbufTryComputeCapacityWithin(0, 0, kAllocationOverhead - 1, &capacity),
            "a size ceiling below the allocation overhead was accepted");
    require(! sbufTryComputeCapacityWithin(0, 0, 0, &capacity), "a zero size ceiling was accepted");
    require(capacity == 0xA5A5A5A5U, "a rejected undersized-ceiling request still wrote an output capacity");

    // On a 64-bit host the same request is fine, which is exactly why the
    // ceiling has to be injected to test the 32-bit behaviour at all.
    if (SIZE_MAX > (uint64_t) UINT32_MAX)
    {
        require(computeOrFail(max_aligned, 32, "a 64-bit host rejected a capacity its size_t can represent") ==
                    max_aligned + 32,
                "a 64-bit host computed the wrong total for the largest padded capacity");
    }
}

/*
 * The MUX encoders size their frame buffer from a peer-influenced payload
 * length. `encoded_length <= UINT32_MAX` alone let a value through that then
 * wrapped inside the allocator, so the encoders now validate the real
 * allocation. This pins the specific boundary that reaches them.
 */
static void testMuxEncodedLengthBoundary(void)
{
    enum
    {
        kMuxFrameLength        = 8,
        kMuxMaxDataFrameLength = 0xFFFF - kMuxFrameLength
    };

    // The smallest payload whose encoded length lands above the largest aligned
    // capacity while still being <= UINT32_MAX: the old check accepted it.
    const uint64_t max_aligned = maxAlignedCapacity();
    bool           found       = false;

    for (uint64_t payload = UINT64_C(4294000000); payload <= (uint64_t) UINT32_MAX; payload++)
    {
        const uint64_t data_frames    = (payload + kMuxMaxDataFrameLength - 1U) / kMuxMaxDataFrameLength;
        const uint64_t encoded_length = payload + (data_frames * kMuxFrameLength);

        if (encoded_length > (uint64_t) UINT32_MAX || encoded_length <= max_aligned)
        {
            continue;
        }

        // This is the dangerous window: the old `> UINT32_MAX` test passes it.
        uint32_t capacity = 0;
        require(! sbufTryComputeCapacity(encoded_length, 0, &capacity),
                "a MUX encoded length that wraps the allocator was accepted");
        found = true;
        break;
    }

    require(found, "no MUX payload reaching the wrap window was found; the boundary scan is not testing anything");
}

/*
 * sbufCreateWithPadding() must actually reject a request in that window rather
 * than returning a small buffer. It aborts, so this runs in a forked child.
 */
static void testCreateRejectsUnrepresentableRequest(void)
{
    pid_t child = fork();
    require(child >= 0, "failed to fork the capacity-overflow child");

    if (child == 0)
    {
        // Pre-fix this returned a buffer of pad_left bytes reporting a capacity
        // of pad_left, instead of refusing an impossible request.
        sbuf_t *buf = sbufCreateWithPadding(UINT32_MAX, 0);
        // Returning at all is the failure. The pointer is folded into the status
        // so the call cannot be optimised away, and so the two ways of returning
        // are distinguishable in the output.
        _Exit(buf == NULL ? kChildAllocationReturnedNull : kChildAllocationSucceeded);
    }

    int status = 0;
    require(waitpid(child, &status, 0) == child, "failed to wait for the capacity-overflow child");
    require(WIFEXITED(status), "the capacity-overflow child did not exit normally");
    require(WEXITSTATUS(status) != kChildAllocationSucceeded,
            "sbufCreateWithPadding() returned a buffer for a capacity it cannot represent");
    require(WEXITSTATUS(status) == 1, "the capacity-overflow child did not abort with the documented status");
}

/*
 * BufferPool sizes its two buffer classes through the same helper.
 *
 * It used to round them with its own copy of the 32-bit arithmetic, which
 * wrapped the same way: a size within a cache line of UINT32_MAX became 0, and
 * bufferpoolCreate() returned a pool whose buffers were empty but whose
 * reported size satisfied every later bounds check.
 *
 * bufferpoolCreate() is nullable, so an unrepresentable size is rejected before
 * the pool or its callbacks are published. Each parameter is checked on its own.
 */
static void requirePoolCreateRejects(uint32_t large_buffer_size, uint32_t small_buffer_size, const char *which)
{
    master_pool_t *large_master = masterpoolCreateWithCapacity(64);
    master_pool_t *small_master = masterpoolCreateWithCapacity(64);
    require(large_master != NULL && small_master != NULL, "failed to create buffer-pool masters");

    buffer_pool_t *pool     = bufferpoolCreate(large_master, small_master, 1, large_buffer_size, small_buffer_size);
    const bool     rejected = pool == NULL;
    if (pool != NULL)
    {
        bufferpoolDestroy(pool);
    }
    masterpoolMakeEmpty(large_master);
    masterpoolMakeEmpty(small_master);
    masterpoolDestroy(large_master);
    masterpoolDestroy(small_master);

    char message[128];
    snprintf(message, sizeof(message), "bufferpoolCreate() accepted an unrepresentable %s buffer size", which);
    require(rejected, message);
}

static void testPoolRejectsUnrepresentableBufferSizes(void)
{
    requirePoolCreateRejects(UINT32_MAX, 1024, "large");
    requirePoolCreateRejects(8192, UINT32_MAX, "small");
}

/*
 * The rejections above only mean something if a representable geometry is still
 * accepted and still rounded exactly the way sbufCreateWithPadding() would.
 * Sizes stay small: a debug build allocates one buffer of each class here.
 */
static void testPoolRoundsRepresentableBufferSizes(void)
{
    master_pool_t *large_master = masterpoolCreateWithCapacity(64);
    master_pool_t *small_master = masterpoolCreateWithCapacity(64);

    buffer_pool_t *pool = bufferpoolCreate(large_master, small_master, 1, (uint32_t) kLine + 1, 1);
    require(pool != NULL, "bufferpoolCreate() rejected a representable geometry");

    require(bufferpoolGetLargeBufferSize(pool) == computeOrFail(kLine + 1, 0, "the helper rejected a pool large size"),
            "the pool's large buffer size does not match the shared helper");
    require(bufferpoolGetSmallBufferSize(pool) == computeOrFail(1, 0, "the helper rejected a pool small size"),
            "the pool's small buffer size does not match the shared helper");

    bufferpoolDestroy(pool);
    masterpoolMakeEmpty(large_master);
    masterpoolMakeEmpty(small_master);
    masterpoolDestroy(large_master);
    masterpoolDestroy(small_master);
}

int main(void)
{
    testRoundsUpToCacheLines();
    testPaddingIsAlignedAndAdded();
    testUnrepresentableRequestsAreRejected();
    testFullAllocationMustFitInSizeT();
    testMuxEncodedLengthBoundary();
    testCreateRejectsUnrepresentableRequest();
    testPoolRoundsRepresentableBufferSizes();
    testPoolRejectsUnrepresentableBufferSizes();
    puts("sbuf capacity boundary tests passed");
    return 0;
}

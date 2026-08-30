#include "crypto/impl_software/private/chacha20_stream.h"
#include "wfrand.h"
#include "wwapi.h"

#if defined(OS_LINUX)
#include <fcntl.h>
#include <sys/syscall.h>
#include <unistd.h>

#if defined(SYS_getrandom)
#define WFRAND_TEST_SYS_GETRANDOM SYS_getrandom
#elif defined(__NR_getrandom)
#define WFRAND_TEST_SYS_GETRANDOM __NR_getrandom
#endif

static bool deny_urandom_open;

int __real_open(const char *path, int flags, ...);
int __wrap_open(const char *path, int flags, ...);

int __wrap_open(const char *path, int flags, ...)
{
    if (deny_urandom_open && strcmp(path, "/dev/urandom") == 0)
    {
        errno = ENOENT;
        return -1;
    }

    bool needs_mode = (flags & O_CREAT) != 0;
#if defined(O_TMPFILE)
    needs_mode = needs_mode || (flags & O_TMPFILE) == O_TMPFILE;
#endif
    if (! needs_mode)
    {
        return __real_open(path, flags);
    }

    va_list args;
    va_start(args, flags);
    mode_t mode = va_arg(args, mode_t);
    va_end(args);
    return __real_open(path, flags, mode);
}

static bool linuxGetrandomAvailable(void)
{
#if defined(WFRAND_TEST_SYS_GETRANDOM)
    uint8_t probe = 0;
    ssize_t result;
    do
    {
        result = syscall(WFRAND_TEST_SYS_GETRANDOM, &probe, sizeof(probe), 0);
    } while (result < 0 && errno == EINTR);
    memoryZero(&probe, sizeof(probe));
    return result == 1;
#else
    return false;
#endif
}
#endif

#if defined(OS_UNIX)
#include <sys/wait.h>
#include <unistd.h>
#endif

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "FAIL: %s\n", message);
        exit(1);
    }
}

static const uint8_t kDeterministicKey[32] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
                                              0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
                                              0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};

static void resetDeterministicRng(uint64_t next_stream_id)
{
    wfrandTestReset(kDeterministicKey, next_stream_id);
}

// Case 1 & Existing secureRandomBytes coverage
static void caseSecureRandomProvider(void)
{
    uint8_t first[66];
    uint8_t second[64];

    memset(first, 0xA5, sizeof(first));
    memset(second, 0xA5, sizeof(second));

    require(secureRandomBytes(NULL, 0), "zero-sized secure random request failed");
    require(! secureRandomBytes(NULL, 1), "secure random accepted a NULL destination");
    require(! secureRandomBytes(second, sizeof(second)), "secure random worked before global initialization");
    require(! frandGlobalInit(), "fast random global initialization succeeded without an OS random provider");

#if defined(OS_LINUX)
    const bool getrandom_available = linuxGetrandomAvailable();
    deny_urandom_open              = getrandom_available;
#endif

    require(globalstateInitializeSecureRandom(), "secure random global-state initialization failed");

#if defined(OS_LINUX)
    if (getrandom_available)
    {
        require(GSTATE.secure_random.device_fd < 0, "secure random required /dev/urandom despite getrandom support");
    }
    deny_urandom_open = false;
#endif

    require(secureRandomBytes(first + 1, sizeof(first) - 2U), "first secure random request failed");
    require(secureRandomBytes(second, sizeof(second)), "second secure random request failed");
    require(first[0] == 0xA5 && first[sizeof(first) - 1U] == 0xA5, "secure random wrote outside its buffer");
    require(memcmp(first + 1, second, sizeof(second)) != 0, "independent secure random outputs matched");

    globalstateDestroySecureRandom();
    require(! secureRandomBytes(second, sizeof(second)), "secure random worked after global teardown");
}

// Case 2: RFC 8439 known-answer test vector
static void caseRfc8439BlockKnownAnswer(void)
{
    static const uint8_t key[32] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
                                    0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
                                    0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};

    static const uint8_t nonce[12] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00};

    static const uint8_t expected_block1[64] = {
        0x22, 0x4f, 0x51, 0xf3, 0x40, 0x1b, 0xd9, 0xe1, 0x2f, 0xde, 0x27, 0x6f, 0xb8, 0x63, 0x1d, 0xed,
        0x8c, 0x13, 0x1f, 0x82, 0x3d, 0x2c, 0x06, 0xe2, 0x7e, 0x4f, 0xca, 0xec, 0x9e, 0xf3, 0xcf, 0x78,
        0x8a, 0x3b, 0x0a, 0xa3, 0x72, 0x60, 0x0a, 0x92, 0xb5, 0x79, 0x74, 0xcd, 0xed, 0x2b, 0x93, 0x34,
        0x79, 0x4c, 0xba, 0x40, 0xc6, 0x3e, 0x34, 0xcd, 0xea, 0x21, 0x2c, 0x4c, 0xf0, 0x7d, 0x41, 0xb7};

    static const uint8_t expected_block0[64] = {
        0xaf, 0x05, 0x1e, 0x40, 0xbb, 0xa0, 0x35, 0x49, 0x81, 0x32, 0x9a, 0x80, 0x6a, 0x14, 0x0e, 0xaf,
        0xd2, 0x58, 0xa2, 0x2a, 0x6d, 0xcb, 0x4b, 0xb9, 0xf6, 0x56, 0x9c, 0xb3, 0xef, 0xe2, 0xde, 0xaf,
        0x83, 0x7b, 0xd8, 0x7c, 0xa2, 0x0b, 0x5b, 0xa1, 0x20, 0x81, 0xa3, 0x06, 0xaf, 0x0e, 0xb3, 0x5c,
        0x41, 0xa2, 0x39, 0xd2, 0x0d, 0xfc, 0x74, 0xc8, 0x17, 0x71, 0x56, 0x0d, 0x9c, 0x9c, 0x1e, 0x4b};

    struct chacha20_ctx ctx;
    chacha20_init_ietf(&ctx, key, nonce);

    uint8_t block0[64];
    uint8_t block1[64];

    chacha20_keystream_block(&ctx, block0);
    chacha20_keystream_block(&ctx, block1);

    require(memcmp(block0, expected_block0, sizeof(block0)) == 0, "ChaCha20 block 0 test vector mismatch");
    require(memcmp(block1, expected_block1, sizeof(block1)) == 0, "RFC 8439 block 1 test vector mismatch");
}

// Case 3: Mixed fastRand32(), fastRand64(), and getRandomBytes() continuous stream
static void caseContinuousStreamAcrossMixedCalls(void)
{
    resetDeterministicRng(0);

    uint8_t stream_reference[192];
    getRandomBytes(stream_reference, sizeof(stream_reference));

    // Reset back to stream 0 from same master key
    resetDeterministicRng(0);

    // 1. Read 4 bytes via fastRand32() -> matches stream[0..3]
    uint32_t w32 = fastRand32();
    require(w32 == GET_LE32(stream_reference + 0), "fastRand32 output did not match continuous stream");

    // 2. Read 8 bytes via fastRand64() -> matches stream[4..11]
    uint64_t w64 = fastRand64();
    require(w64 == GET_LE64(stream_reference + 4), "fastRand64 output did not match continuous stream");

    // 3. Read 2 bytes via fastRand() -> matches stream[12..13] masked to 15 bits
    uint32_t r15          = fastRand();
    uint32_t expected_r15 = (uint32_t) (GET_LE16(stream_reference + 12) & 0x7FFF);
    require(r15 == expected_r15, "fastRand 15-bit output did not match continuous stream");
    require(r15 <= 32767, "fastRand output was out of range [0, 32767]");

    // 4. Read 20 bytes via getRandomBytes() -> matches stream[14..33]
    uint8_t buf20[20];
    getRandomBytes(buf20, sizeof(buf20));
    require(memcmp(buf20, stream_reference + 14, sizeof(buf20)) == 0,
            "getRandomBytes(20) did not match continuous stream");

    // 5. Read another fastRand64() -> matches stream[34..41]
    uint64_t w64_2 = fastRand64();
    require(w64_2 == GET_LE64(stream_reference + 34), "second fastRand64 did not match continuous stream");

    // 6. Read 80 bytes (crossing 64-byte block boundary) -> matches stream[42..121]
    uint8_t buf80[80];
    getRandomBytes(buf80, sizeof(buf80));
    require(memcmp(buf80, stream_reference + 42, sizeof(buf80)) == 0,
            "getRandomBytes(80) did not match continuous stream across block boundary");
}

// Case 4: Boundary reads immediately before, at, and after 64-byte boundary
static void caseBoundaryReadsAndSentinels(void)
{
    resetDeterministicRng(0);

    uint8_t reference[128];
    getRandomBytes(reference, sizeof(reference));

    resetDeterministicRng(0);

    uint8_t buffer[68];
    memset(buffer, 0xCC, sizeof(buffer));

    // Read 63 bytes (offset 2, length 63) -> leaves 1 byte in block 0
    getRandomBytes(buffer + 2, 63);
    require(buffer[0] == 0xCC && buffer[1] == 0xCC, "sentinel before buffer overwritten");
    require(buffer[65] == 0xCC && buffer[66] == 0xCC && buffer[67] == 0xCC, "sentinel after buffer overwritten");
    require(memcmp(buffer + 2, reference, 63) == 0, "63-byte boundary read mismatch");

    // Read 1 byte -> exact 64-byte boundary
    uint8_t b1 = 0;
    getRandomBytes(&b1, 1);
    require(b1 == reference[63], "exact 64-byte boundary read mismatch");

    // Read 1 byte -> first byte of block 1
    uint8_t b2 = 0;
    getRandomBytes(&b2, 1);
    require(b2 == reference[64], "first byte after 64-byte boundary read mismatch");

    // Read 63 bytes -> finishes block 1
    uint8_t rest[63];
    getRandomBytes(rest, 63);
    require(memcmp(rest, reference + 65, 63) == 0, "remaining block 1 read mismatch");
}

// Case 5: Counter exhaustion obtains a new nonce rather than returning block zero
static void caseCounterExhaustionRenewsNonce(void)
{
    resetDeterministicRng(10);

    // Stream ID is 10.
    require(wfrandTestGetCurrentStreamId() == 10, "initial stream ID mismatch");

    // Set max blocks per stream to 1. After 1 block (64 bytes), next generation must renew stream.
    wfrandTestSetMaxBlocksPerStream(1);

    uint8_t stream10_block0[64];
    getRandomBytes(stream10_block0, sizeof(stream10_block0));
    require(wfrandTestGetCurrentStreamId() == 10, "stream ID changed before block exhaustion");

    // Next 64-byte read must trigger stream renewal to stream ID 11!
    uint8_t stream11_block0[64];
    getRandomBytes(stream11_block0, sizeof(stream11_block0));
    require(wfrandTestGetCurrentStreamId() == 11, "stream ID did not advance upon block exhaustion");

    // The output must NOT equal stream10_block0 (which would occur if it looped to block 0 of stream 10)
    require(memcmp(stream11_block0, stream10_block0, 64) != 0,
            "exhausted stream returned duplicate block zero from old nonce");

    wfrandTestSetMaxBlocksPerStream(0);
}

// Case 6: Multiple threads receive distinct stream identifiers and outputs
typedef struct thread_test_data_s
{
    uint64_t stream_id;
    uint64_t sample_words[4];
} thread_test_data_t;

static WTHREAD_ROUTINE(threadWorkerFunc)
{
    thread_test_data_t *data = (thread_test_data_t *) userdata;
    frandInit();
    data->stream_id = wfrandTestGetCurrentStreamId();
    for (int i = 0; i < 4; ++i)
    {
        data->sample_words[i] = fastRand64();
    }
    frandThreadCleanup();
#if defined(OS_WIN)
    return 0;
#else
    return NULL;
#endif
}

static void caseMultiThreadIndependentStreams(void)
{
    thread_test_data_t t1_data = {0};
    thread_test_data_t t2_data = {0};

    resetDeterministicRng(100);
    frandThreadCleanup();

    wthread_t th1;
    wthread_t th2;
    require(threadCreate(&th1, threadWorkerFunc, &t1_data) == kWThreadErrorNone, "threadCreate 1 failed");
    require(threadCreate(&th2, threadWorkerFunc, &t2_data) == kWThreadErrorNone, "threadCreate 2 failed");

    require(threadJoin(th1) == 0, "threadJoin 1 failed");
    require(threadJoin(th2) == 0, "threadJoin 2 failed");

    require(t1_data.stream_id != t2_data.stream_id, "threads received identical stream IDs");
    require(memcmp(t1_data.sample_words, t2_data.sample_words, sizeof(t1_data.sample_words)) != 0,
            "independent threads produced identical random output");
}

// Case 7: Cleanup clears initialized state
static void caseCleanupClearsState(void)
{
    frandInit();
    require(wfrandTestIsThreadInitialized(), "thread random state was not initialized by frandInit");
    (void) fastRand32();

    frandThreadCleanup();
    require(! wfrandTestIsThreadInitialized(), "thread random state survived frandThreadCleanup");
}

// Case 8: POSIX fork invalidates stream in child
#if defined(OS_UNIX)
static bool writeAll(int fd, const uint8_t *data, size_t size)
{
    size_t offset = 0;
    while (offset < size)
    {
        const ssize_t written = write(fd, data + offset, size - offset);
        if (written < 0 && errno == EINTR)
        {
            continue;
        }
        if (written <= 0)
        {
            return false;
        }
        offset += (size_t) written;
    }
    return true;
}

static bool readAll(int fd, uint8_t *data, size_t size)
{
    size_t offset = 0;
    while (offset < size)
    {
        const ssize_t received = read(fd, data + offset, size - offset);
        if (received < 0 && errno == EINTR)
        {
            continue;
        }
        if (received <= 0)
        {
            return false;
        }
        offset += (size_t) received;
    }
    return true;
}

static void casePosixForkInvalidatesStream(void)
{
    resetDeterministicRng(200);
    uint8_t prefix[13];
    getRandomBytes(prefix, sizeof(prefix));

    int pipe_fds[2];
    require(pipe(pipe_fds) == 0, "fork RNG pipe creation failed");

    pid_t pid = fork();
    require(pid >= 0, "fork failed");

    if (pid == 0)
    {
        discard close(pipe_fds[0]);
        uint8_t child_block[96];
        getRandomBytes(child_block, sizeof(child_block));
        const bool written = writeAll(pipe_fds[1], child_block, sizeof(child_block));
        discard    close(pipe_fds[1]);
        _exit(written ? 0 : 1);
    }

    discard close(pipe_fds[1]);
    uint8_t parent_continuation[96];
    uint8_t child_output[96];
    getRandomBytes(parent_continuation, sizeof(parent_continuation));
    const bool child_output_received = readAll(pipe_fds[0], child_output, sizeof(child_output));
    discard    close(pipe_fds[0]);

    int status = 0;
    require(waitpid(pid, &status, 0) == pid, "waitpid failed");
    require(WIFEXITED(status) && WEXITSTATUS(status) == 0, "child process failed fork RNG test");
    require(child_output_received, "parent did not receive the child RNG output");
    require(memcmp(child_output, parent_continuation, sizeof(child_output)) != 0,
            "fork child continued the parent's cached ChaCha20 stream");
}

static void caseGlobalCleanupPreventsOutput(void)
{
    pid_t pid = fork();
    require(pid >= 0, "post-cleanup fork failed");
    if (pid == 0)
    {
        (void) fastRand32();
        _exit(0);
    }

    int status = 0;
    require(waitpid(pid, &status, 0) == pid, "post-cleanup waitpid failed");
    require(! (WIFEXITED(status) && WEXITSTATUS(status) == 0),
            "fast random output remained available after global cleanup");
}
#endif

// Case 9: Zero-length byte requests do not advance the stream
static void caseZeroLengthRequestPreservesStream(void)
{
    resetDeterministicRng(0);

    uint64_t first_word = fastRand64();

    resetDeterministicRng(0);

    // Calling getRandomBytes with size 0 (NULL destination)
    getRandomBytes(NULL, 0);

    uint8_t dummy[1];
    getRandomBytes(dummy, 0);

    uint64_t actual_first = fastRand64();
    require(actual_first == first_word, "zero-length getRandomBytes advanced the random stream");
}

int main(void)
{
    // Part 1: Secure random provider tests
    caseSecureRandomProvider();

    // Part 2: Initialize global state for ChaCha20 random family
    require(globalstateInitializeSecureRandom(), "globalstateInitializeSecureRandom failed");
    require(frandGlobalInit(), "frandGlobalInit failed");
    frandInit();

    // RFC 8439 known-answer test
    caseRfc8439BlockKnownAnswer();

    // Continuous stream across mixed calls
    caseContinuousStreamAcrossMixedCalls();

    // Boundary reads and sentinels
    caseBoundaryReadsAndSentinels();

    // Counter exhaustion stream renewal
    caseCounterExhaustionRenewsNonce();

    // Multithreading independent streams
    caseMultiThreadIndependentStreams();

    // Cleanup clears state
    caseCleanupClearsState();

#if defined(OS_UNIX)
    // POSIX fork invalidation
    casePosixForkInvalidatesStream();
#endif

    // Zero length byte request
    caseZeroLengthRequestPreservesStream();

    frandThreadCleanup();
    frandGlobalCleanup();
#if defined(OS_UNIX)
    caseGlobalCleanupPreventsOutput();
#endif
    globalstateDestroySecureRandom();

    puts("wfrand_test: all cases passed");

    return 0;
}

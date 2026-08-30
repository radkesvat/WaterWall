#include "wfrand.h"
#include "wlibc.h"

#include "crypto/impl_software/private/chacha20_stream.h"
#include "global_state.h"
#include "wendian.h"

#if defined(OS_LINUX)
#include <sys/syscall.h>

#if defined(SYS_getrandom)
#define WFRAND_SYS_GETRANDOM SYS_getrandom
#elif defined(__NR_getrandom)
#define WFRAND_SYS_GETRANDOM __NR_getrandom
#endif
#endif

#if defined(OS_UNIX)
#include <pthread.h>
#include <sched.h>
#include <unistd.h>
#endif

#if defined(OS_LINUX) && defined(WFRAND_SYS_GETRANDOM)
static bool secureRandomBytesGetrandom(uint8_t *dest, size_t len)
{
    size_t offset = 0;
    while (offset < len)
    {
        ssize_t nread = (ssize_t) syscall(WFRAND_SYS_GETRANDOM, dest + offset, len - offset, 0);
        if (UNLIKELY(nread < 0))
        {
            if (UNLIKELY(errno == EINTR))
            {
                continue;
            }
            break;
        }
        if (UNLIKELY(nread == 0))
        {
            break;
        }
        offset += (size_t) nread;
    }
    return offset == len;
}
#endif

#if defined(OS_WIN)
static bool secureRandomBytesWindows(uint8_t *dest, size_t len)
{
    enum
    {
        kBcryptUseSystemPreferredRng = 0x00000002UL
    };
    secure_random_windows_generator_fn gen_random = GSTATE.secure_random.generator;
    if (UNLIKELY(gen_random == NULL))
    {
        return false;
    }

    size_t offset = 0;
    while (offset < len)
    {
        const size_t remaining = len - offset;
        const ULONG  chunk     = remaining > (size_t) ULONG_MAX ? ULONG_MAX : (ULONG) remaining;

        if (UNLIKELY(gen_random(NULL, dest + offset, chunk, kBcryptUseSystemPreferredRng) < 0))
        {
            return false;
        }
        offset += chunk;
    }

    return true;
}
#endif

#if defined(OS_UNIX) && ! (defined(OS_DARWIN) || defined(OS_BSD))
static bool secureRandomBytesUrandom(uint8_t *dest, size_t len)
{
    int fd = GSTATE.secure_random.device_fd;
    if (UNLIKELY(fd < 0))
    {
        return false;
    }

    size_t offset = 0;
    while (offset < len)
    {
        ssize_t nread = read(fd, dest + offset, len - offset);
        if (UNLIKELY(nread < 0))
        {
            if (UNLIKELY(errno == EINTR))
            {
                continue;
            }
            break;
        }
        if (UNLIKELY(nread == 0))
        {
            break;
        }
        offset += (size_t) nread;
    }

    return offset == len;
}
#endif

bool secureRandomBytes(void *bytes, size_t size)
{
    if (size == 0)
    {
        return true;
    }
    if (UNLIKELY(bytes == NULL))
    {
        return false;
    }
    if (UNLIKELY(! GSTATE.secure_random.initialized))
    {
        return false;
    }

    uint8_t *dest = bytes;

#if defined(OS_LINUX) && defined(WFRAND_SYS_GETRANDOM)
    if (LIKELY(secureRandomBytesGetrandom(dest, size)))
    {
        return true;
    }
#endif

#if defined(OS_DARWIN) || defined(OS_BSD)
    arc4random_buf(dest, size);
    return true;
#elif defined(OS_WIN)
    return secureRandomBytesWindows(dest, size);
#elif defined(OS_UNIX)
    return secureRandomBytesUrandom(dest, size);
#else
    discard dest;
    discard size;
    return false;
#endif
}

// ---------------------------------------------------------------------------
// ChaCha20-backed Fast Random Generation
// ---------------------------------------------------------------------------

typedef struct frand_global_state_s
{
    uint8_t       master_key[CHACHA20_KEY_SIZE];
    atomic_ullong next_stream_id;
    atomic_bool   initialized;
#if defined(OS_UNIX)
    atomic_int fork_reseed_state;
#endif
#if defined(WFRAND_TEST_SEAM)
    uint64_t test_max_blocks_per_stream;
#endif
} frand_global_state_t;

static frand_global_state_t g_frand_state = {0};

typedef struct frand_tls_state_s
{
    struct chacha20_ctx ctx;
    uint8_t             block[CHACHA20_BLOCK_SIZE];
    size_t              cursor;
    uint64_t            stream_id;
    uint64_t            blocks_generated;
    bool                initialized;
} frand_tls_state_t;

static thread_local frand_tls_state_t tls_frand_state = {
    .cursor = CHACHA20_BLOCK_SIZE,
};

static _Noreturn void frandInvariantFailure(const char *message)
{
    printError("Fast random invariant failure: %s\n", message);
    abortProgramNow(1);
}

#if defined(OS_UNIX)
typedef enum frand_fork_reseed_state_e
{
    kFrandForkKeyCurrent = 0,
    kFrandForkReseedRequired,
    kFrandForkReseedInProgress,
} frand_fork_reseed_state_t;

_Static_assert(ATOMIC_INT_LOCK_FREE == 2, "the POSIX atfork marker must use lock-free atomic operations");

static pthread_once_t g_frand_atfork_once = PTHREAD_ONCE_INIT;
static int            g_frand_atfork_result;

static void frandAtForkChild(void)
{
    atomic_store_explicit(&g_frand_state.fork_reseed_state, kFrandForkReseedRequired, memory_order_relaxed);
    tls_frand_state.cursor      = CHACHA20_BLOCK_SIZE;
    tls_frand_state.initialized = false;
}

static void frandRegisterAtFork(void)
{
    g_frand_atfork_result = pthread_atfork(NULL, NULL, frandAtForkChild);
}

static bool frandEnsureAtForkRegistered(void)
{
    return pthread_once(&g_frand_atfork_once, frandRegisterAtFork) == 0 && g_frand_atfork_result == 0;
}

static void frandHandleForkReseed(void)
{
    for (;;)
    {
        const int state = atomic_load_explicit(&g_frand_state.fork_reseed_state, memory_order_acquire);
        if (state == kFrandForkKeyCurrent)
        {
            return;
        }

        if (state == kFrandForkReseedRequired)
        {
            int expected = kFrandForkReseedRequired;
            if (atomic_compare_exchange_weak_explicit(&g_frand_state.fork_reseed_state,
                                                      &expected,
                                                      kFrandForkReseedInProgress,
                                                      memory_order_acq_rel,
                                                      memory_order_acquire))
            {
                uint8_t new_master_key[CHACHA20_KEY_SIZE];
                if (UNLIKELY(! secureRandomBytes(new_master_key, sizeof(new_master_key))))
                {
                    memorySecureZero(new_master_key, sizeof(new_master_key));
                    abortProgramNow(1);
                }

                memoryCopy(g_frand_state.master_key, new_master_key, sizeof(new_master_key));
                memorySecureZero(new_master_key, sizeof(new_master_key));
                atomicStoreU64Relaxed(&g_frand_state.next_stream_id, 0);
                atomic_store_explicit(&g_frand_state.fork_reseed_state, kFrandForkKeyCurrent, memory_order_release);
                return;
            }
            continue;
        }

        assert(state == kFrandForkReseedInProgress);
        if (UNLIKELY(state != kFrandForkReseedInProgress))
        {
            abortProgramNow(1);
        }
        sched_yield();
    }
}
#endif

static uint64_t frandReserveStreamId(void)
{
    uint64_t stream_id = atomicLoadU64Relaxed(&g_frand_state.next_stream_id);
    for (;;)
    {
        assert(stream_id != UINT64_MAX);
        if (UNLIKELY(stream_id == UINT64_MAX))
        {
            frandInvariantFailure("ChaCha20 stream identifiers exhausted");
        }

        if (atomicCompareExchangeWeakU64Explicit(
                &g_frand_state.next_stream_id, &stream_id, stream_id + 1U, memory_order_relaxed, memory_order_relaxed))
        {
            return stream_id;
        }
    }
}

static void frandInitStreamForTls(frand_tls_state_t *tls)
{
    const uint64_t stream_id = frandReserveStreamId();

    uint8_t nonce[CHACHA20_IETF_NONCE_SIZE] = {'W', 'W', 'F', 'R'};
    PUT_LE64(nonce + 4, stream_id);

    chacha20_init_ietf(&tls->ctx, g_frand_state.master_key, nonce);

    tls->stream_id        = stream_id;
    tls->blocks_generated = 0;
    tls->cursor           = CHACHA20_BLOCK_SIZE;
    tls->initialized      = true;
}

static void frandInitializeTls(frand_tls_state_t *tls)
{
    memorySecureZero(tls, sizeof(*tls));
    tls->cursor = CHACHA20_BLOCK_SIZE;

    const bool global_initialized = atomic_load_explicit(&g_frand_state.initialized, memory_order_acquire);
    assert(global_initialized);
    if (UNLIKELY(! global_initialized))
    {
        frandInvariantFailure("random output requested outside the initialized process lifetime");
    }

#if defined(OS_UNIX)
    frandHandleForkReseed();
#endif

    frandInitStreamForTls(tls);
}

static inline void frandEnsureInitialized(frand_tls_state_t *tls)
{
    if (UNLIKELY(! tls->initialized))
    {
        frandInitializeTls(tls);
    }
}

static inline uint64_t frandBlocksPerStream(void)
{
#if defined(WFRAND_TEST_SEAM)
    if (g_frand_state.test_max_blocks_per_stream != 0)
    {
        return g_frand_state.test_max_blocks_per_stream;
    }
#endif
    return UINT64_C(1) << 32U;
}

static inline void frandGenerateBlock(frand_tls_state_t *tls, uint8_t out[CHACHA20_BLOCK_SIZE])
{
    if (UNLIKELY(tls->blocks_generated == frandBlocksPerStream()))
    {
        frandInitStreamForTls(tls);
    }

    chacha20_keystream_block(&tls->ctx, out);
    tls->blocks_generated++;
}

static void frandConsumeBytes(void *dest, size_t size)
{
    if (size == 0)
    {
        return;
    }

    frand_tls_state_t *tls = &tls_frand_state;
    frandEnsureInitialized(tls);

    uint8_t *out = (uint8_t *) dest;

    if (tls->cursor < CHACHA20_BLOCK_SIZE)
    {
        size_t avail = CHACHA20_BLOCK_SIZE - tls->cursor;
        if (size <= avail)
        {
            memoryCopy(out, tls->block + tls->cursor, size);
            tls->cursor += size;
            return;
        }
        memoryCopy(out, tls->block + tls->cursor, avail);
        out += avail;
        size -= avail;
        tls->cursor = CHACHA20_BLOCK_SIZE;
    }

    while (size >= CHACHA20_BLOCK_SIZE)
    {
        frandGenerateBlock(tls, out);
        out += CHACHA20_BLOCK_SIZE;
        size -= CHACHA20_BLOCK_SIZE;
    }

    if (size > 0)
    {
        frandGenerateBlock(tls, tls->block);
        memoryCopy(out, tls->block, size);
        tls->cursor = size;
    }
}

uint32_t fastRand(void)
{
    uint8_t b[2];
    frandConsumeBytes(b, sizeof(b));
    return (uint32_t) (GET_LE16(b) & 0x7FFF);
}

uint32_t fastRand32(void)
{
    uint8_t b[4];
    frandConsumeBytes(b, sizeof(b));
    return GET_LE32(b);
}

uint64_t fastRand64(void)
{
    uint8_t b[8];
    frandConsumeBytes(b, sizeof(b));
    return GET_LE64(b);
}

void getRandomBytes(void *bytes, size_t size)
{
    frandConsumeBytes(bytes, size);
}

bool frandGlobalInit(void)
{
    const bool already_initialized = atomic_load_explicit(&g_frand_state.initialized, memory_order_acquire);
    assert(! already_initialized);
    if (UNLIKELY(already_initialized))
    {
        frandInvariantFailure("process state initialized more than once");
    }

#if defined(OS_UNIX)
    if (UNLIKELY(! frandEnsureAtForkRegistered()))
    {
        return false;
    }
#endif

    uint8_t master_key[CHACHA20_KEY_SIZE];
    if (UNLIKELY(! secureRandomBytes(master_key, sizeof(master_key))))
    {
        memorySecureZero(master_key, sizeof(master_key));
        return false;
    }

    memoryCopy(g_frand_state.master_key, master_key, sizeof(master_key));
    memorySecureZero(master_key, sizeof(master_key));
    atomicStoreU64Relaxed(&g_frand_state.next_stream_id, 0);
#if defined(OS_UNIX)
    atomic_store_explicit(&g_frand_state.fork_reseed_state, kFrandForkKeyCurrent, memory_order_relaxed);
#endif
#if defined(WFRAND_TEST_SEAM)
    g_frand_state.test_max_blocks_per_stream = 0;
#endif
    atomic_store_explicit(&g_frand_state.initialized, true, memory_order_release);

    return true;
}

void frandGlobalCleanup(void)
{
    const bool initialized = atomic_load_explicit(&g_frand_state.initialized, memory_order_acquire);
    assert(initialized);
    discard initialized;
    assert(! tls_frand_state.initialized);
    if (UNLIKELY(tls_frand_state.initialized))
    {
        frandInvariantFailure("process cleanup began before current-thread cleanup");
    }

    atomic_store_explicit(&g_frand_state.initialized, false, memory_order_release);
    memorySecureZero(g_frand_state.master_key, sizeof(g_frand_state.master_key));
    atomicStoreU64Relaxed(&g_frand_state.next_stream_id, 0);
#if defined(OS_UNIX)
    atomic_store_explicit(&g_frand_state.fork_reseed_state, kFrandForkKeyCurrent, memory_order_relaxed);
#endif
#if defined(WFRAND_TEST_SEAM)
    g_frand_state.test_max_blocks_per_stream = 0;
#endif
}

void frandInit(void)
{
    frand_tls_state_t *tls = &tls_frand_state;
    frandEnsureInitialized(tls);
}

void frandThreadCleanup(void)
{
    memorySecureZero(&tls_frand_state, sizeof(tls_frand_state));
    tls_frand_state.cursor = CHACHA20_BLOCK_SIZE;
}

#if defined(WFRAND_TEST_SEAM)
void wfrandTestReset(const uint8_t key[CHACHA20_KEY_SIZE], uint64_t next_stream_id)
{
    assert(key != NULL);
    assert(atomic_load_explicit(&g_frand_state.initialized, memory_order_acquire));

    frandThreadCleanup();
    memoryCopy(g_frand_state.master_key, key, CHACHA20_KEY_SIZE);
    atomicStoreU64Relaxed(&g_frand_state.next_stream_id, next_stream_id);
    g_frand_state.test_max_blocks_per_stream = 0;
#if defined(OS_UNIX)
    atomic_store_explicit(&g_frand_state.fork_reseed_state, kFrandForkKeyCurrent, memory_order_relaxed);
#endif
    frandInit();
}

uint64_t wfrandTestGetCurrentStreamId(void)
{
    assert(tls_frand_state.initialized);
    return tls_frand_state.stream_id;
}

void wfrandTestSetMaxBlocksPerStream(uint64_t max_blocks)
{
    assert(max_blocks <= (UINT64_C(1) << 32U));
    g_frand_state.test_max_blocks_per_stream = max_blocks;
}

bool wfrandTestIsThreadInitialized(void)
{
    return tls_frand_state.initialized && atomic_load_explicit(&g_frand_state.initialized, memory_order_relaxed);
}
#endif

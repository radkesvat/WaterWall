#pragma once
#include "wlibc.h"

#ifdef COMPILER_MSVC
#pragma warning(disable : 4146) // unary minus operator applied to unsigned type, result still unsigned
#endif

/*
    Fill a buffer directly from the operating system's secure random provider.

    The provider is initialized and probed by createGlobalState() before
    workers or tunnels start. Returns true only when the entire buffer was
    filled. A zero-sized request succeeds even when bytes is NULL. No insecure
    fallback is used, and the buffer contents are unspecified on failure. Use
    this interface when an independent OS draw and recoverable failure result
    are required; ordinary runtime random generation uses the fast family below.
*/
WW_EXPORT bool secureRandomBytes(void *bytes, size_t size);

/*
    Fast cryptographically secure pseudorandom generator family backed by
    per-thread ChaCha20 streams seeded from the operating-system provider.

    The integer and byte interfaces consume one continuous stream. They are the
    normal choice for runtime nonces, IVs, salts, unpredictable identifiers,
    local hash seeds, randomized protocol fields, and padding. Select enough
    output for the purpose: the fixed-width functions provide 15, 32, or 64
    random bits, while getRandomBytes() provides any requested byte length.

    Process-wide state is initialized by frandGlobalInit() immediately after
    secure-random provider initialization. Each thread lazily or eagerly
    initializes its thread-local ChaCha20 stream with frandInit() and frees
    its local state with frandThreadCleanup(). Calling random functions before
    global initialization or after frandGlobalCleanup() is fatal.
*/

/*
    Compute a cryptographically unpredictable 15-bit integer in [0, 32767].
*/
WW_EXPORT uint32_t fastRand(void);

/*
    Compute a cryptographically unpredictable 32-bit integer.
*/
WW_EXPORT uint32_t fastRand32(void);

/*
    Compute a cryptographically unpredictable 64-bit integer.
*/
WW_EXPORT uint64_t fastRand64(void);

/*
    Fill a buffer with cryptographically unpredictable bytes from the thread's
    continuous ChaCha20 stream.
*/
WW_EXPORT void getRandomBytes(void *bytes, size_t size);

/* Convenience range mapping; modulo reduction is not exact-uniform for every span. */
static inline uint32_t fastRandRange32(uint32_t min_value, uint32_t max_value)
{
    if (max_value <= min_value)
    {
        return min_value;
    }

    uint64_t span = (uint64_t) max_value - (uint64_t) min_value + 1ULL;
    return min_value + (uint32_t) (fastRand64() % span);
}

/* Convenience jitter mapping; modulo reduction is not exact-uniform for every span. */
static inline uint32_t fastRandJittered32(uint32_t center, uint32_t jitter)
{
    if (center == 0 || jitter == 0)
    {
        return center;
    }

    uint32_t lower = jitter >= center ? 0 : center - jitter;
    uint32_t upper = UINT32_MAX - center < jitter ? UINT32_MAX : center + jitter;
    uint64_t span  = (uint64_t) upper - (uint64_t) lower + 1ULL;

    return lower + (uint32_t) (fastRand64() % span);
}

/* Convenience percentage roll; this is not an exact-uniform cryptographic sampler. */
static inline bool roll100(int chance_percent)
{
    if (chance_percent <= 0)
        return false;
    if (chance_percent >= 100)
        return true;
    uint32_t r = fastRand() % 100;
    return r < (uint32_t) chance_percent;
}

/*
    Global and thread lifecycle operations for process fast-random state.
*/
WW_MUST_USE WW_EXPORT bool frandGlobalInit(void);
WW_EXPORT void             frandGlobalCleanup(void);
WW_EXPORT void             frandInit(void);
WW_EXPORT void             frandThreadCleanup(void);

#if defined(WFRAND_TEST_SEAM)
WW_EXPORT void     wfrandTestReset(const uint8_t key[32], uint64_t next_stream_id);
WW_EXPORT uint64_t wfrandTestGetCurrentStreamId(void);
WW_EXPORT void     wfrandTestSetMaxBlocksPerStream(uint64_t max_blocks);
WW_EXPORT bool     wfrandTestIsThreadInitialized(void);
#endif

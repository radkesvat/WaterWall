#ifndef WW_ATOMIC_H_
#define WW_ATOMIC_H_

#include "wplatform.h" // for WW_HAVE_C11_ATOMICS

/* Published objects use WaterWall operations. Choose U32 or U64 for fixed-width
 * unsigned state, Ptr for object pointers, and the generic operations for
 * flags and native counts. Add, Sub, Inc and Dec return the previous value.
 * Before publication an initializer or atomic_init is sufficient. */

#if WW_HAVE_C11_ATOMICS

// c11
#include <stdatomic.h>

typedef _Atomic(void *)    atomic_ptr_t;
typedef long long          w_atomic_llong_value_t;
typedef int                w_atomic_int_value_t;
typedef unsigned int       w_atomic_uint_value_t;
typedef unsigned long long w_atomic_ullong_value_t;
typedef _Atomic(uint32_t)  atomic_u32_t;
#define W_ATOMIC_UINT_VALUE_SIGNED 0
#define W_ATOMIC_UINT_VALUE_MAX    UINT_MAX

#elif defined(OS_WIN)

#define ATOMIC_FLAG_INIT 0

#define ATOMIC_VAR_INIT(value) (value)

#define atomic_init(obj, value)                                                                                        \
    do                                                                                                                 \
    {                                                                                                                  \
        *(obj) = (value);                                                                                              \
    } while (0)

#define kill_dependency(y) ((void) 0)

#define atomic_thread_fence(order) MemoryBarrier()

#define atomic_signal_fence(order) ((void) 0)

#define atomic_is_lock_free(obj)   0

/*
 * Match the C11 names used throughout the codebase. The fallback implements
 * every operation below with a full-barrier Interlocked primitive, so the
 * individual order values are API markers rather than code-generation inputs.
 */
typedef enum memory_order_e
{
    memory_order_relaxed,
    memory_order_consume,
    memory_order_acquire,
    memory_order_release,
    memory_order_acq_rel,
    memory_order_seq_cst
} memory_order;

/* LONG_PTR is the signed operand type of the pointer-width Interlocked
 * integer intrinsics on both Win32 (LONG) and Win64 (LONG64). */
typedef void *volatile atomic_ptr_t;
typedef LONG_PTR      w_atomic_llong_value_t;
typedef LONG_PTR      atomic_flag;
typedef LONG_PTR      atomic_bool;
typedef LONG_PTR      atomic_char;
typedef LONG_PTR      atomic_schar;
typedef LONG_PTR      atomic_uchar;
typedef LONG_PTR      atomic_short;
typedef LONG_PTR      atomic_ushort;
typedef LONG_PTR      atomic_int;
typedef LONG_PTR      w_atomic_int_value_t;
typedef LONG_PTR      atomic_uint;
typedef LONG_PTR      w_atomic_uint_value_t;
typedef volatile LONG atomic_u32_t;
#define W_ATOMIC_UINT_VALUE_SIGNED 1
typedef LONG_PTR      atomic_long;
typedef LONG_PTR      atomic_ulong;
/* The lightweight semaphore stores its signed permit/waiter count in a native word. */
typedef LONG_PTR atomic_llong;
/*
 * Interlocked*64 requires its operand to be 8-byte aligned, and on a 32-bit
 * target that is more than the C alignment rules promise for an 8-byte integer.
 * Every Windows ABI happens to align long long to 8 anyway, but the requirement
 * is stated here rather than inherited, so a target that does not is a build
 * failure at the assertion below instead of a torn read at runtime.
 */
#if defined(_MSC_VER)
typedef __declspec(align(8)) unsigned long long atomic_ullong;
#else
typedef __attribute__((aligned(8))) unsigned long long atomic_ullong;
#endif
typedef unsigned long long w_atomic_ullong_value_t;
typedef LONG_PTR           atomic_wchar_t;
typedef LONG_PTR           atomic_int_least8_t;
typedef LONG_PTR           atomic_uint_least8_t;
typedef LONG_PTR           atomic_int_least16_t;
typedef LONG_PTR           atomic_uint_least16_t;
typedef LONG_PTR           atomic_int_least32_t;
typedef LONG_PTR           atomic_uint_least32_t;
typedef LONG_PTR           atomic_int_least64_t;
typedef LONG_PTR           atomic_uint_least64_t;
typedef LONG_PTR           atomic_int_fast8_t;
typedef LONG_PTR           atomic_uint_fast8_t;
typedef LONG_PTR           atomic_int_fast16_t;
typedef LONG_PTR           atomic_uint_fast16_t;
typedef LONG_PTR           atomic_int_fast32_t;
typedef LONG_PTR           atomic_uint_fast32_t;
typedef LONG_PTR           atomic_int_fast64_t;
typedef LONG_PTR           atomic_uint_fast64_t;
typedef LONG_PTR           atomic_intptr_t;
typedef LONG_PTR           atomic_uintptr_t;
typedef LONG_PTR           atomic_size_t;
typedef LONG_PTR           atomic_ptrdiff_t;
typedef LONG_PTR           atomic_intmax_t;
typedef LONG_PTR           atomic_uintmax_t;

#define _Atomic(x)              LONG_PTR
#define W_ATOMIC_UINT_VALUE_MAX INTPTR_MAX

/*
 * Interlocked operations are intentionally used even for relaxed call sites.
 * Besides providing indivisible pointer-width access, their full barrier keeps
 * release publication and acquire consumption correct on Windows ARM. A
 * store-then-barrier or barrier-then-load sequence would put the barrier on the
 * wrong side of the access.
 */

/* The fallback operates on exactly one pointer-width integer. Reject both
 * narrower and wider objects before any access. Fixed-width fields have
 * separate U32 and U64 operations. */
#define W_ATOMIC_REQUIRE_PTR_WIDTH(object)                                                                             \
    ((void) sizeof(struct {                                                                                            \
        int atomic_object_is_not_pointer_width_use_the_u64_api_for_64_bit_state                                        \
            : ((sizeof *(object)) == sizeof(intptr_t))                                                                 \
              ? 1                                                                                                      \
              : -1;                                                                                                    \
    }))

#ifdef _WIN64
#define W_ATOMIC_WORD_EXCHANGE InterlockedExchange64
#define W_ATOMIC_WORD_CAS      InterlockedCompareExchange64
#else
#define W_ATOMIC_WORD_EXCHANGE InterlockedExchange
#define W_ATOMIC_WORD_CAS      InterlockedCompareExchange
#endif

#define atomic_store(object, desired)                 (void) atomic_exchange(object, desired)
#define atomic_store_explicit(object, desired, order) atomic_store(object, desired)
#define atomic_load(object)                                                                                            \
    (W_ATOMIC_REQUIRE_PTR_WIDTH(object), W_ATOMIC_WORD_CAS((volatile LONG_PTR *) (object), 0, 0))
#define atomic_load_explicit(object, order) atomic_load(object)
#define atomic_exchange(object, desired)                                                                               \
    (W_ATOMIC_REQUIRE_PTR_WIDTH(object), W_ATOMIC_WORD_EXCHANGE((object), (LONG_PTR) (desired)))
#define atomic_exchange_explicit(object, desired, order) atomic_exchange(object, desired)

static inline bool w_atomicCompareExchangePtrWidth(LONG_PTR *object, LONG_PTR *expected, LONG_PTR desired)
{
    const LONG_PTR old = *expected;
    *expected          = W_ATOMIC_WORD_CAS(object, desired, old);
    return *expected == old;
}

#define atomic_compare_exchange_strong(object, expected, desired)                                                      \
    (W_ATOMIC_REQUIRE_PTR_WIDTH(object),                                                                               \
     W_ATOMIC_REQUIRE_PTR_WIDTH(expected),                                                                             \
     w_atomicCompareExchangePtrWidth(object, expected, desired))

#define atomic_compare_exchange_strong_explicit(object, expected, desired, success, failure)                           \
    atomic_compare_exchange_strong(object, expected, desired)

#define atomic_compare_exchange_weak(object, expected, desired)                                                        \
    atomic_compare_exchange_strong(object, expected, desired)

#define atomic_compare_exchange_weak_explicit(object, expected, desired, success, failure)                             \
    atomic_compare_exchange_weak(object, expected, desired)

#ifdef _WIN64

#define atomic_fetch_add(object, operand)                                                                              \
    (W_ATOMIC_REQUIRE_PTR_WIDTH(object), InterlockedExchangeAdd64(object, operand))

// negated as unsigned: -(operand) is signed overflow when operand is the signed minimum, and
// the C11 branch subtracts modularly for every operand, so this keeps the two branches agreeing
#define atomic_fetch_sub(object, operand)                                                                              \
    (W_ATOMIC_REQUIRE_PTR_WIDTH(object),                                                                               \
     InterlockedExchangeAdd64(object, (LONG64) (0ULL - (unsigned long long) (operand))))

#define atomic_fetch_or(object, operand) (W_ATOMIC_REQUIRE_PTR_WIDTH(object), InterlockedOr64(object, operand))

#define atomic_fetch_xor(object, operand) (W_ATOMIC_REQUIRE_PTR_WIDTH(object), InterlockedXor64(object, operand))

#define atomic_fetch_and(object, operand) (W_ATOMIC_REQUIRE_PTR_WIDTH(object), InterlockedAnd64(object, operand))
#else

#define atomic_fetch_add(object, operand) (W_ATOMIC_REQUIRE_PTR_WIDTH(object), InterlockedExchangeAdd(object, operand))

// negated as unsigned, for the reason given on the 64-bit spelling above
#define atomic_fetch_sub(object, operand)                                                                              \
    (W_ATOMIC_REQUIRE_PTR_WIDTH(object), InterlockedExchangeAdd(object, (LONG) (0UL - (unsigned long) (operand))))

#define atomic_fetch_or(object, operand) (W_ATOMIC_REQUIRE_PTR_WIDTH(object), InterlockedOr(object, operand))

#define atomic_fetch_xor(object, operand) (W_ATOMIC_REQUIRE_PTR_WIDTH(object), InterlockedXor(object, operand))

#define atomic_fetch_and(object, operand) (W_ATOMIC_REQUIRE_PTR_WIDTH(object), InterlockedAnd(object, operand))

#endif /* _WIN64 */

#define atomic_fetch_add_explicit(object, operand, order) atomic_fetch_add(object, operand)

#define atomic_fetch_sub_explicit(object, operand, order) atomic_fetch_sub(object, operand)

#define atomic_fetch_or_explicit(object, operand, order) atomic_fetch_or(object, operand)

#define atomic_fetch_xor_explicit(object, operand, order) atomic_fetch_xor(object, operand)

#define atomic_fetch_and_explicit(object, operand, order) atomic_fetch_and(object, operand)

#define atomic_flag_test_and_set(object) atomic_exchange(object, 1)

#define atomic_flag_test_and_set_explicit(object, order) atomic_flag_test_and_set(object)

#define atomic_flag_clear(object) atomic_store(object, 0)

#define atomic_flag_clear_explicit(object, order) atomic_flag_clear(object)

#else

#error "Cannot define atomic operations"

#endif

#define atomicAdd    atomic_fetch_add
#define atomicLoad   atomic_load
#define atomicStore  atomic_store
#define atomicSub    atomic_fetch_sub
#define atomicInc(p) atomicAdd(p, 1)
#define atomicDec(p) atomicSub(p, 1)

#define atomicAddExplicit       atomic_fetch_add_explicit
#define atomicLoadExplicit      atomic_load_explicit
#define atomicStoreExplicit     atomic_store_explicit
#define atomicSubExplicit       atomic_fetch_sub_explicit
#define atomicIncExplicit(p, y) atomicAddExplicit(p, 1, y)
#define atomicDecExplicit(p, y) atomicSubExplicit(p, 1, y)

#define atomicExchange                    atomic_exchange
#define atomicOrExplicit                  atomic_fetch_or_explicit
#define atomicCompareExchangeWeakExplicit atomic_compare_exchange_weak_explicit
#define atomicCompareExchange         atomic_compare_exchange_strong
#define atomicCompareExchangeExplicit atomic_compare_exchange_strong_explicit

/* Pass size_t to compare/exchange on every backend. A failed attempt
 * replaces the caller's expected value with the observed count. */
static inline bool atomicCompareExchangeWeakSizeExplicit(atomic_size_t *object, size_t *expected, size_t desired,
                                                         memory_order success, memory_order failure)
{
#if WW_HAVE_C11_ATOMICS
    return atomic_compare_exchange_weak_explicit(object, expected, desired, success, failure);
#else
    (void) success;
    (void) failure;
    LONG_PTR   observed  = (LONG_PTR) *expected;
    const bool exchanged = w_atomicCompareExchangePtrWidth(object, &observed, (LONG_PTR) desired);
    *expected            = (size_t) observed;
    return exchanged;
#endif
}

static inline void *atomicLoadPtrExplicit(const atomic_ptr_t *object, memory_order order)
{
#if WW_HAVE_C11_ATOMICS
    return atomic_load_explicit(object, order);
#else
    (void) order;
    return InterlockedCompareExchangePointer((PVOID volatile *) object, NULL, NULL);
#endif
}

static inline void atomicStorePtrExplicit(atomic_ptr_t *object, void *desired, memory_order order)
{
#if WW_HAVE_C11_ATOMICS
    atomic_store_explicit(object, desired, order);
#else
    (void) order;
    (void) InterlockedExchangePointer(object, desired);
#endif
}

static inline void *atomicExchangePtrExplicit(atomic_ptr_t *object, void *desired, memory_order order)
{
#if WW_HAVE_C11_ATOMICS
    return atomic_exchange_explicit(object, desired, order);
#else
    (void) order;
    return InterlockedExchangePointer(object, desired);
#endif
}

/*
 * Fixed-width 32-bit atomics. Use only the U32 helpers on atomic_u32_t after
 * publication: the Windows generic API accesses pointer-sized storage.
 * Arithmetic returns the previous unsigned value and wraps modulo 2^32.
 * Plain initialization is safe before the object is published.
 */
_Static_assert(sizeof(atomic_u32_t) == sizeof(uint32_t), "atomic_u32_t must use exactly 32-bit storage");

#if WW_HAVE_C11_ATOMICS

static inline uint32_t atomicLoadU32Explicit(const atomic_u32_t *object, memory_order order)
{
    return atomic_load_explicit(object, order);
}

static inline void atomicStoreU32Explicit(atomic_u32_t *object, uint32_t desired, memory_order order)
{
    atomic_store_explicit(object, desired, order);
}

static inline uint32_t atomicAddU32Explicit(atomic_u32_t *object, uint32_t operand, memory_order order)
{
    return atomic_fetch_add_explicit(object, operand, order);
}

static inline uint32_t atomicSubU32Explicit(atomic_u32_t *object, uint32_t operand, memory_order order)
{
    return atomic_fetch_sub_explicit(object, operand, order);
}

/* Strong compare/exchange; on failure, expected receives the observed value. */
static inline bool atomicCompareExchangeU32Explicit(atomic_u32_t *object, uint32_t *expected, uint32_t desired,
                                                    memory_order success, memory_order failure)
{
    return atomic_compare_exchange_strong_explicit(object, expected, desired, success, failure);
}

#else

_Static_assert(_Alignof(atomic_u32_t) >= 4, "Interlocked operations require 4-byte-aligned storage");

// Interlocked primitives provide a full barrier, including for relaxed callers.
static inline uint32_t atomicLoadU32Explicit(const atomic_u32_t *object, memory_order order)
{
    (void) order;
    return (uint32_t) InterlockedCompareExchange((volatile LONG *) object, 0, 0);
}

static inline void atomicStoreU32Explicit(atomic_u32_t *object, uint32_t desired, memory_order order)
{
    (void) order;
    (void) InterlockedExchange(object, (LONG) desired);
}

static inline uint32_t atomicAddU32Explicit(atomic_u32_t *object, uint32_t operand, memory_order order)
{
    (void) order;
    return (uint32_t) InterlockedExchangeAdd(object, (LONG) operand);
}

static inline uint32_t atomicSubU32Explicit(atomic_u32_t *object, uint32_t operand, memory_order order)
{
    (void) order;
    return (uint32_t) InterlockedExchangeAdd(object, (LONG) (UINT32_C(0) - operand));
}

static inline bool atomicCompareExchangeU32Explicit(atomic_u32_t *object, uint32_t *expected, uint32_t desired,
                                                    memory_order success, memory_order failure)
{
    (void) success;
    (void) failure;
    const uint32_t old = *expected;
    *expected          = (uint32_t) InterlockedCompareExchange((volatile LONG *) object, (LONG) desired, (LONG) old);
    return *expected == old;
}

#endif

#define atomicLoadU32(x)     atomicLoadU32Explicit((x), memory_order_seq_cst)
#define atomicStoreU32(x, y) atomicStoreU32Explicit((x), (y), memory_order_seq_cst)
#define atomicAddU32(x, y)   atomicAddU32Explicit((x), (y), memory_order_seq_cst)
#define atomicSubU32(x, y)   atomicSubU32Explicit((x), (y), memory_order_seq_cst)
#define atomicIncU32(x)      atomicAddU32((x), 1)
#define atomicDecU32(x)      atomicSubU32((x), 1)

#define atomicIncU32Explicit(x, y)  atomicAddU32Explicit((x), 1, (y))
#define atomicDecU32Explicit(x, y)  atomicSubU32Explicit((x), 1, (y))
#define atomicLoadU32Relaxed(x)     atomicLoadU32Explicit((x), memory_order_relaxed)
#define atomicStoreU32Relaxed(x, y) atomicStoreU32Explicit((x), (y), memory_order_relaxed)
#define atomicIncU32Relaxed(x)      atomicIncU32Explicit((x), memory_order_relaxed)
#define atomicDecU32Relaxed(x)      atomicDecU32Explicit((x), memory_order_relaxed)

/* Published atomic_ullong fields use the U64 operations. These preserve
 * the entire unsigned value on 32-bit Windows, where the generic operations
 * are pointer-width and Interlocked*64 requires 8-byte aligned storage. */
_Static_assert(sizeof(atomic_ullong) == sizeof(uint64_t),
               "atomic_ullong must be real 64-bit storage on every target, see the comment above");
_Static_assert(sizeof(atomic_ullong) == sizeof(w_atomic_ullong_value_t),
               "atomic_ullong compare/exchange value type must match its storage");

#if WW_HAVE_C11_ATOMICS

/*
 * uint64_t and unsigned long long are distinct types on LP64, and the C11
 * compare/exchange takes a pointer to the atomic's own value type. That is what
 * w_atomic_ullong_value_t is for: it keeps the conversion in one place so call
 * sites can stay in plain uint64_t.
 */

static inline uint64_t atomicLoadU64Explicit(const atomic_ullong *object, memory_order order)
{
    return (uint64_t) atomic_load_explicit(object, order);
}

static inline void atomicStoreU64Explicit(atomic_ullong *object, uint64_t desired, memory_order order)
{
    atomic_store_explicit(object, (w_atomic_ullong_value_t) desired, order);
}

static inline uint64_t atomicExchangeU64Explicit(atomic_ullong *object, uint64_t desired, memory_order order)
{
    return (uint64_t) atomic_exchange_explicit(object, (w_atomic_ullong_value_t) desired, order);
}

static inline uint64_t atomicAddU64Explicit(atomic_ullong *object, uint64_t operand, memory_order order)
{
    return (uint64_t) atomic_fetch_add_explicit(object, (w_atomic_ullong_value_t) operand, order);
}

static inline uint64_t atomicSubU64Explicit(atomic_ullong *object, uint64_t operand, memory_order order)
{
    return (uint64_t) atomic_fetch_sub_explicit(object, (w_atomic_ullong_value_t) operand, order);
}

static inline bool atomicCompareExchangeU64Explicit(atomic_ullong *object, uint64_t *expected, uint64_t desired,
                                                    memory_order success, memory_order failure)
{
    w_atomic_ullong_value_t expected_value = (w_atomic_ullong_value_t) *expected;
    const bool              exchanged      = atomic_compare_exchange_strong_explicit(
        object, &expected_value, (w_atomic_ullong_value_t) desired, success, failure);
    *expected = (uint64_t) expected_value;
    return exchanged;
}

static inline bool atomicCompareExchangeWeakU64Explicit(atomic_ullong *object, uint64_t *expected, uint64_t desired,
                                                        memory_order success, memory_order failure)
{
    w_atomic_ullong_value_t expected_value = (w_atomic_ullong_value_t) *expected;
    const bool              exchanged      = atomic_compare_exchange_weak_explicit(
        object, &expected_value, (w_atomic_ullong_value_t) desired, success, failure);
    *expected = (uint64_t) expected_value;
    return exchanged;
}

#else

_Static_assert(_Alignof(atomic_ullong) >= 8, "Interlocked*64 requires 8 byte aligned storage");

/*
 * As with the generic operations above, the full barrier of the Interlocked
 * primitive is what makes the requested memory order correct on Windows ARM, so
 * the order arguments are API markers rather than code-generation inputs.
 * Interlocked*64 is available on 32-bit Windows too: winnt.h defines the
 * operations that x86 and ARM32 lack as compare-exchange loops over
 * InterlockedCompareExchange64.
 */

static inline uint64_t atomicLoadU64Explicit(const atomic_ullong *object, memory_order order)
{
    (void) order;
    return (uint64_t) InterlockedCompareExchange64((LONG64 volatile *) object, 0, 0);
}

static inline void atomicStoreU64Explicit(atomic_ullong *object, uint64_t desired, memory_order order)
{
    (void) order;
    (void) InterlockedExchange64((LONG64 volatile *) object, (LONG64) desired);
}

static inline uint64_t atomicExchangeU64Explicit(atomic_ullong *object, uint64_t desired, memory_order order)
{
    (void) order;
    return (uint64_t) InterlockedExchange64((LONG64 volatile *) object, (LONG64) desired);
}

static inline uint64_t atomicAddU64Explicit(atomic_ullong *object, uint64_t operand, memory_order order)
{
    (void) order;
    return (uint64_t) InterlockedExchangeAdd64((LONG64 volatile *) object, (LONG64) operand);
}

static inline uint64_t atomicSubU64Explicit(atomic_ullong *object, uint64_t operand, memory_order order)
{
    (void) order;
    // negated as unsigned: -(LONG64) operand is signed overflow when operand is 2^63, and the
    // C11 branch subtracts modularly for every operand, so this keeps the two branches agreeing
    return (uint64_t) InterlockedExchangeAdd64((LONG64 volatile *) object, (LONG64) (0ULL - operand));
}

static inline bool atomicCompareExchangeU64Explicit(atomic_ullong *object, uint64_t *expected, uint64_t desired,
                                                    memory_order success, memory_order failure)
{
    (void) success;
    (void) failure;
    const uint64_t old = *expected;
    const uint64_t previous =
        (uint64_t) InterlockedCompareExchange64((LONG64 volatile *) object, (LONG64) desired, (LONG64) old);
    *expected = previous;
    return previous == old;
}

static inline bool atomicCompareExchangeWeakU64Explicit(atomic_ullong *object, uint64_t *expected, uint64_t desired,
                                                        memory_order success, memory_order failure)
{
    // InterlockedCompareExchange64 never fails spuriously, so weak is strong here
    return atomicCompareExchangeU64Explicit(object, expected, desired, success, failure);
}

#endif

#define atomicLoadU64(x)        atomicLoadU64Explicit((x), memory_order_seq_cst)
#define atomicStoreU64(x, y)    atomicStoreU64Explicit((x), (y), memory_order_seq_cst)
#define atomicExchangeU64(x, y) atomicExchangeU64Explicit((x), (y), memory_order_seq_cst)
#define atomicAddU64(x, y)      atomicAddU64Explicit((x), (y), memory_order_seq_cst)
#define atomicSubU64(x, y)      atomicSubU64Explicit((x), (y), memory_order_seq_cst)
#define atomicIncU64(x)         atomicAddU64((x), 1)
#define atomicDecU64(x)         atomicSubU64((x), 1)

#define atomicIncU64Explicit(x, y) atomicAddU64Explicit((x), 1, (y))
#define atomicDecU64Explicit(x, y) atomicSubU64Explicit((x), 1, (y))

#define atomicLoadU64Relaxed(x)     atomicLoadU64Explicit((x), memory_order_relaxed)
#define atomicStoreU64Relaxed(x, y) atomicStoreU64Explicit((x), (y), memory_order_relaxed)
#define atomicIncU64Relaxed(x)      atomicIncU64Explicit((x), memory_order_relaxed)
#define atomicDecU64Relaxed(x)      atomicDecU64Explicit((x), memory_order_relaxed)

#define atomicCompareExchangeU64(x, expected, desired)                                                                 \
    atomicCompareExchangeU64Explicit((x), (expected), (desired), memory_order_seq_cst, memory_order_seq_cst)

#define atomicFlagTestAndSet atomic_flag_test_and_set
#define atomicFlagClear      atomic_flag_clear

#define atomicThreadFence(x)            atomic_thread_fence(x)
#define atomicLoadRelaxed(x)            atomic_load_explicit((x), memory_order_relaxed)
#define atomicStoreRelaxed(x, y)        atomic_store_explicit((x), (y), memory_order_relaxed)
#define atomicIncRelaxed(x)             atomicIncExplicit((x), memory_order_relaxed)
#define atomicDecRelaxed(x)             atomicDecExplicit((x), memory_order_relaxed)
#define atomicExchangeExplicit(x, y, z) atomic_exchange_explicit(x, y, z)

#endif // WW_ATOMIC_H_

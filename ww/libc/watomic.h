#ifndef WW_ATOMIC_H_
#define WW_ATOMIC_H_

#include "wplatform.h" // for HAVE_STDATOMIC_H

/*
 * This header exposes two atomic APIs and they are not interchangeable:
 *
 *   atomic_ullong objects -> the u64 API:      atomicLoadU64, atomicStoreU64, atomicAddU64,
 *                                              atomicIncU64, atomicCompareExchangeU64, ...
 *   everything else       -> the generic API:  atomicLoad, atomicStore, atomicAdd,
 *                                              atomicInc, atomicCompareExchange, ...
 *
 * The generic API is pointer-width, which is not 64 bits everywhere this project
 * builds. The "64-bit atomics" section at the bottom of this file explains what
 * that costs and why the second API had to exist; read it before adding a new
 * atomic_ullong field or reaching for a generic operation on an existing one.
 */

#if HAVE_STDATOMIC_H

// c11
#include <limits.h>
#include <stdatomic.h>

typedef int                w_atomic_int_value_t;
typedef unsigned int       w_atomic_uint_value_t;
typedef unsigned long long w_atomic_ullong_value_t;
#define W_ATOMIC_UINT_VALUE_SIGNED 0
#define W_ATOMIC_UINT_VALUE_MAX    UINT_MAX

#elif defined(OS_WIN)

#include <stddef.h>
#include <stdint.h>

#define ATOMIC_FLAG_INIT 0

#define ATOMIC_VAR_INIT(value) (value)

#define atomic_init(obj, value)                                                                                        \
    do                                                                                                                 \
    {                                                                                                                  \
        *(obj) = (value);                                                                                              \
    } while (0)

#define kill_dependency(y) ((void) 0)

#define atomic_thread_fence(order) MemoryBarrier();

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

typedef intptr_t atomic_flag;
typedef intptr_t atomic_bool;
typedef intptr_t atomic_char;
typedef intptr_t atomic_schar;
typedef intptr_t atomic_uchar;
typedef intptr_t atomic_short;
typedef intptr_t atomic_ushort;
typedef intptr_t atomic_int;
typedef intptr_t w_atomic_int_value_t;
typedef intptr_t atomic_uint;
typedef intptr_t w_atomic_uint_value_t;
#define W_ATOMIC_UINT_VALUE_SIGNED 1
typedef intptr_t atomic_long;
typedef intptr_t atomic_ulong;
/*
 * atomic_llong stays pointer-width on purpose: its only user is the lightweight
 * semaphore count in wmutex.h, which is bounded by the worker count and can
 * never need more than a pointer. atomic_ullong cannot make that promise -- see
 * the 64-bit atomics section at the bottom of this file.
 */
typedef intptr_t atomic_llong;
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
typedef intptr_t           atomic_wchar_t;
typedef intptr_t atomic_int_least8_t;
typedef intptr_t atomic_uint_least8_t;
typedef intptr_t atomic_int_least16_t;
typedef intptr_t atomic_uint_least16_t;
typedef intptr_t atomic_int_least32_t;
typedef intptr_t atomic_uint_least32_t;
typedef intptr_t atomic_int_least64_t;
typedef intptr_t atomic_uint_least64_t;
typedef intptr_t atomic_int_fast8_t;
typedef intptr_t atomic_uint_fast8_t;
typedef intptr_t atomic_int_fast16_t;
typedef intptr_t atomic_uint_fast16_t;
typedef intptr_t atomic_int_fast32_t;
typedef intptr_t atomic_uint_fast32_t;
typedef intptr_t atomic_int_fast64_t;
typedef intptr_t atomic_uint_fast64_t;
typedef intptr_t atomic_intptr_t;
typedef intptr_t atomic_uintptr_t;
typedef intptr_t atomic_size_t;
typedef intptr_t atomic_ptrdiff_t;
typedef intptr_t atomic_intmax_t;
typedef intptr_t atomic_uintmax_t;

#define _Atomic(x)              intptr_t
#define W_ATOMIC_UINT_VALUE_MAX INTPTR_MAX

/*
 * Interlocked operations are intentionally used even for relaxed call sites.
 * Besides providing indivisible pointer-width access, their full barrier keeps
 * release publication and acquire consumption correct on Windows ARM. A
 * store-then-barrier or barrier-then-load sequence would put the barrier on the
 * wrong side of the access.
 */

/*
 * Every generic operation below is an Interlocked*Pointer call, so it accesses
 * exactly one pointer -- no more and no less -- and the check below demands
 * exactly that width. Both directions are silent corruption otherwise, and
 * neither is caught by the type system, because these macros cast their operand
 * to (PVOID volatile *) and that cast accepts any object pointer:
 *
 *   too wide     half-writes and half-reads the object, and the value that
 *                comes back is not even the surviving low half -- the load
 *                returns a signed intptr_t, so it sign-extends. This is what
 *                a 64-bit field costs on a 32-bit Windows target.
 *
 *   too narrow   reads and writes past the end of the object. A pointer-width
 *                store into a 32-bit field on a 64-bit target overwrites
 *                whatever the compiler laid out in the next four bytes.
 *
 * So the fix depends on which way the mismatch goes: 64-bit state belongs to
 * the u64 API below, while a caller whose own variable is narrower than a
 * pointer should hold the value in a w_atomic_int_value_t / w_atomic_uint_value_t
 * and convert at the boundary, the way worker.c and device_lifetime.h do.
 */
#define W_ATOMIC_REQUIRE_PTR_WIDTH(object)                                                                             \
    ((void) sizeof(struct {                                                                                            \
        int atomic_object_is_not_pointer_width_use_the_u64_api_for_64_bit_state                                        \
            : ((sizeof *(object)) == sizeof(intptr_t)) ? 1 : -1;                                                       \
    }))

#define atomic_store(object, desired)                                                                                  \
    (W_ATOMIC_REQUIRE_PTR_WIDTH(object),                                                                               \
     (void) InterlockedExchangePointer((PVOID volatile *) (object), (PVOID) (intptr_t) (desired)))

#define atomic_store_explicit(object, desired, order) atomic_store(object, desired)

#define atomic_load(object)                                                                                            \
    (W_ATOMIC_REQUIRE_PTR_WIDTH(object),                                                                               \
     (intptr_t) InterlockedCompareExchangePointer((PVOID volatile *) (object), NULL, NULL))

#define atomic_load_explicit(object, order) atomic_load(object)

#define atomic_exchange(object, desired)                                                                               \
    (W_ATOMIC_REQUIRE_PTR_WIDTH(object),                                                                               \
     (intptr_t) InterlockedExchangePointer((PVOID volatile *) (object), (PVOID) (intptr_t) (desired)))

#define atomic_exchange_explicit(object, desired, order) atomic_exchange(object, desired)

static inline int w_atomicCompareExchangePtrWidth(intptr_t *object, intptr_t *expected, intptr_t desired)
{
    intptr_t old = *expected;
    *expected    = (intptr_t) InterlockedCompareExchangePointer(
        (PVOID volatile *) object, (PVOID) (intptr_t) desired, (PVOID) (intptr_t) old);
    return *expected == old;
}

/*
 * Wrapped in a macro so the width check reaches compare/exchange too. Both the
 * object and the expected-value slot are checked: passing 64-bit state here is
 * one mistake spelled two ways, and the intptr_t parameters alone would only
 * report it as a pointer type mismatch.
 */
#define atomic_compare_exchange_strong(object, expected, desired)                                                      \
    (W_ATOMIC_REQUIRE_PTR_WIDTH(object), W_ATOMIC_REQUIRE_PTR_WIDTH(expected),                                         \
     w_atomicCompareExchangePtrWidth(object, expected, desired))

#define atomic_compare_exchange_strong_explicit(object, expected, desired, success, failure)                           \
    atomic_compare_exchange_strong(object, expected, desired)

#define atomic_compare_exchange_weak(object, expected, desired)                                                        \
    atomic_compare_exchange_strong(object, expected, desired)

#define atomic_compare_exchange_weak_explicit(object, expected, desired, success, failure)                             \
    atomic_compare_exchange_weak(object, expected, desired)

#ifdef _WIN64

#define atomic_fetch_add(object, operand) (W_ATOMIC_REQUIRE_PTR_WIDTH(object), InterlockedExchangeAdd64(object, operand))

#define atomic_fetch_sub(object, operand)                                                                              \
    (W_ATOMIC_REQUIRE_PTR_WIDTH(object), InterlockedExchangeAdd64(object, -(operand)))

#define atomic_fetch_or(object, operand) (W_ATOMIC_REQUIRE_PTR_WIDTH(object), InterlockedOr64(object, operand))

#define atomic_fetch_xor(object, operand) (W_ATOMIC_REQUIRE_PTR_WIDTH(object), InterlockedXor64(object, operand))

#define atomic_fetch_and(object, operand) (W_ATOMIC_REQUIRE_PTR_WIDTH(object), InterlockedAnd64(object, operand))
#else

#define atomic_fetch_add(object, operand) (W_ATOMIC_REQUIRE_PTR_WIDTH(object), InterlockedExchangeAdd(object, operand))

#define atomic_fetch_sub(object, operand)                                                                              \
    (W_ATOMIC_REQUIRE_PTR_WIDTH(object), InterlockedExchangeAdd(object, -(operand)))

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

#define atomicCompareExchange         atomic_compare_exchange_strong
#define atomicCompareExchangeExplicit atomic_compare_exchange_strong_explicit

/*
 * ---------------------------------------------------------------------------
 * 64-bit atomics
 * ---------------------------------------------------------------------------
 *
 * Everything above operates on pointer-width objects. Use it for flags,
 * counters, indices, enums, sizes and pointers -- anything that fits in an
 * intptr_t. Use the u64 API below, and only the u64 API, on atomic_ullong.
 *
 * The split is not stylistic, and it is not about range. The Windows fallback
 * in the middle of this file is not a real C11 implementation: it emulates
 * every operation with an Interlocked primitive, and the only width
 * Interlocked*Pointer offers is the width of a pointer. On a 64-bit target that
 * is 64 bits and nobody notices, but this project also builds windows-x86 and
 * windows-arm32, where a pointer is four bytes.
 *
 * What that does to a 64-bit value is worse than dropping the high word. The
 * generic load returns a signed intptr_t, so a value that does not fit is
 * truncated on the way in and then sign-extended on the way out: it comes back
 * as a completely different number rather than as its own low half. Storing
 * 3000000000 through the generic API on a 32-bit target reads back as
 * 18446744072414584320.
 *
 * Every atomic_ullong in this codebase holds a value that cannot fit in 32
 * bits. widle_table and SoftIpLimiter store absolute epoch-millisecond
 * timestamps, which passed 2^32 in 1970 and are around 1.8e12 today. SpeedLimit
 * stores token counts scaled by kSpeedLimitUnitsPerByte, which overflows a
 * signed 32-bit slot at roughly 2.15 MB/s. On the generic API those produced
 * idle items that never expired (or expired instantly, depending on which side
 * of the sign boundary the clock's low 32 bits were on) and an all-connections
 * bandwidth limit that stopped limiting -- silently, on release builds, with no
 * diagnostic anywhere.
 *
 * So atomic_ullong is real 64-bit storage on every target, and the helpers
 * below are the only way to operate on it. They lower to Interlocked*64, which
 * is cmpxchg8b on x86 and ldrexd/strexd on ARM32; winnt.h supplies the variants
 * that have no single instruction as compare-exchange loops. Those primitives
 * require 8-byte-aligned storage, which the natural alignment of unsigned long
 * long already provides on every Windows ABI -- the assertions below keep it
 * that way.
 *
 * Plain assignment to an atomic_ullong is still fine while the object is being
 * constructed and is not yet reachable by another thread; on the fallback it is
 * an ordinary 64-bit store, which is two stores on a 32-bit target and is only
 * safe because nothing else can see it yet. Once the object is published, every
 * access goes through the API.
 *
 * The generic operations reject an atomic_ullong at compile time on 32-bit
 * Windows (see W_ATOMIC_REQUIRE_PTR_WIDTH). Elsewhere they would compile and
 * behave correctly, so the mistake surfaces on the Windows CI leg rather than
 * on a developer's machine.
 */
_Static_assert(sizeof(atomic_ullong) == sizeof(uint64_t),
               "atomic_ullong must be real 64-bit storage on every target, see the comment above");
_Static_assert(sizeof(atomic_ullong) == sizeof(w_atomic_ullong_value_t),
               "atomic_ullong compare/exchange value type must match its storage");

#if HAVE_STDATOMIC_H

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
    const uint64_t old      = *expected;
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

#define atomicLoadU64(x)            atomicLoadU64Explicit((x), memory_order_seq_cst)
#define atomicStoreU64(x, y)        atomicStoreU64Explicit((x), (y), memory_order_seq_cst)
#define atomicExchangeU64(x, y)     atomicExchangeU64Explicit((x), (y), memory_order_seq_cst)
#define atomicAddU64(x, y)          atomicAddU64Explicit((x), (y), memory_order_seq_cst)
#define atomicSubU64(x, y)          atomicSubU64Explicit((x), (y), memory_order_seq_cst)
#define atomicIncU64(x)             atomicAddU64((x), 1)
#define atomicDecU64(x)             atomicSubU64((x), 1)

#define atomicIncU64Explicit(x, y)  atomicAddU64Explicit((x), 1, (y))
#define atomicDecU64Explicit(x, y)  atomicSubU64Explicit((x), 1, (y))

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

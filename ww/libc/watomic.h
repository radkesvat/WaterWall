#ifndef WW_ATOMIC_H_
#define WW_ATOMIC_H_

#include "wplatform.h" // for HAVE_STDATOMIC_H

#if HAVE_STDATOMIC_H

// c11
#include <stdatomic.h>

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

#define atomic_is_lock_free(obj) 0

typedef intptr_t atomic_flag;
typedef intptr_t atomic_bool;
typedef intptr_t atomic_char;
typedef intptr_t atomic_schar;
typedef intptr_t atomic_uchar;
typedef intptr_t atomic_short;
typedef intptr_t atomic_ushort;
typedef intptr_t atomic_int;
typedef intptr_t atomic_uint;
typedef intptr_t atomic_long;
typedef intptr_t atomic_ulong;
typedef intptr_t atomic_llong;
typedef intptr_t atomic_ullong;
typedef intptr_t atomic_wchar_t;
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

#define _Atomic(x) intptr_t

#define atomic_store(object, desired)                                                                                  \
    do                                                                                                                 \
    {                                                                                                                  \
        *(object) = (desired);                                                                                         \
        MemoryBarrier();                                                                                               \
    } while (0)

#define atomic_store_explicit(object, desired, order) atomic_store(object, desired)

#define atomic_load(object) (MemoryBarrier(), *(object))

#define atomic_load_explicit(object, order) atomic_load(object)

#define atomic_exchange(object, desired) InterlockedExchangePointer((PVOID volatile *) object, (PVOID) desired)

#define atomic_exchange_explicit(object, desired, order) atomic_exchange(object, desired)

static inline int atomic_compare_exchange_strong(intptr_t *object, intptr_t *expected, intptr_t desired)
{
    intptr_t old = *expected;
    *expected    = (intptr_t) InterlockedCompareExchangePointer((PVOID *) object, (PVOID) desired, (PVOID) old);
    return *expected == old;
}

#define atomic_compare_exchange_strong_explicit(object, expected, desired, success, failure)                           \
    atomic_compare_exchange_strong(object, expected, desired)

#define atomic_compare_exchange_weak(object, expected, desired)                                                        \
    atomic_compare_exchange_strong(object, expected, desired)

#define atomic_compare_exchange_weak_explicit(object, expected, desired, success, failure)                             \
    atomic_compare_exchange_weak(object, expected, desired)

#ifdef _WIN64

#define atomic_fetch_add(object, operand) InterlockedExchangeAdd64(object, operand)

#define atomic_fetch_sub(object, operand) InterlockedExchangeAdd64(object, -(operand))

#define atomic_fetch_or(object, operand) InterlockedOr64(object, operand)

#define atomic_fetch_xor(object, operand) InterlockedXor64(object, operand)

#define atomic_fetch_and(object, operand) InterlockedAnd64(object, operand)
#else

#define atomic_fetch_add(object, operand) InterlockedExchangeAdd(object, operand)

#define atomic_fetch_sub(object, operand) InterlockedExchangeAdd(object, -(operand))

#define atomic_fetch_or(object, operand) InterlockedOr(object, operand)

#define atomic_fetch_xor(object, operand) InterlockedXor(object, operand)

#define atomic_fetch_and(object, operand) InterlockedAnd(object, operand)

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
#define atomicIncExplicit(p, x) atomicAddExplicit(p, x, 1)
#define atomicDecExplicit(p, x) atomicSubExplicit(p, x, 1)

#define atomicCompareExchange         atomic_compare_exchange_strong
#define atomicCompareExchangeExplicit atomic_compare_exchange_strong_explicit

#define atomicFlagTestAndSet atomic_flag_test_and_set
#define atomicFlagClear      atomic_flag_clear


#define atomicLoadRelaxed(x) atomic_load_explicit((x), memory_order_relaxed)

#endif // WW_ATOMIC_H_

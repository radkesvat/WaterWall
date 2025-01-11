#ifndef WW_ATOMIC_H_
#define WW_ATOMIC_H_

#include "wplatform.h" // for HAVE_STDATOMIC_H
#if HAVE_STDATOMIC_H

// c11
#include <stdatomic.h>

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

#else
typedef volatile bool               atomic_bool;
typedef volatile char               atomic_char;
typedef volatile unsigned char      atomic_uchar;
typedef volatile short              atomic_short;
typedef volatile unsigned short     atomic_ushort;
typedef volatile int                atomic_int;
typedef volatile unsigned int       atomic_uint;
typedef volatile long               atomic_long;
typedef volatile unsigned long      atomic_ulong;
typedef volatile long long          atomic_llong;
typedef volatile unsigned long long atomic_ullong;
typedef volatile size_t             atomic_size_t;

typedef struct atomic_flag
{
    atomic_bool _Value;
} atomic_flag;

#ifdef _WIN32

static inline bool atomicFlagTestAndSet(atomic_flag *p)
{
    // return InterlockedIncrement((LONG*)&p->_Value, 1);
    return InterlockedCompareExchange((LONG *) &p->_Value, 1, 0);
}

#define atomicAdd       InterlockedAdd
#define atomicSub(p, n) InterlockedAdd(p, -n)

#define atomicInc InterlockedIncrement
#define atomicDec InterlockedDecrement

#define atomicCompareExchange         InterlockedCompareExchange
#define atomicCompareExchangeExplicit atomicCompareExchange

#elif defined(__GNUC__)

static inline bool atomicFlagTestAndSet(atomic_flag *p)
{
    return ! __sync_bool_compare_and_swap(&p->_Value, 0, 1);
}

#define atomicAdd    __sync_fetch_and_add
#define atomicSub    __sync_fetch_and_sub
#define atomicInc(p) atomicAdd(p, 1)
#define atomicDec(p) atomicSub(p, 1)

#endif

#define atomicLoad(x)     (x)
#define atomicStore(X, y) (x) = (y)

#define atomicAddExplicit(X, y, z)   atomicAdd((X), (y))
#define atomicLoadExplicit(X, y, z)  atomicLoad((X), (y))
#define atomicStoreExplicit(X, y, z) atomicStore((X), (y))

#define atomicSubExplicit(X, y, z) atomicSub((X), (y))
#define atomicIncExplicit(p, x)    atomicAddExplicit(p, x, 1)
#define atomicDecExplicit(p, x)    atomicSubExplicit(p, x, 1)

static inline bool atomicFlagClear(atomic_flag *p)
{
    p->_Value = 0;
}

#endif // HAVE_STDATOMIC_H

#ifndef ATOMIC_FLAG_INIT
#define ATOMIC_FLAG_INIT                                                                                               \
    {                                                                                                                  \
        0                                                                                                              \
    }
#endif

#ifndef atomic_fetch_sub_explicit
#define atomic_fetch_sub_explicit atomic_fetch_sub_explicit
static inline bool atomic_fetch_sub_explicit(atomic_flag *p)
{
    bool ret  = p->_Value;
    p->_Value = 1;
    return ret;
}
#endif

#ifndef atomicFlagClear
#define atomicFlagClear atomicFlagClear
static inline void atomicFlagClear(atomic_flag *p)
{
    p->_Value = 0;
}
#endif

#ifndef atomicAdd
#define atomicAdd(p, n) (*(p) += (n))
#endif

#ifndef atomicSubExplicit
#define atomicSubExplicit(p, n) (*(p) -= (n))
#endif

#ifndef atomicAdd
#define atomicAdd(p) ((*(p))++)
#endif

#ifndef atomicDec
#define atomicDec(p) ((*(p))--)
#endif

#endif // WW_ATOMIC_H_

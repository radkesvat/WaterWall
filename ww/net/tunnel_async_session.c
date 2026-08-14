#include "tunnel_async_session.h"

#include "loggers/internal_logger.h"

tunnel_async_session_t *tunnelasyncsessionCreate(tunnel_t *t, const char *owner_name)
{
    tunnel_async_session_t *session = memoryAllocateZero(sizeof(*session));
    if (UNLIKELY(session == NULL))
    {
        return NULL;
    }

    atomic_init(&session->refcount, 1);
    atomic_init(&session->tunnel, (uintptr_t) t);
    deviceLifetimeGateInit(&session->callback_gate);
    session->owner_name = owner_name;
    return session;
}

void tunnelasyncsessionRef(tunnel_async_session_t *session)
{
    w_atomic_uint_value_t previous = atomicLoadRelaxed(&session->refcount);
    for (;;)
    {
        /*
         * Zero means the allocation is already being freed, so taking a
         * reference here would resurrect it; the maximum means the next
         * increment would wrap into zero. Neither is recoverable.
         */
        if (UNLIKELY(previous == 0 || previous >= W_ATOMIC_UINT_VALUE_MAX))
        {
            LOGF("%s: async-session reference count overflow or resurrection", session->owner_name);
            abortProgramNow(1);
        }
        if (atomic_compare_exchange_weak_explicit(
                &session->refcount, &previous, previous + 1, memory_order_relaxed, memory_order_relaxed))
        {
            return;
        }
    }
}

void tunnelasyncsessionUnref(tunnel_async_session_t *session)
{
    const w_atomic_uint_value_t previous = atomicSubExplicit(&session->refcount, 1, memory_order_release);
    assert(previous > 0);
    if (previous == 1)
    {
        // Pairs with every releasing decrement, so the free sees all prior writes.
        atomicThreadFence(memory_order_acquire);
        memoryFree(session);
    }
}

bool tunnelasyncsessionEnter(tunnel_async_session_t *session, tunnel_t **out_tunnel)
{
    if (! deviceLifetimeGateEnter(&session->callback_gate))
    {
        return false;
    }

    tunnel_t *t = (tunnel_t *) (uintptr_t) atomicLoadExplicit(&session->tunnel, memory_order_acquire);
    if (UNLIKELY(t == NULL))
    {
        // Detach raced the entry; give the gate slot straight back.
        deviceLifetimeGateLeave(&session->callback_gate);
        return false;
    }

    *out_tunnel = t;
    return true;
}

void tunnelasyncsessionLeave(tunnel_async_session_t *session)
{
    deviceLifetimeGateLeave(&session->callback_gate);
}

bool tunnelasyncsessionOpen(tunnel_async_session_t *session)
{
    return deviceLifetimeGateOpen(&session->callback_gate);
}

void tunnelasyncsessionCloseAndQuiesce(tunnel_async_session_t *session)
{
    deviceLifetimeGateCloseAndQuiesce(&session->callback_gate, deviceLifetimeYieldThread, NULL);
}

bool tunnelasyncsessionIsAccepting(const tunnel_async_session_t *session)
{
    return deviceLifetimeGateIsActive(&session->callback_gate);
}

void tunnelasyncsessionDetach(tunnel_async_session_t *session)
{
    discard atomicExchangeExplicit(&session->tunnel, (uintptr_t) NULL, memory_order_acq_rel);
}

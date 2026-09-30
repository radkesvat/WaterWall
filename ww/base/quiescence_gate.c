#include "quiescence_gate.h"

#include "loggers/internal_logger.h"

#ifndef NDEBUG
thread_local quiescence_gate_thread_entries_t quiescence_gate_thread_entries;
#endif

enum
{
    kQuiescenceGateWarningWaitMs          = 2000,
    kQuiescenceGateWarningCheckYieldCount = 256
};

bool quiescenceGateOpen(quiescence_gate_t *gate)
{
    w_atomic_uint_value_t expected = QUIESCENCE_GATE_CLOSED;

    // Publishes the protected fields installed by the lifecycle owner.
    if (atomicCompareExchangeExplicit(&gate->state, &expected, 0, memory_order_release, memory_order_relaxed))
    {
        return true;
    }

    LOGE("Quiescence gate open requires a closed, quiesced gate (state=%llu)", (unsigned long long) expected);
    assert(expected == QUIESCENCE_GATE_CLOSED);
    return false;
}

void quiescenceGateReportSaturation(void)
{
    LOGE("Quiescence gate entry count saturated");
}

_Noreturn void quiescenceGateAbortUnderflow(void)
{
    LOGF("quiescenceGateLeave: gate state count underflow");
    abortProgramNow(1);
}

void quiescenceGateWaitQuiesced(quiescence_gate_t *gate, QuiescenceGateYieldFn yield_fn, void *yield_context)
{
    assert(yield_fn != NULL);
    assert((atomicLoadRelaxed(&gate->state) & QUIESCENCE_GATE_CLOSED) != 0);

    unsigned int wait_started_at = getTickMS();
    unsigned int yields          = 0;
    bool         warned          = false;
    for (;;)
    {
        // Acquire pairs with the final entrant's release Leave before reclamation.
        const w_atomic_uint_value_t state     = atomicLoadExplicit(&gate->state, memory_order_acquire);
        const w_atomic_uint_value_t in_flight = state & QUIESCENCE_GATE_COUNT_MASK;
        if (in_flight == 0)
        {
            return;
        }

        yield_fn(yield_context);
        yields++;
        if (! warned && yields % kQuiescenceGateWarningCheckYieldCount == 0 &&
            getTickMS() - wait_started_at >= kQuiescenceGateWarningWaitMs)
        {
            LOGW("Quiescence gate is still waiting for %llu in-flight operation(s)", (unsigned long long) in_flight);
            warned = true;
        }
    }
}

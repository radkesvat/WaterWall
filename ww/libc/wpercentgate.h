#pragma once

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*
 * A small, caller-owned percentage gate for hot paths that need random-like
 * event selection without cryptographic security. Each gate keeps an
 * independent deterministic PCG32 stream and a cutoff computed once during
 * initialization.
 *
 * The output is deliberately predictable and must never select secrets,
 * protocol identifiers, security tokens, nonces, hash-flood defenses, or any
 * behavior whose resistance to an observer matters. Use the fastRand family
 * for those purposes. Callers must not access one gate concurrently and should
 * keep one gate per independent decision stream.
 */
typedef struct noncrypto_percent_gate_s
{
    uint64_t state;
    uint64_t cutoff;
} noncrypto_percent_gate_t;

/*
 * Initialize a gate for a fixed percentage in [0, 100]. The seed selects a
 * deterministic sequence; every uint64_t value, including zero, is valid.
 */
static inline void nonCryptoPercentGateInit(noncrypto_percent_gate_t *gate, uint32_t chance_percent, uint64_t seed)
{
    assert(gate != NULL);
    assert(chance_percent <= 100U);

    const uint64_t multiplier = UINT64_C(6364136223846793005);
    const uint64_t increment  = UINT64_C(1442695040888963407);

    /* Equivalent to the canonical fixed-stream PCG warm-up sequence. */
    gate->state  = (seed + increment) * multiplier + increment;
    gate->cutoff = ((uint64_t) chance_percent << 32U) / 100U;
}

/*
 * Advance the gate and report whether this event was selected. Zero and one
 * hundred percent are exact and do not advance the stream. For other values,
 * this is one 64-bit multiply/add, the PCG output permutation, and a compare.
 */
static inline bool nonCryptoPercentGateStep(noncrypto_percent_gate_t *gate)
{
    assert(gate != NULL);

    if (gate->cutoff == 0U)
    {
        return false;
    }
    if (gate->cutoff == (UINT64_C(1) << 32U))
    {
        return true;
    }

    const uint64_t old_state = gate->state;
    gate->state              = old_state * UINT64_C(6364136223846793005) + UINT64_C(1442695040888963407);

    const uint32_t xorshifted = (uint32_t) (((old_state >> 18U) ^ old_state) >> 27U);
    const uint32_t rotation   = (uint32_t) (old_state >> 59U);
    const uint32_t sample     = (xorshifted >> rotation) | (xorshifted << ((32U - rotation) & 31U));

    return (uint64_t) sample < gate->cutoff;
}

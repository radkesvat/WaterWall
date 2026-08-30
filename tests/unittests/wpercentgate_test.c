#include "wpercentgate.h"

#include <stdio.h>
#include <stdlib.h>

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "FAIL: %s\n", message);
        exit(1);
    }
}

static void caseBoundaryPercentages(void)
{
    noncrypto_percent_gate_t never_gate;
    noncrypto_percent_gate_t always_gate;

    nonCryptoPercentGateInit(&never_gate, 0U, 0U);
    nonCryptoPercentGateInit(&always_gate, 100U, UINT64_MAX);

    const uint64_t never_state  = never_gate.state;
    const uint64_t always_state = always_gate.state;

    for (size_t i = 0; i < 1024U; ++i)
    {
        require(! nonCryptoPercentGateStep(&never_gate), "zero-percent gate selected an event");
        require(nonCryptoPercentGateStep(&always_gate), "hundred-percent gate rejected an event");
    }

    require(never_gate.state == never_state, "zero-percent gate advanced its stream");
    require(always_gate.state == always_state, "hundred-percent gate advanced its stream");
}

static void caseSeededDeterminismAndIndependence(void)
{
    noncrypto_percent_gate_t first;
    noncrypto_percent_gate_t replay;
    noncrypto_percent_gate_t other;

    nonCryptoPercentGateInit(&first, 37U, 0U);
    nonCryptoPercentGateInit(&replay, 37U, 0U);
    nonCryptoPercentGateInit(&other, 37U, UINT64_C(0xfedcba9876543210));

    bool different_seed_diverged = false;
    for (size_t i = 0; i < 1024U; ++i)
    {
        const bool first_result  = nonCryptoPercentGateStep(&first);
        const bool replay_result = nonCryptoPercentGateStep(&replay);
        const bool other_result  = nonCryptoPercentGateStep(&other);

        require(first_result == replay_result, "equal seeds produced different gate sequences");
        different_seed_diverged |= first_result != other_result;
    }

    require(different_seed_diverged, "different seeds produced identical gate sequences");
    require(first.state == replay.state, "equal seeds finished with different PCG states");
}

static void caseKnownSequence(void)
{
    noncrypto_percent_gate_t gate;
    nonCryptoPercentGateInit(&gate, 70U, UINT64_C(0x4d595df4d0f33173));
    require(gate.cutoff == UINT64_C(3006477107), "70-percent gate cutoff was not precomputed correctly");

    uint64_t selected_bits = 0U;
    for (uint32_t i = 0; i < 64U; ++i)
    {
        if (nonCryptoPercentGateStep(&gate))
        {
            selected_bits |= UINT64_C(1) << i;
        }
    }

    require(selected_bits == UINT64_C(0x6af7fb620f974bd7), "PCG percentage-gate known sequence changed");
    require(gate.state == UINT64_C(0x699b883792bc0da9), "PCG percentage-gate final state changed");
}

static void caseRandomLikeRunsAndLongTermRate(void)
{
    noncrypto_percent_gate_t gate;
    nonCryptoPercentGateInit(&gate, 70U, UINT64_C(0xa02bdbf7bb3c0a7));

    size_t selected                 = 0U;
    bool   saw_consecutive_selected = false;
    bool   saw_consecutive_rejected = false;
    bool   previous                 = nonCryptoPercentGateStep(&gate);

    selected += previous ? 1U : 0U;
    for (size_t i = 1U; i < 1000000U; ++i)
    {
        const bool current = nonCryptoPercentGateStep(&gate);
        selected += current ? 1U : 0U;
        saw_consecutive_selected |= previous && current;
        saw_consecutive_rejected |= ! previous && ! current;
        previous = current;
    }

    require(saw_consecutive_selected, "gate did not produce consecutive selections");
    require(saw_consecutive_rejected, "gate did not produce consecutive rejections");
    require(selected >= 697000U && selected <= 703000U, "70-percent gate fell outside its long-term rate bound");
}

int main(void)
{
    caseBoundaryPercentages();
    caseSeededDeterminismAndIndependence();
    caseKnownSequence();
    caseRandomLikeRunsAndLongTermRate();

    puts("wpercentgate_test: PASS");
    return 0;
}

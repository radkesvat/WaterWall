#include "structure.h"

#include "loggers/network_logger.h"

static uint32_t disturberChancePercent(int chance_percent)
{
    if (chance_percent <= 0)
    {
        return 0;
    }
    if (chance_percent >= 100)
    {
        return 100;
    }
    return (uint32_t) chance_percent;
}

static void disturberPercentGateInitialize(noncrypto_percent_gate_t *gate, int chance_percent)
{
    const uint32_t chance = disturberChancePercent(chance_percent);
    const uint64_t seed   = chance == 0 || chance == 100 ? 0 : fastRand64();
    nonCryptoPercentGateInit(gate, chance, seed);
}

static void disturberDirectionLinestateInitialize(disturber_direction_lstate_t *dir_ls, const disturber_tstate_t *ts)
{
    *dir_ls = (disturber_direction_lstate_t) {0};

    disturberPercentGateInitialize(&dir_ls->instant_close_gate, ts->chance_instant_close);
    disturberPercentGateInitialize(&dir_ls->middle_close_gate, ts->chance_middle_close);
    disturberPercentGateInitialize(&dir_ls->payload_corruption_gate, ts->chance_payload_corruption);
    disturberPercentGateInitialize(&dir_ls->payload_loss_gate, ts->chance_payload_loss);
    disturberPercentGateInitialize(&dir_ls->payload_duplication_gate, ts->chance_payload_duplication);
    disturberPercentGateInitialize(&dir_ls->payload_out_of_order_gate, ts->chance_payload_out_of_order);
    disturberPercentGateInitialize(&dir_ls->payload_delay_gate, ts->chance_payload_delay);
    disturberPercentGateInitialize(&dir_ls->connection_deadhang_gate, ts->chance_connection_deadhang);
}

void disturberLinestateInitialize(disturber_lstate_t *ls, const disturber_tstate_t *ts)
{
    disturberDirectionLinestateInitialize(&ls->upstream, ts);
    disturberDirectionLinestateInitialize(&ls->downstream, ts);
}

void disturberLinestateDestroy(line_t *l, disturber_lstate_t *ls)
{
    if (UNLIKELY(l == NULL || ! lineIsOnCurrentEventWorker(l)))
    {
        LOGF("Disturber: line-state destruction ran outside its owner worker");
        abortProgramNow(1);
    }

    assert(l != NULL && lineIsOnCurrentEventWorker(l));

    if (ls->upstream.held_payload != NULL)
    {
        lineReuseBuffer(l, ls->upstream.held_payload);
        ls->upstream.held_payload = NULL;
    }
    if (ls->downstream.held_payload != NULL)
    {
        lineReuseBuffer(l, ls->downstream.held_payload);
        ls->downstream.held_payload = NULL;
    }
    memoryZeroAligned32(ls, tunnelGetCorrectAlignedLineStateSize(sizeof(disturber_lstate_t)));
}

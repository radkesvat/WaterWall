#include "structure.h"

#include "loggers/network_logger.h"

static bool ptcReceiveCreditFailureLocked(ptc_lstate_t *ls, const char *reason)
{
    LOGE("PacketsToConnection: invalid TCP receive-credit state (%s); resetting the flow", reason);

    struct tcp_pcb *pcb = ls->tcp_pcb;
    ptcDetachTcpPcbLocked(ls);
    if (pcb != NULL)
    {
        tcp_abort(pcb);
    }

    ls->rx_uncredited   = 0;
    ls->read_paused_len = 0;

    if (lineIsAlive(ls->line))
    {
        const line_task_submit_result_e result = lineScheduleTask(ls->line, ptcCloseLineTask, ls->tunnel, NULL);
        if (result == kLineTaskSubmitRejectedSettled)
        {
            discard ptcRequiredControlRefusedLocked(ls, "receive-credit failure close");
        }
        else
        {
            assert(result == kLineTaskSubmitAcceptedAsync);
        }
    }
    return false;
}

bool ptcReceiveCreditAccumulateLocked(ptc_lstate_t *ls, uint32_t amount)
{
    if (UNLIKELY(ls->kind != kPtcLineKindTcp || amount > UINT32_MAX - ls->rx_uncredited))
    {
        return ptcReceiveCreditFailureLocked(ls, "uncredited-byte overflow");
    }

    ls->rx_uncredited += amount;
    return true;
}

void ptcReceiveCreditRollbackLocked(ptc_lstate_t *ls, uint32_t amount)
{
    if (UNLIKELY(amount > ls->rx_uncredited))
    {
        discard ptcReceiveCreditFailureLocked(ls, "failed-delivery rollback underflow");
        return;
    }
    ls->rx_uncredited -= amount;
}

bool ptcPausedReadAccumulateLocked(ptc_lstate_t *ls, uint32_t amount)
{
    if (UNLIKELY(ls->kind != kPtcLineKindTcp || amount > UINT32_MAX - ls->read_paused_len))
    {
        return ptcReceiveCreditFailureLocked(ls, "paused-byte overflow");
    }

    const uint32_t paused = ls->read_paused_len + amount;
    if (UNLIKELY(paused > ls->rx_uncredited))
    {
        return ptcReceiveCreditFailureLocked(ls, "paused bytes exceed uncredited bytes");
    }

    ls->read_paused_len = paused;
    return true;
}

bool ptcReturnReceiveCreditLocked(ptc_lstate_t *ls, uint32_t amount)
{
    if (UNLIKELY(ls->kind != kPtcLineKindTcp || ls->tcp_pcb == NULL || amount > ls->rx_uncredited))
    {
        return ptcReceiveCreditFailureLocked(ls, "credit return underflow or detached PCB");
    }

    uint32_t remaining = amount;
    while (remaining > 0)
    {
        const uint16_t chunk = (uint16_t) min(remaining, (uint32_t) UINT16_MAX);
        tcp_recved(ls->tcp_pcb, chunk);
        remaining -= chunk;
    }

    ls->rx_uncredited -= amount;
    return true;
}

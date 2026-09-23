#include "structure.h"

#include "loggers/network_logger.h"

void tcplistenerLinestateInitialize(tcplistener_lstate_t *ls, wio_t *io, tunnel_t *t, line_t *l)
{
    ls->io               = io;
    ls->tunnel           = t;
    ls->line             = l;
    ls->idle_handle      = NULL;
    ls->active_write     = (buffer_budget_reservation_t) {0};
    ls->queue_pause_sent = false;
    ls->write_paused     = false;
    ls->read_paused      = false;
    ls->pause_queue      = bufferqueueCreate(kPauseQueueCapacity);
    bufferbudgetInit(&ls->write_budget, (buffer_budget_cost_t) {kMaxPauseQueueSize, kMaxPauseQueueSize, SIZE_MAX});
    const bool attached = bufferqueueTryAttachBudget(&ls->pause_queue, &ls->write_budget);
    assert(attached);
    discard attached;
}

void tcplistenerLinestateDestroy(tcplistener_lstate_t *ls)
{
    bufferqueueDestroy(&ls->pause_queue);
    bufferbudgetReservationRelease(&ls->active_write);
    bufferbudgetAssertEmpty(&ls->write_budget);
    if (ls->idle_handle)
    {
        LOGF("TcpListener: idle item still exists for FD:%x ", wioGetFD(ls->io));
        abortProgramNow(1);
    }
    memoryZeroAligned32(ls, tunnelGetCorrectAlignedLineStateSize(sizeof(tcplistener_lstate_t)));
}

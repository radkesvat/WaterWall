#include "structure.h"

#include "loggers/network_logger.h"

void tcpconnectorLinestateInitialize(tcpconnector_lstate_t *ls)
{
    ls->pause_queue       = bufferqueueCreate(kPauseQueueCapacity);
    ls->io                = NULL;
    ls->idle_handle       = NULL;
    ls->outbound_ip_range = 0;
    ls->socket_options    = (tcpconnector_socket_options_t) {0};
    ls->active_write      = (buffer_budget_reservation_t) {0};
    ls->queue_pause_sent  = false;
    ls->write_paused      = false;
    ls->read_paused       = false;
    bufferbudgetInit(&ls->write_budget, (buffer_budget_cost_t) {kMaxPauseQueueSize, kMaxPauseQueueSize, SIZE_MAX});
    const bool attached = bufferqueueTryAttachBudget(&ls->pause_queue, &ls->write_budget);
    assert(attached);
    discard attached;
}

void tcpconnectorLinestateDestroy(tcpconnector_lstate_t *ls)
{
    bufferqueueDestroy(&ls->pause_queue);
    bufferbudgetReservationRelease(&ls->active_write);
    bufferbudgetAssertEmpty(&ls->write_budget);
    if (ls->idle_handle)
    {
        LOGF("TcpConnector: idle item still exists for FD:%x ", wioGetFD(ls->io));
        abortProgramNow(1);
    }
    memoryZeroAligned32(ls, tunnelGetCorrectAlignedLineStateSize(sizeof(tcpconnector_lstate_t)));
}

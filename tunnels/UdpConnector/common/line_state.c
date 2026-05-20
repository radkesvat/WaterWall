#include "structure.h"

#include "loggers/network_logger.h"

void udpconnectorLinestateInitialize(udpconnector_lstate_t *ls, tunnel_t *t, line_t *l, wio_t *io)
{
    *ls = (udpconnector_lstate_t){
        .tunnel           = t,
        .line             = l,
        .io               = io,
        .dns_request      = NULL,
        .pause_queue      = bufferqueueCreate(kUdpPauseQueueCapacity),
        .established      = false,
        .read_paused      = false,
        .resolving        = false,
        .write_paused     = false,
        .queue_pause_sent = false,
    };

    if (io != NULL)
    {
        weventSetUserData(io, ls);
    }
}

void udpconnectorCancelDnsRequest(udpconnector_lstate_t *ls)
{
    if (ls->dns_request != NULL)
    {
        ls->dns_request->cancelled = true;
        ls->dns_request            = NULL;
    }
    ls->resolving = false;
}

void udpconnectorLinestateDestroy(udpconnector_lstate_t *ls)
{
    udpconnectorCancelDnsRequest(ls);
    bufferqueueDestroy(&ls->pause_queue);
    if (ls->idle_handle != NULL)
    {
        LOGF("UdpConnector: idle item still exists for FD:%x ", ls->io ? wioGetFD(ls->io) : -1);
        terminateProgram(1);
    }
    memoryZeroAligned32(ls, sizeof(udpconnector_lstate_t));
}

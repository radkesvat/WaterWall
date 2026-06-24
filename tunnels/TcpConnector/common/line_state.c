#include "structure.h"

#include "loggers/network_logger.h"

void tcpconnectorLinestateInitialize(tcpconnector_lstate_t *ls)
{
    ls->pause_queue       = bufferqueueCreate(kPauseQueueCapacity);
    ls->io                = NULL;
    ls->idle_handle       = NULL;
    ls->outbound_ip_range = 0;
    ls->socket_options    = (tcpconnector_socket_options_t) {0};
    ls->write_paused      = false;
    ls->read_paused       = false;
}

void tcpconnectorLinestateDestroy(tcpconnector_lstate_t *ls)
{
    bufferqueueDestroy(&ls->pause_queue);
    if (ls->idle_handle)
    {
        LOGF("TcpConnector: idle item still exists for FD:%x ", wioGetFD(ls->io));
        terminateProgram(1);
    }
    memoryZeroAligned32(ls, tunnelGetCorrectAlignedLineStateSize(sizeof(tcpconnector_lstate_t)));
}

void tcpconnectorDomainSetupLinestateInitialize(tcpconnector_domain_setup_lstate_t *ls)
{
    *ls = (tcpconnector_domain_setup_lstate_t) {0};
}

void tcpconnectorDomainSetupLinestateDestroy(tcpconnector_domain_setup_lstate_t *ls)
{
    memoryZeroAligned32(ls, tunnelGetCorrectAlignedLineStateSize(sizeof(tcpconnector_domain_setup_lstate_t)));
}

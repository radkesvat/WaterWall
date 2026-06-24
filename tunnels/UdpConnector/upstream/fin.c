#include "structure.h"

#include "loggers/network_logger.h"

void udpconnectorTunnelUpStreamFinish(tunnel_t *t, line_t *l)
{

    udpconnector_tstate_t *ts = tunnelGetState(t);
    udpconnector_lstate_t *ls = lineGetState(l, t);
    wio_t                 *io = ls->io;

    if (io == NULL)
    {
        udpconnectorLinestateDestroy(ls);
        return;
    }

    bool removed = localidletableRemoveIdleItemByHash(udpconnectorGetLineIdleTable(ts, l), udpconnectorIdleKey(ls->io));
    if (! removed)
    {
        LOGF("UdpConnector: failed to remove idle item for FD:%x ", wioGetFD(ls->io));
        terminateProgram(1);
    }
    ls->idle_handle = NULL; // mark as removed

    weventSetUserData(io, NULL);
    udpconnectorFlushWriteQueue(ls);
    udpconnectorLinestateDestroy(ls);
    wioClose(io);
}

void udpconnectorDomainSetupTunnelUpStreamFinish(tunnel_t *t, line_t *l)
{
    udpconnector_domain_setup_lstate_t *ls = lineGetState(l, t);

    udpconnectorDomainSetupLinestateDestroy(ls);
    tunnelNextUpStreamFinish(t, l);
}

void udpconnectorDomainSetupTunnelDownStreamFinish(tunnel_t *t, line_t *l)
{
    udpconnector_domain_setup_lstate_t *ls = lineGetState(l, t);

    udpconnectorDomainSetupLinestateDestroy(ls);
    tunnelPrevDownStreamFinish(t, l);
}

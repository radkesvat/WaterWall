#include "structure.h"

#include "loggers/network_logger.h"

static void kcpPrintLog(const char *log, struct IKCPCB *kcp, void *user)
{
    discard user;

    LOGD("TcpOverUdpServer -> KCP[%d]: %s", kcp->conv, log);
}

void tcpoverudpserverLinestateInitialize(tcpoverudpserver_lstate_t *ls, line_t *l, tunnel_t *t)
{
    // tcpoverudpserver_tstate_t *ts = tunnelGetState(t);

    // uint32_t new_session_id = atomicIncRelaxed(&ts->session_identifier);

    ikcpcb *k_handle = ikcp_create(0, ls);

    /* configuring the high-efficiency KCP settings */

    ikcp_setoutput(k_handle, tcpoverudpserverKUdpOutput);

    ikcp_nodelay(k_handle, kTcpOverUdpServerKcpNodelay, kTcpOverUdpServerKcpInterval, kTcpOverUdpServerKcpResend,
                 kTcpOverUdpServerKcpStream);

    ikcp_setmtu(k_handle, KCP_MTU);

    k_handle->writelog = kcpPrintLog;
    // k_handle->logmask = 0x0FFFFFFF; // Enable all logs

    k_handle->rx_minrto = 30;

    wtimer_t *k_timer = wtimerAdd(getWorkerLoop(lineGetWID(l)), tcpoverudpserverKcpLoopIntervalCallback,
                                  kTcpOverUdpServerKcpInterval, INFINITE);

    weventSetUserData(k_timer, ls);

    *ls = (tcpoverudpserver_lstate_t){
        .k_handle = k_handle, .k_timer = k_timer, .tunnel = t, .line = l, .write_paused = false, .can_upstream = true};
}

void tcpoverudpserverLinestateDestroy(tcpoverudpserver_lstate_t *ls)
{
    weventSetUserData(ls->k_timer, NULL);
    wtimerDelete(ls->k_timer);

    ikcp_release(ls->k_handle);
    memorySet(ls, 0, sizeof(tcpoverudpserver_lstate_t));
}

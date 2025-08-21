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
                 kTcpOverUdpServerKcpFlowCtl);

    ikcp_wndsize(k_handle, kTcpOverUdpServerKcpSendWindow, kTcpOverUdpServerKcpRecvWindow);

    ikcp_setmtu(k_handle, KCP_MTU);

    k_handle->cwnd = kTcpOverUdpServerKcpSendWindow / 4;

    k_handle->writelog = kcpPrintLog;
    // k_handle->logmask = 0x0FFFFFFF; // Enable all logs

    k_handle->rx_minrto = 30;

    wtimer_t *k_timer = wtimerAdd(getWorkerLoop(lineGetWID(l)), tcpoverudpserverKcpLoopIntervalCallback,
                                  kTcpOverUdpServerKcpInterval, INFINITE);

    weventSetUserData(k_timer, ls);

    *ls = (tcpoverudpserver_lstate_t) {.k_handle     = k_handle,
                                       .k_timer      = k_timer,
                                       .tunnel       = t,
                                       .line         = l,
                                       .last_recv    = wloopNowMS(getWorkerLoop(lineGetWID(l))),
                                       .cq_d         = contextqueueCreate(),
                                       .cq_u         = contextqueueCreate(),
                                       .write_paused = false,
                                       .can_upstream = true,
                                       .ping_sent    = true};

    uint8_t ping_buf[kFrameHeaderLength] = {kFrameFlagPing};
    ikcp_send(ls->k_handle, (const char *) ping_buf, (int) sizeof(ping_buf));
}

void tcpoverudpserverLinestateDestroy(tcpoverudpserver_lstate_t *ls)
{
    weventSetUserData(ls->k_timer, NULL);
    wtimerDelete(ls->k_timer);

    contextqueueDestroy(&ls->cq_u);
    contextqueueDestroy(&ls->cq_d);

    ikcp_release(ls->k_handle);
    memoryZeroAligned32(ls, sizeof(tcpoverudpserver_lstate_t));
}

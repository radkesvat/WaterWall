#include "structure.h"

#include "loggers/network_logger.h"

static void kcpPrintLog(const char *log, struct IKCPCB *kcp, void *user)
{
    discard user;

    LOGD("TcpOverUdpClient -> KCP[%d]: %s", kcp->conv, log);
}

void tcpoverudpclientLinestateInitialize(tcpoverudpclient_lstate_t *ls, line_t *l, tunnel_t *t)
{
    // tcpoverudpclient_tstate_t *ts = tunnelGetState(t);

    // uint32_t new_session_id = atomicIncRelaxed(&ts->session_identifier);

    ikcpcb *k_handle = ikcp_create(0, ls);

    /* configuring the high-efficiency KCP settings */

    ikcp_setoutput(k_handle, tcpoverudpclientKUdpOutput);

    ikcp_nodelay(k_handle, kTcpOverUdpClientKcpNodelay, kTcpOverUdpClientKcpInterval, kTcpOverUdpClientKcpResend,
                 kTcpOverUdpClientKcpFlowCtl);

    ikcp_wndsize(k_handle, kTcpOverUdpClientKcpSendWindow, kTcpOverUdpClientKcpRecvWindow);

    ikcp_setmtu(k_handle, KCP_MTU);

    k_handle->cwnd = kTcpOverUdpClientKcpSendWindow / 4;

    k_handle->writelog = kcpPrintLog;
    // k_handle->logmask = 0x0FFFFFFF; // Enable all logs

    k_handle->rx_minrto = 30;

    wtimer_t *k_timer = wtimerAdd(getWorkerLoop(lineGetWID(l)), tcpoverudpclientKcpLoopIntervalCallback,
                                  kTcpOverUdpClientKcpInterval, INFINITE);

    weventSetUserData(k_timer, ls);

    *ls = (tcpoverudpclient_lstate_t) {.k_handle       = k_handle,
                                       .k_timer        = k_timer,
                                       .tunnel         = t,
                                       .line           = l,
                                       .last_recv      = wloopNowMS(getWorkerLoop(lineGetWID(l))),
                                       .cq_d           = contextqueueCreate(),
                                       .cq_u           = contextqueueCreate(),
                                       .write_paused   = false,
                                       .can_downstream = true,
                                       .ping_sent      = true};

    uint8_t ping_buf[kFrameHeaderLength] = {kFrameFlagPing};
    ikcp_send(ls->k_handle, (const char *) ping_buf, (int) sizeof(ping_buf));
    // ikcp_update(k_handle, wloopNowMS(getWorkerLoop(lineGetWID(l))));
}

void tcpoverudpclientLinestateDestroy(tcpoverudpclient_lstate_t *ls)
{
    weventSetUserData(ls->k_timer, NULL);
    wtimerDelete(ls->k_timer);
    contextqueueDestroy(&ls->cq_u);
    contextqueueDestroy(&ls->cq_d);
    ikcp_release(ls->k_handle);
    memorySet(ls, 0, sizeof(tcpoverudpclient_lstate_t));
}

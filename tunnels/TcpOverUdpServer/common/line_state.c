#include "structure.h"

#include "loggers/network_logger.h"

static void kcpPrintLog(const char *log, struct IKCPCB *kcp, void *user)
{
    discard user;

    LOGD("TcpOverUdpServer -> KCP[%d]: %s", kcp->conv, log);
}

bool tcpoverudpserverLinestateInitialize(tcpoverudpserver_lstate_t *ls, line_t *l, tunnel_t *t)
{
    tcpoverudpserver_tstate_t *ts = tunnelGetState(t);

    // every resource is built in a local until all of them succeeded; a failing line therefore leaves the line state
    // zeroed, which is the same terminal shape tcpoverudpserverLinestateDestroy() produces.
    memoryZeroAligned32(ls, tunnelGetCorrectAlignedLineStateSize(sizeof(tcpoverudpserver_lstate_t)));

    ikcpcb *k_handle = ikcp_create(0, ls);
    if (k_handle == NULL)
    {
        LOGE("TcpOverUdpServer: failed to create the KCP handle for this line");
        return false;
    }

    /* configuring the high-efficiency KCP settings */

    ikcp_setoutput(k_handle, tcpoverudpserverKUdpOutput);

    ikcp_nodelay(
        k_handle, ts->kcp_nodelay ? 1 : 0, ts->kcp_interval_ms, ts->kcp_resend, ts->kcp_no_congestion_control ? 1 : 0);

    ikcp_wndsize(k_handle, ts->kcp_send_window, ts->kcp_recv_window);

    const int kcp_mtu       = tcpoverudpserverGetKcpMtu(ts);
    const int setmtu_result = ikcp_setmtu(k_handle, kcp_mtu);

    if (setmtu_result == -2)
    {
        // allocation failure of the KCP frame buffer, this is a per-line resource failure
        ikcp_release(k_handle);
        LOGE("TcpOverUdpServer: failed to allocate the KCP frame buffer for MTU %d", kcp_mtu);
        return false;
    }

    if (setmtu_result != 0)
    {
        // tunnel creation already rejected every MTU that KCP can refuse, so reaching this branch means the validated
        // tunnel state was corrupted or the KCP contract changed under us
        LOGF("TcpOverUdpServer: KCP rejected the validated MTU %d (result %d)", kcp_mtu, setmtu_result);
        abortProgramNow(1);
    }

    k_handle->cwnd = (IUINT32) ts->kcp_initial_cwnd;

    k_handle->writelog = kcpPrintLog;
    // k_handle->logmask = 0x0FFFFFFF; // Enable all logs

    k_handle->rx_minrto = (IINT32) ts->kcp_rx_minrto_ms;

    wtimer_t *k_timer = wtimerAdd(getWorkerLoop(lineGetWID(l)),
                                  tcpoverudpserverKcpLoopIntervalCallback,
                                  (uint32_t) ts->kcp_interval_ms,
                                  INFINITE);

    if (k_timer == NULL)
    {
        ikcp_release(k_handle);
        LOGE("TcpOverUdpServer: failed to create the KCP interval timer for this line");
        return false;
    }

    tcpoverudp_fec_encoder_t *fec_encoder = NULL;
    tcpoverudp_fec_decoder_t *fec_decoder = NULL;

    if (ts->fec_enabled)
    {
        fec_encoder = tcpoverudpFecEncoderCreate(ts->fec_data_shards, ts->fec_parity_shards);
        fec_decoder = tcpoverudpFecDecoderCreate(ts->fec_data_shards, ts->fec_parity_shards);

        if (fec_encoder == NULL || fec_decoder == NULL)
        {
            tcpoverudpFecEncoderDestroy(&fec_encoder);
            tcpoverudpFecDecoderDestroy(&fec_decoder);
            weventSetUserData(k_timer, NULL);
            wtimerDelete(k_timer);
            ikcp_release(k_handle);
            LOGE("TcpOverUdpServer: failed to initialize the FEC state for this line");
            return false;
        }
    }

    *ls = (tcpoverudpserver_lstate_t) {.k_handle     = k_handle,
                                       .k_timer      = k_timer,
                                       .fec_encoder  = fec_encoder,
                                       .fec_decoder  = fec_decoder,
                                       .tunnel       = t,
                                       .line         = l,
                                       .last_recv    = wloopNowMS(getWorkerLoop(lineGetWID(l))),
                                       .cq_d         = contextqueueCreate(),
                                       .cq_u         = contextqueueCreate(),
                                       .write_paused = false,
                                       .can_upstream = true,
                                       .ping_sent    = true};

    // published only after the line state is committed, so the timer callback can never observe a partial state
    weventSetUserData(k_timer, ls);

    uint8_t ping_buf[kFrameHeaderLength] = {kFrameFlagPing};
    ikcp_send(ls->k_handle, (const char *) ping_buf, (int) sizeof(ping_buf));

    return true;
}

void tcpoverudpserverLinestateDestroy(tcpoverudpserver_lstate_t *ls)
{
    assert(ls->k_handle != NULL && ls->k_timer != NULL);

    weventSetUserData(ls->k_timer, NULL);
    wtimerDelete(ls->k_timer);

    contextqueueDestroy(&ls->cq_u);
    contextqueueDestroy(&ls->cq_d);

    tcpoverudpFecEncoderDestroy(&ls->fec_encoder);
    tcpoverudpFecDecoderDestroy(&ls->fec_decoder);

    ikcp_release(ls->k_handle);

    memoryZeroAligned32(ls, tunnelGetCorrectAlignedLineStateSize(sizeof(tcpoverudpserver_lstate_t)));
}

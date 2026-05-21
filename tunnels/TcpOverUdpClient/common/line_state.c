#include "structure.h"

#include "loggers/network_logger.h"

static void kcpPrintLog(const char *log, struct IKCPCB *kcp, void *user)
{
    discard user;

    LOGD("TcpOverUdpClient -> KCP[%d]: %s", kcp->conv, log);
}

void tcpoverudpclientLinestateInitialize(tcpoverudpclient_lstate_t *ls, line_t *l, tunnel_t *t)
{
    tcpoverudpclient_tstate_t *ts = tunnelGetState(t);

    ikcpcb *k_handle = ikcp_create(0, ls);
    if (k_handle == NULL)
    {
        LOGF("TcpOverUdpClient: failed to create KCP handle");
        terminateProgram(1);
    }

    /* configuring the high-efficiency KCP settings */

    ikcp_setoutput(k_handle, tcpoverudpclientKUdpOutput);

    ikcp_nodelay(k_handle, ts->kcp_nodelay ? 1 : 0, ts->kcp_interval_ms, ts->kcp_resend,
                 ts->kcp_no_congestion_control ? 1 : 0);

    ikcp_wndsize(k_handle, ts->kcp_send_window, ts->kcp_recv_window);

    if (ikcp_setmtu(k_handle, tcpoverudpclientGetKcpMtu(ts)) != 0)
    {
        ikcp_release(k_handle);
        LOGF("TcpOverUdpClient: failed to set KCP MTU");
        terminateProgram(1);
    }

    k_handle->cwnd = (IUINT32) ts->kcp_initial_cwnd;

    k_handle->writelog = kcpPrintLog;
    // k_handle->logmask = 0x0FFFFFFF; // Enable all logs

    k_handle->rx_minrto = (IINT32) ts->kcp_rx_minrto_ms;

    wtimer_t *k_timer = wtimerAdd(getWorkerLoop(lineGetWID(l)), tcpoverudpclientKcpLoopIntervalCallback,
                                  (uint32_t) ts->kcp_interval_ms, INFINITE);

    weventSetUserData(k_timer, ls);

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
            LOGF("TcpOverUdpClient: failed to initialize FEC state");
            terminateProgram(1);
        }
    }

    *ls = (tcpoverudpclient_lstate_t) {.k_handle       = k_handle,
                                       .k_timer        = k_timer,
                                       .fec_encoder    = fec_encoder,
                                       .fec_decoder    = fec_decoder,
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
    if (ls->k_handle == NULL)
    {
        return;
    }

    if (ls->k_timer != NULL)
    {
        weventSetUserData(ls->k_timer, NULL);
        wtimerDelete(ls->k_timer);
    }

    contextqueueDestroy(&ls->cq_u);
    contextqueueDestroy(&ls->cq_d);

    tcpoverudpFecEncoderDestroy(&ls->fec_encoder);
    tcpoverudpFecDecoderDestroy(&ls->fec_decoder);

    if (ls->k_handle != NULL)
    {
        ikcp_release(ls->k_handle);
    }

    memoryZeroAligned32(ls, sizeof(tcpoverudpclient_lstate_t));
}

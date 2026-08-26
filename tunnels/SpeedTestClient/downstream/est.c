#include "structure.h"

#include "loggers/network_logger.h"

void speedtestclientTunnelDownStreamEst(tunnel_t *t, line_t *l)
{
    speedtestclient_tstate_t *state = tunnelGetState(t);
    speedtestclient_lstate_t *ls    = lineGetState(l, t);
    char                      target_buf[64];

    lineMarkEstablished(l);

    ls->est_received = true;
    if (state->target_bandwidth_bps == 0)
    {
        stringNPrintf(target_buf, sizeof(target_buf), "unlimited");
    }
    else
    {
        speedtestclientFormatBitrate((double) state->target_bandwidth_bps, target_buf, sizeof(target_buf));
    }

    LOGI("SpeedTestClient: stream %u established (%s, %s%s%s, target %s)",
         (unsigned int) ls->stream_id,
         state->mode == kSpeedTestClientModeUdp ? "udp" : "tcp",
         state->upload ? "upload" : "",
         (state->upload && state->download) ? "+" : "",
         state->download ? "download" : "",
         target_buf);

    /* A synchronous scheduling refusal closes this owned line. Keep the
     * allocation present across the first admission and stop before the
     * second scheduler reads destroyed lstate. */
    lineRef(l);
    if (state->upload)
    {
        speedtestclientScheduleSend(t, l, ls);
    }
    else if (! ls->hello_sent)
    {
        speedtestclientScheduleSend(t, l, ls);
    }
    if (! lineIsAlive(l))
    {
        lineUnref(l);
        return;
    }
    speedtestclientScheduleReport(t, l, ls);
    lineUnref(l);
}

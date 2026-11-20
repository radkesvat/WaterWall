#include "structure.h"

#include "loggers/network_logger.h"

void speedtestclientTunnelDownStreamEst(tunnel_t *t, line_t *l)
{
    speedtestclient_tstate_t *state = tunnelGetState(t);
    speedtestclient_lstate_t *ls    = lineGetState(l, t);
    char                      target_buf[64];

    lineMarkEstablished(l);

    if (ls->est_received)
    {
        return;
    }
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
}

#include "structure.h"

#include "loggers/network_logger.h"

void speedtestserverTunnelUpStreamFinish(tunnel_t *t, line_t *l)
{
    speedtestserver_lstate_t *ls = lineGetState(l, t);

    if (! ls->closing && ls->hello_received && ls->upload && ! ls->receiver_finished && speedtestserverLogsEnabled(t))
    {
        LOGW("SpeedTestServer: stream %u closed before upload END", (unsigned int) ls->stream_id);
    }
    speedtestserverLinestateDestroy(ls);
}

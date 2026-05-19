#include "structure.h"

#include "loggers/network_logger.h"

void disturberTunnelUpStreamInit(tunnel_t *t, line_t *l)
{
    disturber_tstate_t *ts = tunnelGetState(t);
    disturber_lstate_t *ls = lineGetState(l, t);

    disturberLinestateInitialize(ls);

    if (ts->disturb_upstream && roll100(ts->chance_instant_close))
    {
        LOGD("Disturber: Closing upstream direction instantly");
        if (! disturberIsWorkerPacketLine(t, l))
        {
            disturberLinestateDestroy(ls);
            tunnelPrevDownStreamFinish(t, l);
            return;
        }
        ls->upstream.is_deadhang = true;
        tunnelNextUpStreamInit(t, l);
        return;
    }

    tunnelNextUpStreamInit(t, l);
}

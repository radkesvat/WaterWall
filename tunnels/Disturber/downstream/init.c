#include "structure.h"

#include "loggers/network_logger.h"

void disturberTunnelDownStreamInit(tunnel_t *t, line_t *l)
{
    disturber_tstate_t *ts = tunnelGetState(t);
    disturber_lstate_t *ls = lineGetState(l, t);
    disturberLinestateInitialize(ls);

    if (ts->disturb_downstream && roll100(ts->chance_instant_close))
    {
        LOGD("Disturber: Closing downstream direction instantly");
        if (! disturberIsWorkerPacketLine(t, l))
        {
            disturberLinestateDestroy(ls);
            tunnelNextUpStreamFinish(t, l);
            return;
        }
        ls->downstream.is_deadhang = true;
        tunnelPrevDownStreamInit(t, l);
        return;
    }

    tunnelPrevDownStreamInit(t, l);
}

#include "structure.h"

#include "loggers/network_logger.h"

void disturberTunnelUpStreamFinish(tunnel_t *t, line_t *l)
{
    if (disturberIsWorkerPacketLine(t, l))
    {
        /* A packet line is persistent, but Disturber is a transparent middle
         * transform: settle retained bytes and propagate the directional close. */
        disturberPacketLineFinish(t, l, kDisturberPayloadDirectionUpstream);
        tunnelNextUpStreamFinish(t, l);
        return;
    }

    disturber_lstate_t *ls = lineGetState(l, t);
    disturberLinestateDestroy(l, ls);

    tunnelNextUpStreamFinish(t, l);
}

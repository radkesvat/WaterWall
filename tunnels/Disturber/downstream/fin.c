#include "structure.h"

#include "loggers/network_logger.h"

void disturberTunnelDownStreamFinish(tunnel_t *t, line_t *l)
{
    if (disturberIsWorkerPacketLine(t, l))
    {
        /* A packet line is persistent, but Disturber is a transparent middle
         * transform: settle retained bytes and propagate the directional close. */
        disturberPacketLineFinish(t, l, kDisturberPayloadDirectionDownstream);
        tunnelPrevDownStreamFinish(t, l);
        return;
    }

    disturber_lstate_t *ls = lineGetState(l, t);
    disturberLinestateDestroy(l, ls);

    tunnelPrevDownStreamFinish(t, l);
}

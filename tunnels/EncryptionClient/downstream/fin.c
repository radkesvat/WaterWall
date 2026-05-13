#include "structure.h"

#include "loggers/network_logger.h"

void encryptionclientTunnelDownStreamFinish(tunnel_t *t, line_t *l)
{
    lineLock(l);

    encryptionclient_lstate_t *ls = lineGetState(l, t);
    bool send_prev = ! ls->prev_finished;

    ls->prev_finished = true;
    encryptionclientLinestateDestroy(ls);

    if (send_prev)
    {
        tunnelPrevDownStreamFinish(t, l);
    }

    lineUnlock(l);
}

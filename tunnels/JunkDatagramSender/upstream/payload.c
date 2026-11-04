#include "structure.h"

#include "loggers/network_logger.h"

void junkdatagramsenderTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    junkdatagramsender_lstate_t *ls = lineGetState(l, t);
    if (! junkdatagramsenderCanPublish(ls, kJunkDatagramSenderDirectionUpstream))
    {
        lineReuseBuffer(l, buf);
        return;
    }
    if (ls->remaining_resend_again_times > 0)
    {
        buffer_pool_t *pool = lineGetBufferPool(l);

        ls->remaining_resend_again_times--;

        lineRef(l);
        bool can_publish = junkdatagramsenderSendJunk(t, l, kJunkDatagramSenderDirectionUpstream);
        if (! lineIsAlive(l) || ! can_publish)
        {
            lineUnref(l);
            bufferpoolReuseBuffer(pool, buf);
            return;
        }
        lineUnref(l);
    }

    tunnelNextUpStreamPayload(t, l, buf);
}

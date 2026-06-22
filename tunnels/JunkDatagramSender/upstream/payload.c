#include "structure.h"

#include "loggers/network_logger.h"

void junkdatagramsenderTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    junkdatagramsender_lstate_t *ls = lineGetState(l, t);
    if (ls->remaining_resend_again_times > 0)
    {
        buffer_pool_t *pool = lineGetBufferPool(l);

        ls->remaining_resend_again_times--;

        lineLock(l);
        bool alive = junkdatagramsenderSendJunk(t, l, kJunkDatagramSenderDirectionUpstream);
        if (! alive || ! lineIsAlive(l))
        {
            lineUnlock(l);
            bufferpoolReuseBuffer(pool, buf);
            return;
        }
        lineUnlock(l);
    }

    tunnelNextUpStreamPayload(t, l, buf);
}

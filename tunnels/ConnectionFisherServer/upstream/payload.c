#include "structure.h"

#include "loggers/network_logger.h"

void connectionfisherserverHandleHandshakePayload(tunnel_t *t, line_t *l, sbuf_t *buf);

void connectionfisherserverTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    connectionfisherserver_lstate_t *ls = lineGetState(l, t);

    if (ls->phase == kConnectionFisherServerPhaseEstablished)
    {
        tunnelNextUpStreamPayload(t, l, buf);
        return;
    }

    if (ls->phase == kConnectionFisherServerPhaseWaitPayload)
    {
        buffer_pool_t *pool = lineGetBufferPool(l);

        ls->next_init_sent = true;

        if (! withLineLocked(l, tunnelNextUpStreamInit, t))
        {
            bufferpoolReuseBuffer(pool, buf);
            return;
        }

        ls = lineGetState(l, t);
        ls->phase = kConnectionFisherServerPhaseEstablished;

        if (! withLineLockedWithBuf(l, tunnelNextUpStreamPayload, t, buf))
        {
            return;
        }
        return;
    }

    connectionfisherserverHandleHandshakePayload(t, l, buf);
}

#include "structure.h"

void connectionfisherserverTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    connectionfisherserver_lstate_t *ls = lineGetState(l, t);
    if (UNLIKELY(ls->phase == kConnectionFisherServerPhaseClosing))
    {
        lineReuseBuffer(l, buf);
        return;
    }
    if (ls->phase == kConnectionFisherServerPhaseEstablished && ! ls->dispatching)
    {
        tunnelNextUpStreamPayload(t, l, buf);
        return;
    }
    if (UNLIKELY(sbufGetLength(buf) == 0))
    {
        lineReuseBuffer(l, buf);
        return;
    }
    if (UNLIKELY(sbufGetLength(buf) > kConnectionFisherServerMaxPendingBytes - ls->init_payload_bytes -
                                          bufferqueueGetBufLen(&ls->pending_up) ||
                 ! bufferqueueTryPushBack(&ls->pending_up, &buf)))
    {
        lineReuseBuffer(l, buf);
        connectionfisherserverCloseLineFromProtocolError(t, l);
        return;
    }
    if (ls->dispatching)
        return;

    lineRef(l);
    ls->dispatching     = true;
    buffer_pool_t *pool = lineGetBufferPool(l);
    while (lineIsAlive(l) && ls->phase != kConnectionFisherServerPhaseClosing &&
           (buf = bufferqueuePopFront(&ls->pending_up)) != NULL)
    {
        if (ls->phase == kConnectionFisherServerPhaseWaitPing)
        {
            connectionfisherserverHandleHandshakePayload(t, l, buf);
            continue;
        }
        if (ls->phase == kConnectionFisherServerPhaseWaitPayload)
        {
            /* Publish the continuing route before synchronous Est/data from Init.
             * buf is older than every reentrant input in pending_up. */
            ls->phase              = kConnectionFisherServerPhaseEstablished;
            ls->next_init_sent     = true;
            ls->init_payload_bytes = sbufGetLength(buf);
            tunnelNextUpStreamInit(t, l);
            if (UNLIKELY(! lineIsAlive(l) || ls->phase == kConnectionFisherServerPhaseClosing))
            {
                bufferpoolReuseBuffer(pool, buf);
                break;
            }
        }
        ls->init_payload_bytes = 0;
        tunnelNextUpStreamPayload(t, l, buf);
    }
    if (lineIsAlive(l) && ls->phase != kConnectionFisherServerPhaseClosing)
        ls->dispatching = false;
    lineUnref(l);
}

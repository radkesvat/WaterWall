#include "loggers/network_logger.h"
#include "structure.h"

void connectionfisherserverTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    connectionfisherserver_lstate_t *ls = lineGetState(l, t);
    if (UNLIKELY(ls->phase == kConnectionFisherServerPhaseClosing))
    {
        lineReuseBuffer(l, buf);
        return;
    }
    if (UNLIKELY(sbufGetLength(buf) == 0))
    {
        lineReuseBuffer(l, buf);
        return;
    }
    const size_t handshake_bytes =
        ls->phase == kConnectionFisherServerPhaseWaitPing ? kConnectionFisherServerHandshakeLength : 0;
    const size_t retained_bytes =
        ls->init_payload_bytes + bufferqueueGetLength(&ls->pending_up) + bufferstreamGetLength(&ls->in_stream);
    const size_t retained_charge =
        ls->init_payload_charge + bufferqueueGetCharge(&ls->pending_up) + bufferstreamGetCharge(&ls->in_stream);
    if (UNLIKELY(sbufGetLength(buf) > kConnectionFisherServerMaxPendingBytes + handshake_bytes - retained_bytes ||
                 retained_charge > kConnectionFisherServerMaxPendingCharge ||
                 sbufGetQueueCharge(buf) > kConnectionFisherServerMaxPendingCharge - retained_charge ||
                 ! bufferqueueTryPushBack(&ls->pending_up, &buf)))
    {
        const size_t incoming_bytes  = sbufGetLength(buf);
        const size_t incoming_charge = sbufGetQueueCharge(buf);
        const size_t limit           = kConnectionFisherServerMaxPendingBytes + handshake_bytes;
        LOGW("ConnectionFisherServer: closing connection: pending input %s "
             "(retained_bytes=%zu, incoming_bytes=%zu, byte_limit=%zu, retained_charge_bytes=%zu, "
             "incoming_charge_bytes=%zu, charge_limit_bytes=%u)",
             incoming_bytes > limit - retained_bytes ? "byte limit exceeded"
             : retained_charge > kConnectionFisherServerMaxPendingCharge ||
                     incoming_charge > kConnectionFisherServerMaxPendingCharge - retained_charge
                 ? "storage charge limit exceeded"
                 : "queue admission failed",
             retained_bytes,
             incoming_bytes,
             limit,
             retained_charge,
             incoming_charge,
             (unsigned) kConnectionFisherServerMaxPendingCharge);
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
            ls->init_payload_bytes = sbufGetLength(buf);
            ls->init_payload_charge = sbufGetQueueCharge(buf);
            tunnelNextUpStreamInit(t, l);
            if (UNLIKELY(! lineIsAlive(l) || ls->phase == kConnectionFisherServerPhaseClosing))
            {
                bufferpoolReuseBuffer(pool, buf);
                break;
            }
            if (ls->pending_next_pause)
            {
                ls->pending_next_pause = false;
                tunnelNextUpStreamPause(t, l);
                if (UNLIKELY(! lineIsAlive(l) || ls->phase == kConnectionFisherServerPhaseClosing))
                {
                    bufferpoolReuseBuffer(pool, buf);
                    break;
                }
            }
        }
        ls->init_payload_bytes = 0;
        ls->init_payload_charge = 0;
        tunnelNextUpStreamPayload(t, l, buf);
    }
    if (lineIsAlive(l) && ls->phase != kConnectionFisherServerPhaseClosing)
    {
        ls->dispatching = false;
        if (ls->phase == kConnectionFisherServerPhaseEstablished)
        {
            connectionfisherserverLinestateDestroy(ls);
            tunnelBypassLine(t, l);
        }
    }
    lineUnref(l);
}

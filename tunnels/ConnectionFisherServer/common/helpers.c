#include "structure.h"

#include "loggers/network_logger.h"

static const uint8_t kConnectionFisherServerPing[kConnectionFisherServerHandshakeLength]  = {'F', 'I', 'S', 'H', '?'};
static const uint8_t kConnectionFisherServerReply[kConnectionFisherServerHandshakeLength] = {'F', 'I', 'S', 'H', '!'};

static sbuf_t *connectionfisherserverMakeReply(line_t *l)
{
    sbuf_t *buf = bufferpoolGetSmallBuffer(lineGetBufferPool(l));

    sbufSetLength(buf, kConnectionFisherServerHandshakeLength);
    memoryCopy(sbufGetMutablePtr(buf), kConnectionFisherServerReply, kConnectionFisherServerHandshakeLength);

    return buf;
}

void connectionfisherserverCloseLineFromUpstream(tunnel_t *t, line_t *l)
{
    connectionfisherserver_lstate_t *ls = lineGetState(l, t);
    if (ls->phase == kConnectionFisherServerPhaseClosing)
        return;
    const bool close_next = ls->phase == kConnectionFisherServerPhaseEstablished;
    connectionfisherserverLinestateDestroy(ls);

    if (close_next)
    {
        tunnelNextUpStreamFinish(t, l);
    }
}

void connectionfisherserverCloseLineFromDownstream(tunnel_t *t, line_t *l)
{
    connectionfisherserver_lstate_t *ls = lineGetState(l, t);
    if (ls->phase == kConnectionFisherServerPhaseClosing)
        return;
    connectionfisherserverLinestateDestroy(ls);
    tunnelPrevDownStreamFinish(t, l);
}

void connectionfisherserverCloseLineFromProtocolError(tunnel_t *t, line_t *l)
{
    connectionfisherserver_lstate_t *ls = lineGetState(l, t);
    if (ls->phase == kConnectionFisherServerPhaseClosing)
        return;
    const bool close_next = ls->phase == kConnectionFisherServerPhaseEstablished;
    lineRef(l);
    connectionfisherserverLinestateDestroy(ls);
    if (close_next)
        tunnelNextUpStreamFinish(t, l);
    if (lineIsAlive(l))
        tunnelPrevDownStreamFinish(t, l);
    lineUnref(l);
}

void connectionfisherserverHandleHandshakePayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    connectionfisherserver_lstate_t *ls = lineGetState(l, t);

    buf = sbufEnsureOrdinary(lineGetBufferPool(l), buf);
    bufferstreamPush(&ls->in_stream, buf);

    if (bufferstreamGetBufLen(&ls->in_stream) < kConnectionFisherServerHandshakeLength)
    {
        return;
    }

    sbuf_t    *ping = bufferstreamReadExact(&ls->in_stream, kConnectionFisherServerHandshakeLength);
    const bool valid =
        memoryCompare(sbufGetRawPtr(ping), kConnectionFisherServerPing, kConnectionFisherServerHandshakeLength) == 0;

    lineReuseBuffer(l, ping);

    if (! valid)
    {
        LOGW("ConnectionFisherServer: received bytes that do not match the ConnectionFisher client probe");
        connectionfisherserverCloseLineFromProtocolError(t, l);
        return;
    }

    /* Publish the older body before replying: FISH! may synchronously cause
     * application input, and next Init may emit Est with more nested input. */
    if (! bufferstreamIsEmpty(&ls->in_stream))
    {
        sbuf_t *extra = bufferstreamFullRead(&ls->in_stream);
        /* No callback ran during handshake parsing; this ordinary tail is the
         * sole entry, and its allocated capacity has a representable charge. */
        assert(bufferqueueGetBufCount(&ls->pending_up) == 0);
        bufferqueuePushFront(&ls->pending_up, extra);
    }
    connectionfisherserverRetireReadStream(ls);
    ls->phase = kConnectionFisherServerPhaseWaitPayload;
    tunnelPrevDownStreamPayload(t, l, connectionfisherserverMakeReply(l));
}

#include "structure.h"

#include "loggers/network_logger.h"

static const uint8_t kConnectionFisherServerPing[kConnectionFisherServerHandshakeLength]  = {'F', 'I', 'S', 'H', '?'};
static const uint8_t kConnectionFisherServerReply[kConnectionFisherServerHandshakeLength] = {'F', 'I', 'S', 'H', '!'};

static bool connectionfisherserverReadMatches(const sbuf_t *buf, const uint8_t *expected)
{
    if (sbufGetLength(buf) != kConnectionFisherServerHandshakeLength)
    {
        return false;
    }

    return memoryCompare(sbufGetRawPtr(buf), expected, kConnectionFisherServerHandshakeLength) == 0;
}

static sbuf_t *connectionfisherserverMakeReply(line_t *l)
{
    sbuf_t *buf = bufferpoolGetSmallBuffer(lineGetBufferPool(l));

    sbufSetLength(buf, kConnectionFisherServerHandshakeLength);
    memoryCopy(sbufGetMutablePtr(buf), kConnectionFisherServerReply, kConnectionFisherServerHandshakeLength);

    return buf;
}

void connectionfisherserverCloseLineFromUpstream(tunnel_t *t, line_t *l)
{
    connectionfisherserver_lstate_t *ls         = lineGetState(l, t);
    bool                             close_next = ls->next_init_sent;

    if (ls->phase == kConnectionFisherServerPhaseClosing)
        return;
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
    bool close_next = ls->next_init_sent;
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

    bufferstreamPush(&ls->in_stream, buf);

    if (bufferstreamGetBufLen(&ls->in_stream) > kConnectionFisherServerMaxHandshakeBytes)
    {
        LOGW("ConnectionFisherServer: handshake buffer overflow, closing line");
        connectionfisherserverCloseLineFromProtocolError(t, l);
        return;
    }

    if (bufferstreamGetBufLen(&ls->in_stream) < kConnectionFisherServerHandshakeLength)
    {
        return;
    }

    sbuf_t *ping  = bufferstreamReadExact(&ls->in_stream, kConnectionFisherServerHandshakeLength);
    bool    valid = connectionfisherserverReadMatches(ping, kConnectionFisherServerPing);

    lineReuseBuffer(l, ping);

    if (! valid)
    {
        LOGW("ConnectionFisherServer: received bytes that do not match the ConnectionFisher client probe");
        bufferstreamEmpty(&ls->in_stream);
        connectionfisherserverCloseLineFromProtocolError(t, l);
        return;
    }

    /* Publish the older body before replying: FISH! may synchronously cause
     * application input, and next Init may emit Est with more nested input. */
    if (! bufferstreamIsEmpty(&ls->in_stream))
    {
        sbuf_t *extra = bufferstreamFullRead(&ls->in_stream);
        if (UNLIKELY(! bufferqueueTryPushFront(&ls->pending_up, &extra)))
        {
            lineReuseBuffer(l, extra);
            connectionfisherserverCloseLineFromProtocolError(t, l);
            return;
        }
    }
    ls->phase = kConnectionFisherServerPhaseWaitPayload;
    tunnelPrevDownStreamPayload(t, l, connectionfisherserverMakeReply(l));
}

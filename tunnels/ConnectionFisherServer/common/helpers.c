#include "structure.h"

#include "loggers/network_logger.h"

static const uint8_t kConnectionFisherServerPing[kConnectionFisherServerHandshakeLength]  = {'F', 'I', 'S', 'H', '?'};
static const uint8_t kConnectionFisherServerReply[kConnectionFisherServerHandshakeLength] = {'F', 'I', 'S', 'H', '!'};

static bool connectionfisherserverEnsureNextInit(tunnel_t *t, line_t *l, connectionfisherserver_lstate_t *ls)
{
    if (ls->next_init_sent)
    {
        return true;
    }

    ls->next_init_sent = true;
    if (! withLineLocked(l, tunnelNextUpStreamInit, t))
    {
        return false;
    }

    ls = lineGetState(l, t);
    if (ls->phase == kConnectionFisherServerPhaseWaitPayload)
    {
        ls->phase = kConnectionFisherServerPhaseEstablished;
    }

    return true;
}

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
    lineLock(l);

    connectionfisherserver_lstate_t *ls = lineGetState(l, t);
    if (ls->phase == kConnectionFisherServerPhaseNone)
    {
        lineUnlock(l);
        return;
    }

    bool close_next = ls->next_init_sent;

    connectionfisherserverLinestateDestroy(ls);

    if (close_next)
    {
        tunnelNextUpStreamFinish(t, l);
    }

    lineUnlock(l);
}

void connectionfisherserverCloseLineFromDownstream(tunnel_t *t, line_t *l)
{
    lineLock(l);

    connectionfisherserver_lstate_t *ls = lineGetState(l, t);
    if (ls->phase == kConnectionFisherServerPhaseNone)
    {
        lineUnlock(l);
        return;
    }

    connectionfisherserverLinestateDestroy(ls);

    tunnelPrevDownStreamFinish(t, l);

    lineUnlock(l);
}

void connectionfisherserverHandleHandshakePayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    connectionfisherserver_lstate_t *ls = lineGetState(l, t);

    bufferstreamPush(&ls->in_stream, buf);

    if (bufferstreamGetBufLen(&ls->in_stream) > kConnectionFisherServerMaxHandshakeBytes)
    {
        LOGW("ConnectionFisherServer: handshake buffer overflow, closing line");
        connectionfisherserverCloseLineFromUpstream(t, l);
        return;
    }

    if (bufferstreamGetBufLen(&ls->in_stream) < kConnectionFisherServerHandshakeLength)
    {
        return;
    }

    sbuf_t *ping = bufferstreamReadExact(&ls->in_stream, kConnectionFisherServerHandshakeLength);
    bool    valid = connectionfisherserverReadMatches(ping, kConnectionFisherServerPing);

    lineReuseBuffer(l, ping);

    if (! valid)
    {
        LOGW("ConnectionFisherServer: received bytes that do not match the ConnectionFisher client probe");
        bufferstreamEmpty(&ls->in_stream);
        connectionfisherserverCloseLineFromUpstream(t, l);
        return;
    }

    ls->phase = kConnectionFisherServerPhaseWaitPayload;

    if (! withLineLockedWithBuf(l, tunnelPrevDownStreamPayload, t, connectionfisherserverMakeReply(l)))
    {
        return;
    }

    if (! bufferstreamIsEmpty(&ls->in_stream))
    {
        if (! connectionfisherserverEnsureNextInit(t, l, ls))
        {
            return;
        }

        ls = lineGetState(l, t);
        sbuf_t *extra = bufferstreamFullRead(&ls->in_stream);
        if (extra != NULL && ! withLineLockedWithBuf(l, tunnelNextUpStreamPayload, t, extra))
        {
            return;
        }
    }
}

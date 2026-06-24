#include "structure.h"

#include "loggers/network_logger.h"

static const uint8_t kConnectionFisherClientPing[kConnectionFisherHandshakeLength]   = {'F', 'I', 'S', 'H', '?'};
static const uint8_t kConnectionFisherClientReply[kConnectionFisherHandshakeLength]  = {'F', 'I', 'S', 'H', '!'};

static bool connectionfisherclientReadMatches(const sbuf_t *buf, const uint8_t *expected)
{
    if (sbufGetLength(buf) != kConnectionFisherHandshakeLength)
    {
        return false;
    }

    return memoryCompare(sbufGetRawPtr(buf), expected, kConnectionFisherHandshakeLength) == 0;
}

bool connectionfisherclientSendPing(tunnel_t *t, line_t *child_l)
{
    sbuf_t *buf = bufferpoolGetSmallBuffer(lineGetBufferPool(child_l));

    sbufSetLength(buf, kConnectionFisherHandshakeLength);
    memoryCopy(sbufGetMutablePtr(buf), kConnectionFisherClientPing, kConnectionFisherHandshakeLength);

    return withLineLockedWithBuf(child_l, tunnelNextUpStreamPayload, t, buf);
}

bool connectionfisherclientFlushPendingToSelected(tunnel_t *t, line_t *main_l, line_t *child_l)
{
    connectionfisherclient_lstate_t *main_ls = lineGetState(main_l, t);

    while (bufferqueueGetBufCount(&main_ls->pending_up) > 0)
    {
        sbuf_t *buf = bufferqueuePopFront(&main_ls->pending_up);
        if (! withLineLockedWithBuf(child_l, tunnelNextUpStreamPayload, t, buf))
        {
            return false;
        }

        if (! lineIsAlive(main_l))
        {
            return false;
        }
    }

    return true;
}

static void connectionfisherclientCloseMainLineInternal(tunnel_t *t, line_t *main_l, bool send_downstream_finish)
{
    if (! lineIsAlive(main_l))
    {
        return;
    }

    lineLock(main_l);

    connectionfisherclient_lstate_t *main_ls = lineGetState(main_l, t);
    if (main_ls->role != kConnectionFisherClientRoleMain)
    {
        lineUnlock(main_l);
        return;
    }

    line_t  **children   = main_ls->child_lines;
    uint32_t child_count = main_ls->child_count;

    main_ls->child_lines      = NULL;
    main_ls->child_count      = 0;
    main_ls->open_child_count = 0;
    main_ls->selected_child   = NULL;

    connectionfisherclientLinestateDestroyMain(main_ls);

    if (children != NULL)
    {
        for (uint32_t i = 0; i < child_count; ++i)
        {
            if (children[i] != NULL && lineIsAlive(children[i]))
            {
                connectionfisherclientCloseChildLine(t, children[i], false);
            }
        }

        memoryFree(children);
    }

    if (send_downstream_finish && lineIsAlive(main_l))
    {
        tunnelPrevDownStreamFinish(t, main_l);
    }

    lineUnlock(main_l);
}

void connectionfisherclientCloseMainLine(tunnel_t *t, line_t *main_l)
{
    connectionfisherclientCloseMainLineInternal(t, main_l, true);
}

void connectionfisherclientCloseMainLineFromUpstream(tunnel_t *t, line_t *main_l)
{
    connectionfisherclientCloseMainLineInternal(t, main_l, false);
}

static void connectionfisherclientCloseChildLineInternal(tunnel_t *t, line_t *child_l, bool force_close_main,
                                                         bool send_upstream_finish)
{
    if (! lineIsAlive(child_l))
    {
        return;
    }

    lineLock(child_l);

    connectionfisherclient_lstate_t *child_ls = lineGetState(child_l, t);
    if (child_ls->role != kConnectionFisherClientRoleChild)
    {
        lineUnlock(child_l);
        return;
    }

    line_t   *main_l            = child_ls->main_line;
    uint32_t  child_slot        = child_ls->child_slot;
    bool      should_close_main = force_close_main;

    if (main_l != NULL)
    {
        connectionfisherclient_lstate_t *main_ls = lineGetState(main_l, t);

        if (main_ls->role == kConnectionFisherClientRoleMain)
        {
            if (child_slot < main_ls->child_count && main_ls->child_lines[child_slot] == child_l)
            {
                main_ls->child_lines[child_slot] = NULL;
                if (main_ls->open_child_count > 0)
                {
                    main_ls->open_child_count -= 1;
                }
            }

            if (main_ls->selected_child == child_l)
            {
                main_ls->selected_child = NULL;
                should_close_main       = true;
            }
            else if (! should_close_main && main_ls->selected_child == NULL && main_ls->open_child_count == 0)
            {
                should_close_main = true;
            }
        }
    }

    connectionfisherclientLinestateDestroyChild(child_ls);
    if (send_upstream_finish)
    {
        tunnelNextUpStreamFinish(t, child_l);
    }
    if (lineIsAlive(child_l))
    {
        lineDestroy(child_l);
    }
    lineUnlock(child_l);

    if (should_close_main && main_l != NULL && lineIsAlive(main_l))
    {
        connectionfisherclientCloseMainLine(t, main_l);
    }

    if (main_l != NULL)
    {
        lineUnlock(main_l);
    }
}

void connectionfisherclientCloseChildLine(tunnel_t *t, line_t *child_l, bool force_close_main)
{
    connectionfisherclientCloseChildLineInternal(t, child_l, force_close_main, true);
}

void connectionfisherclientCloseChildLineFromDownstream(tunnel_t *t, line_t *child_l, bool force_close_main)
{
    connectionfisherclientCloseChildLineInternal(t, child_l, force_close_main, false);
}

bool connectionfisherclientSelectChild(tunnel_t *t, line_t *child_l)
{
    connectionfisherclient_lstate_t *child_ls = lineGetState(child_l, t);
    line_t                          *main_l   = child_ls->main_line;

    if (main_l == NULL || ! lineIsAlive(main_l))
    {
        connectionfisherclientCloseChildLine(t, child_l, false);
        return false;
    }

    connectionfisherclient_lstate_t *main_ls = lineGetState(main_l, t);
    if (main_ls->role != kConnectionFisherClientRoleMain)
    {
        connectionfisherclientCloseChildLine(t, child_l, false);
        return false;
    }

    if (main_ls->selected_child != NULL && main_ls->selected_child != child_l)
    {
        connectionfisherclientCloseChildLine(t, child_l, false);
        return false;
    }

    line_t  **losers     = NULL;
    uint32_t loser_count = 0;

    if (main_ls->selected_child == NULL)
    {
        if (main_ls->child_count > 1)
        {
            losers = memoryAllocate(sizeof(line_t *) * (main_ls->child_count - 1));
        }

        main_ls->selected_child = child_l;

        for (uint32_t i = 0; i < main_ls->child_count; ++i)
        {
            line_t *candidate = main_ls->child_lines[i];

            if (candidate == NULL || candidate == child_l)
            {
                continue;
            }

            losers[loser_count++]   = candidate;
            main_ls->child_lines[i] = NULL;
        }

        main_ls->open_child_count = 1;

        if (lineIsEstablished(child_l) && ! main_ls->main_est_forwarded)
        {
            main_ls->main_est_forwarded = true;

 

            if (! withLineLocked(main_l, tunnelPrevDownStreamEst, t))
            {
                if (losers != NULL)
                {
                    memoryFree(losers);
                }
                return false;
            }
        }
    }

    for (uint32_t i = 0; i < loser_count; ++i)
    {
        if (lineIsAlive(losers[i]))
        {
            connectionfisherclientCloseChildLine(t, losers[i], false);

            if (! lineIsAlive(main_l))
            {
                memoryFree(losers);
                return false;
            }
        }
    }

    if (losers != NULL)
    {
        memoryFree(losers);
    }

    if (! connectionfisherclientFlushPendingToSelected(t, main_l, child_l))
    {
        return false;
    }

    if (! lineIsAlive(main_l))
    {
        return false;
    }

    child_ls = lineGetState(child_l, t);
    if (child_ls->role != kConnectionFisherClientRoleChild)
    {
        return false;
    }

    if (! bufferstreamIsEmpty(&child_ls->read_stream))
    {
        sbuf_t *extra = bufferstreamFullRead(&child_ls->read_stream);

        if (extra != NULL && ! withLineLockedWithBuf(main_l, tunnelPrevDownStreamPayload, t, extra))
        {
            return false;
        }
    }

    return true;
}

void connectionfisherclientTimeoutTask(tunnel_t *t, line_t *main_l)
{
    connectionfisherclient_lstate_t *main_ls = lineGetState(main_l, t);

    if (main_ls->role != kConnectionFisherClientRoleMain)
    {
        return;
    }

    if (main_ls->selected_child != NULL)
    {
        return;
    }

    LOGW("ConnectionFisherClient: timed out waiting for a valid child line after %u ms",
         (unsigned int) kConnectionFisherTimeoutMs);
    connectionfisherclientCloseMainLine(t, main_l);
}

void connectionfisherclientHandleChildHandshakePayload(tunnel_t *t, line_t *child_l, sbuf_t *buf)
{
    connectionfisherclient_lstate_t *child_ls = lineGetState(child_l, t);

    bufferstreamPush(&child_ls->read_stream, buf);

    if (bufferstreamGetBufLen(&child_ls->read_stream) > kConnectionFisherMaxHandshakeBytes)
    {
        LOGW("ConnectionFisherClient: handshake buffer overflow on child line, closing the main line");
        connectionfisherclientCloseChildLine(t, child_l, true);
        return;
    }

    if (bufferstreamGetBufLen(&child_ls->read_stream) < kConnectionFisherHandshakeLength)
    {
        return;
    }

    sbuf_t *reply = bufferstreamReadExact(&child_ls->read_stream, kConnectionFisherHandshakeLength);
    bool    valid = connectionfisherclientReadMatches(reply, kConnectionFisherClientReply);

    lineReuseBuffer(child_l, reply);

    if (! valid)
    {
        LOGW("ConnectionFisherClient: child line received bytes that do not match the ConnectionFisher reply");
        bufferstreamEmpty(&child_ls->read_stream);
        connectionfisherclientCloseChildLine(t, child_l, true);
        return;
    }

    child_ls->child_handshake_complete = true;

    if (! connectionfisherclientSelectChild(t, child_l))
    {
        return;
    }
}

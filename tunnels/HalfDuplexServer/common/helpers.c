#include "structure.h"

bool halfduplexserverPairAlive(tunnel_t *t, line_t *main, line_t *upload, line_t *download)
{
    if (! lineIsAlive(main) || ! lineIsAlive(upload) || ! lineIsAlive(download))
        return false;
    halfduplexserver_lstate_t *ls = lineGetState(main, t);
    return ls->main_line == main && ls->upload_line == upload && ls->download_line == download &&
           ((halfduplexserver_lstate_t *) lineGetState(upload, t))->main_line == main &&
           ((halfduplexserver_lstate_t *) lineGetState(download, t))->main_line == main;
}

// NULL leaves the source caller-owned. Success consumes a splice source.
sbuf_t *halfduplexserverMaterialize(line_t *line, sbuf_t *buf)
{
    if (! sbufIsSplice(buf))
        return buf;
    buffer_pool_t *pool     = lineGetBufferPool(line);
    sbuf_t        *ordinary = bufferpoolTryGetBestFit(pool, sbufGetLength(buf), bufferpoolGetLargeBufferPadding(pool));
    if (ordinary == NULL)
        return NULL;
    if (sbufGetMaximumWriteableSize(ordinary) < sbufGetLength(buf))
    {
        bufferpoolReuseBuffer(pool, ordinary);
        return NULL;
    }
    sbufSpliceReadToBuffer(buf, ordinary, sbufGetLength(buf));
    bufferpoolReuseBuffer(pool, buf);
    return ordinary;
}

void halfduplexserverAbortPair(tunnel_t *t, line_t *main)
{
    halfduplexserver_lstate_t *ls     = lineGetState(main, t);
    line_t                    *upload = ls->upload_line;
    lineRef(upload);
    // Internal refusal closes both directions. The normal upload-close path
    // detaches the association and settles main storage before next callbacks.
    halfduplexserverTunnelUpStreamFinish(t, upload);
    if (lineIsAlive(upload))
        tunnelPrevDownStreamFinish(t, upload);
    lineUnref(upload);
}

void halfduplexserverReplayStartup(tunnel_t *t, line_t *main)
{
    halfduplexserver_lstate_t *ls = lineGetState(main, t);
    if (ls->startup_initializing || ls->startup_dispatching || ls->next_paused)
        return;
    line_t *upload   = ls->upload_line;
    line_t *download = ls->download_line;
    lineRef(main);
    lineRef(upload);
    lineRef(download);
    ls->startup_dispatching = true;
    if (ls->startup_active)
    {
        sbuf_t *initial     = ls->startup_initial;
        ls->startup_initial = NULL;
        if (initial != NULL)
        {
            tunnelNextUpStreamPayload(t, main, initial);
            if (! halfduplexserverPairAlive(t, main, upload, download))
                goto done;
            if (ls->next_paused)
                goto live_done;
        }
        // No callbacks while preparing the complete admitted tail. At most one
        // more Payload is needed, even if that callback generates further input.
        sbuf_t *tail = NULL;
        if (bufferqueueGetBufCount(&ls->startup_pending) == 1)
            tail = bufferqueuePopFront(&ls->startup_pending);
        else if (bufferqueueGetBufCount(&ls->startup_pending) != 0)
        {
            const size_t length = bufferqueueGetBufLen(&ls->startup_pending);
            tail = bufferpoolTryGetBestFit(ls->startup_pool, length, bufferpoolGetLargeBufferPadding(ls->startup_pool));
            if (tail == NULL || length > sbufGetMaximumWriteableSize(tail))
            {
                if (tail != NULL)
                    bufferpoolReuseBuffer(ls->startup_pool, tail);
                halfduplexserverAbortPair(t, main);
                goto done;
            }
            sbuf_t *entry;
            while ((entry = bufferqueuePopFront(&ls->startup_pending)) != NULL)
            {
                assert(! sbufIsSplice(entry));
                sbufConcatNoCheck(tail, entry);
                bufferpoolReuseBuffer(ls->startup_pool, entry);
            }
        }
        bufferbudgetAssertEmpty(&ls->startup_budget);
        ls->startup_active = false;
        if (tail != NULL)
        {
            tunnelNextUpStreamPayload(t, main, tail);
            if (! halfduplexserverPairAlive(t, main, upload, download))
                goto done;
        }
    }
    // A Resume nested in Init/replay records permission only. Release source
    // pressure after every older startup byte has reached the next receiver.
    if (! ls->next_paused && ! ls->startup_active && ls->source_paused)
    {
        ls->source_paused       = false;
        ls->startup_dispatching = false;
        tunnelPrevDownStreamResume(t, upload);
        if (! halfduplexserverPairAlive(t, main, upload, download))
            goto done;
    }
live_done:
    ls->startup_dispatching = false;
done:
    lineUnref(download);
    lineUnref(upload);
    lineUnref(main);
}

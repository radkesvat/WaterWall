#include "structure.h"

bool halfduplexclientPairAlive(tunnel_t *t, line_t *main, line_t *upload, line_t *download)
{
    if (UNLIKELY(! lineIsAlive(main) || ! lineIsAlive(upload) || ! lineIsAlive(download)))
        return false;
    halfduplexclient_lstate_t *ls = lineGetState(main, t);
    return ls->main_line == main && ls->upload_line == upload && ls->download_line == download;
}

bool halfduplexclientNotifyEstablished(tunnel_t *t, line_t *main)
{
    halfduplexclient_lstate_t *ls = lineGetState(main, t);
    if (! ls->est_seen || ls->est_forwarded || ls->pair_initializing)
        return true;
    ls->est_forwarded = true;
    return lineCallWithRef(main, tunnelPrevDownStreamEst, t);
}

bool halfduplexclientDrainPending(tunnel_t *t, line_t *main, bool admitted)
{
    halfduplexclient_lstate_t *ls = lineGetState(main, t);
    if (ls->pair_initializing || ls->intro_dispatching || ls->draining)
        return true;
    lineRef(main);
    ls->draining = true;
    // admitted is used only by the outer first-input dispatch, whose FIFO can
    // contain only nested admitted input. Init/backlog release respects Pause.
    while (lineIsAlive(main) && ls->main_line == main && (admitted || ! ls->next_paused) &&
           bufferqueueGetBufCount(&ls->pending_up) != 0)
    {
        sbuf_t *buf = bufferqueuePopFront(&ls->pending_up);
        if (UNLIKELY(! halfduplexclientForwardPayload(t, main, buf)))
            break;
    }
    bool alive = lineIsAlive(main) && ls->main_line == main;
    if (alive)
        ls->draining = false;
    lineUnref(main);
    return alive;
}

void halfduplexclientClosePair(tunnel_t *t, line_t *line, bool from_prev, bool from_next)
{
    halfduplexclient_lstate_t *origin = lineGetState(line, t);
    line_t                    *main   = origin->main_line;
    if (main == NULL)
    {
        // Downstream Finish can target a detached owned sibling during close.
        if (from_next)
            lineDestroy(line);
        return;
    }
    halfduplexclient_lstate_t *ls       = lineGetState(main, t);
    line_t                    *upload   = ls->upload_line;
    line_t                    *download = ls->download_line;
    lineRef(main);
    bool upload_started = false, download_started = false;
    if (upload != NULL)
    {
        lineRef(upload);
        halfduplexclient_lstate_t *child = lineGetState(upload, t);
        upload_started                   = child->next_started;
        halfduplexclientLinestateDestroy(child);
    }
    if (download != NULL)
    {
        lineRef(download);
        halfduplexclient_lstate_t *child = lineGetState(download, t);
        download_started                 = child->next_started;
        halfduplexclientLinestateDestroy(child);
    }
    halfduplexclientLinestateDestroy(ls);
    // Detach the whole pair before callbacks. A received child Finish closes
    // that exact owned line now and never reflects anything toward its sender.
    if (from_next)
        lineDestroy(line);
    if (upload != NULL && lineIsAlive(upload))
    {
        if (upload_started)
            tunnelNextUpStreamFinish(t, upload);
        if (lineIsAlive(upload))
            lineDestroy(upload);
    }
    if (download != NULL && lineIsAlive(download))
    {
        if (download_started)
            tunnelNextUpStreamFinish(t, download);
        if (lineIsAlive(download))
            lineDestroy(download);
    }
    if (! from_prev && lineIsAlive(main))
        tunnelPrevDownStreamFinish(t, main);
    if (download != NULL)
        lineUnref(download);
    if (upload != NULL)
        lineUnref(upload);
    lineUnref(main);
}

void halfduplexclientSetPrevPaused(tunnel_t *t, line_t *main, bool paused)
{
    halfduplexclient_lstate_t *ls = lineGetState(main, t);
    if (ls->main_line == NULL)
        return;
    ls->prev_paused  = paused;
    line_t *download = ls->download_line;
    if (download == NULL)
        return;
    halfduplexclient_lstate_t *child = lineGetState(download, t);
    if (! child->next_started || child->read_pause_sent == paused)
        return;
    child->read_pause_sent = paused;
    if (paused)
        tunnelNextUpStreamPause(t, download);
    else
        tunnelNextUpStreamResume(t, download);
}

void halfduplexclientSetNextPaused(tunnel_t *t, line_t *line, bool paused)
{
    halfduplexclient_lstate_t *child = lineGetState(line, t);
    line_t                    *main  = child->main_line;
    if (main == NULL)
        return;
    child->next_paused                  = paused;
    halfduplexclient_lstate_t *ls       = lineGetState(main, t);
    halfduplexclient_lstate_t *upload   = ls->upload_line ? lineGetState(ls->upload_line, t) : NULL;
    halfduplexclient_lstate_t *download = ls->download_line ? lineGetState(ls->download_line, t) : NULL;
    ls->next_paused                     = (upload && upload->next_paused) || (download && download->next_paused);
    if (ls->next_paused)
    {
        if (! ls->source_pause_sent)
        {
            ls->source_pause_sent = true;
            tunnelPrevDownStreamPause(t, main);
        }
        return;
    }
    lineRef(main);
    if (halfduplexclientDrainPending(t, main, false) && ! ls->next_paused && ls->source_pause_sent)
    {
        ls->source_pause_sent = false;
        tunnelPrevDownStreamResume(t, main);
    }
    lineUnref(main);
}

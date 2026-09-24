#include "structure.h"

/* Shared request/response progress. Callers retain the session; pumping
 * serializes reentry while each callback publishes its own direction first. */

static uint64_t retained(hps_session_t *s)
{
    uint64_t n = hpsPendingBytes(s);
    for (unsigned d = 0; d < 2; ++d)
    {
        const hps_direction_state_t *dir = &s->directions[d];
        if (dir->deferred)
            n += sbufGetLength(dir->deferred);
        if (dir->incoming)
            n += sbufGetLength(dir->incoming);
    }
    return n;
}

void hpsFail(hps_session_t *s, unsigned status)
{
    if (! hpsIsActive(s))
        return;
    if (s->final_committed || s->phase == kHpsRelay || s->phase == kHpsFallback || s->phase == kHpsError)
    {
        hpsClose(s, false);
        return;
    }
    s->phase = kHpsError;
    hpsCloseChild(s, false);
    for (unsigned i = 0; i < 2; ++i)
    {
        hps_direction_state_t *dir = &s->directions[i];
        hpsDiscardBuffer(s, &dir->input);
        hpsDiscardBuffer(s, &dir->output);
        hpsDiscardBuffer(s, &dir->deferred);
        hpsDiscardBuffer(s, &dir->incoming);
    }
    const char *reason = "Bad Request";
    switch (status)
    {
    case 405:
        reason = "Method Not Allowed";
        break;
    case 407:
        reason = "Proxy Authentication Required";
        break;
    case 408:
        reason = "Request Timeout";
        break;
    case 414:
        reason = "URI Too Long";
        break;
    case 417:
        reason = "Expectation Failed";
        break;
    case 431:
        reason = "Request Header Fields Too Large";
        break;
    case 501:
        reason = "Not Implemented";
        break;
    case 502:
        reason = "Bad Gateway";
        break;
    case 503:
        reason = "Service Unavailable";
        break;
    case 504:
        reason = "Gateway Timeout";
        break;
    case 505:
        reason = "HTTP Version Not Supported";
        break;
    }
    char text[384];
    int  n = stringNPrintf(text,
                          sizeof(text),
                          "HTTP/1.%c %u %s\r\nContent-Length: 0\r\nConnection: close\r\n%s\r\n",
                          s->http10 ? '0' : '1',
                          status,
                          reason,
                          status == 407   ? "Proxy-Authenticate: Basic realm=\"WaterWall\"\r\n"
                           : status == 405 ? "Allow: GET, HEAD, POST, PUT, DELETE, OPTIONS, CONNECT\r\n"
                                           : "");
    if (! hpsQueueOutput(s, kHpsDownstream, text, (size_t) n))
        hpsClose(s, false);
}

void hpsUpdatePressure(hps_session_t *s)
{
    if (! hpsIsActive(s) || hpsSettings(s)->workers[lineGetWID(s->client)].quiescing)
        return;
    /* No outward notification may overtake the active first-request remainder,
     * or enter a branch whose Init has not returned. */
    if ((s->directions[kHpsUpstream].receiving && ! s->protected_committed) || s->child_initializing)
        return;
    for (unsigned d = 0; d < 2 && hpsIsActive(s); ++d)
    {
        hps_direction_state_t *dir = &s->directions[d];
        /* Future requests cannot drain until the current response arrives. Reserve
         * headroom by stopping client input, without stopping that response producer.
         * Recompute after each callback: a Resume can synchronously drain buffers. */
        uint64_t n    = d == kHpsUpstream ? retained(s)
                                          : (uint64_t) (dir->input ? sbufGetLength(dir->input) : 0) +
                                             (dir->output ? sbufGetLength(dir->output) : 0) +
                                             (dir->deferred ? sbufGetLength(dir->deferred) : 0) +
                                             (dir->incoming ? sbufGetLength(dir->incoming) : 0);
        bool     want = dir->paused || dir->deferred != NULL || n >= hpsSettings(s)->max_pending * 3 / 4 ||
                    (d == kHpsUpstream && (s->upload_stopped || s->phase == kHpsError));
        if (! want && n > hpsSettings(s)->max_pending / 2 && dir->read_paused)
            want = true;
        if (want == dir->read_paused ||
            (d == kHpsDownstream && (! s->child || (s->phase != kHpsFallback && ! s->child_established))))
            continue;
        dir->read_paused  = want;
        line_t *line      = d == kHpsUpstream ? s->client : s->child;
        lineRef(line);
        if (d == kHpsUpstream)
        {
            if (want)
                tunnelPrevDownStreamPause(s->t, line);
            else
                tunnelPrevDownStreamResume(s->t, line);
        }
        else
        {
            if (want)
                s->child_entry->fnPauseU(s->child_entry, line);
            else
                s->child_entry->fnResumeU(s->child_entry, line);
        }
        lineUnref(line);
        s->again = true;
    }
}

bool hpsDeliverPayload(hps_session_t *s, hps_direction_t d, sbuf_t *b)
{
    line_t *line = d == kHpsUpstream ? s->child : s->client;
    lineRef(line);
    s->progress_at = hpsNowMs(s);
    if (d == kHpsUpstream)
        s->child_entry->fnPayloadU(s->child_entry, line, b);
    else
        tunnelPrevDownStreamPayload(s->t, line, b);
    bool alive = lineIsAlive(line);
    lineUnref(line);
    return alive && hpsIsActive(s);
}

static bool flush(hps_session_t *s, hps_direction_t d)
{
    hps_direction_state_t *dir = &s->directions[d];
    if (! dir->output || dir->paused ||
        (d == kHpsUpstream &&
         (! s->child || s->child_initializing || (s->phase != kHpsFallback && ! s->child_established))))
        return false;
    sbuf_t *b   = dir->output;
    dir->output = NULL;
    if (d == kHpsDownstream && (s->phase == kHpsError || s->phase == kHpsRelay || ! s->response_header))
        s->final_committed = true;
    hpsDeliverPayload(s, d, b);
    return true;
}

static bool admitDeferred(hps_session_t *s, hps_direction_t d)
{
    hps_direction_state_t *dir = &s->directions[d];
    if (! dir->deferred || dir->paused || s->phase == kHpsError || s->phase == kHpsFallback || s->phase == kHpsRelay)
        return false;
    if (d == kHpsUpstream && (s->upload_stopped || s->phase == kHpsConnect ||
                              (s->phase == kHpsExchange && (! s->child_established || dir->body.kind == kHpsBodyDone))))
        return false;
    size_t room = hpsSettings(s)->max_pending - hpsPendingBytes(s);
    if ((d == kHpsUpstream ? s->phase == kHpsRequest : s->response_header) && room > 1024)
        room -= 1024;
    size_t n = min(min((size_t) 16384, sbufGetLength(dir->deferred)), room);
    if (! n)
        return false;
    if (! hpsAppendInput(s, d, sbufGetRawPtr(dir->deferred), n))
    {
        hpsFail(s, 503);
        return true;
    }
    if (n == sbufGetLength(dir->deferred))
        hpsDiscardBuffer(s, &dir->deferred);
    else
        sbufShiftRight(dir->deferred, (uint32_t) n);
    s->progress_at = hpsNowMs(s);
    return true;
}

static bool drainRaw(hps_session_t *s, hps_direction_t d)
{
    hps_direction_state_t *dir = &s->directions[d];
    if (dir->paused || dir->output || (d == kHpsUpstream && (! s->child || s->child_initializing)))
        return false;
    /* Raw bytes need no working copy. Drain older working input first, then
     * hand off the charged remainder even if the other direction fills P. */
    sbuf_t **slot = dir->input ? &dir->input : &dir->deferred;
    if (! *slot)
        return false;
    sbuf_t *b = *slot;
    *slot     = NULL;
    hpsDeliverPayload(s, d, b);
    return true;
}

static void finishRaw(hps_session_t *s)
{
    const hps_direction_state_t *down = &s->directions[kHpsDownstream];
    if (hpsIsActive(s) && s->child_eof && ! down->input && ! down->output && ! down->deferred && ! down->incoming)
        hpsClose(s, false);
}

void hpsPump(hps_session_t *s)
{
    hps_direction_state_t *up   = &s->directions[kHpsUpstream];
    hps_direction_state_t *down = &s->directions[kHpsDownstream];
    if (s->pumping)
    {
        s->again = true;
        return;
    }
    s->pumping = true;
    do
    {
        s->again = false;
        if (! hpsIsActive(s) || hpsSettings(s)->workers[lineGetWID(s->client)].quiescing)
            break;
        if (admitDeferred(s, kHpsDownstream))
            s->again = true;
        if (hpsIsActive(s) && admitDeferred(s, kHpsUpstream))
            s->again = true;
        if (! hpsIsActive(s))
            break;
        if (flush(s, kHpsDownstream))
            s->again = true;
        if (! hpsIsActive(s))
            break;
        if (s->phase == kHpsError)
        {
            if (! down->output)
                hpsClose(s, false);
            break;
        }
        if (s->phase == kHpsRequest)
        {
            if (down->input)
            {
                hpsFail(s, 502);
                s->again = true;
                continue;
            }
            if (hpsProcessRequest(s))
                s->again = true;
        }
        if (! hpsIsActive(s))
            break;
        if (s->phase == kHpsFallback)
        {
            if (! up->receiving && ! s->child_initializing)
            {
                if (! s->child && ! s->child_eof)
                    hpsCreateChild(s, NULL, NULL);
                hpsUpdatePressure(s); /* Reconcile current permission, including changes from Init. */
                if (! hpsIsActive(s))
                    break;
                if (flush(s, kHpsUpstream))
                    s->again = true;
                for (unsigned d = 0; d < 2 && hpsIsActive(s); ++d)
                    if (drainRaw(s, d))
                        s->again = true;
                finishRaw(s);
            }
        }
        if (! hpsIsActive(s))
            break;
        if (s->phase == kHpsConnect && s->child_established)
        {
            char success[] = "HTTP/1.1 200 Connection Established\r\n\r\n";
            success[7]     = s->http10 ? '0' : '1';
            s->phase       = kHpsRelay;
            if (! hpsQueueOutput(s, kHpsDownstream, success, stringLength(success)))
                hpsFail(s, 503);
            s->again = true;
        }
        if (! hpsIsActive(s))
            break;
        if (s->phase == kHpsRelay && ! down->output)
        {
            for (unsigned d = 0; d < 2 && hpsIsActive(s); ++d)
                if (drainRaw(s, d))
                    s->again = true;
            finishRaw(s);
        }
        if (! hpsIsActive(s))
            break;
        if (s->phase == kHpsExchange)
        {
            bool needs_input = false;
            if (s->response_header && ! down->output)
            {
                if (hpsProcessResponse(s))
                    s->again = true;
                else
                    needs_input = true;
            }
            if (! hpsIsActive(s) || s->phase != kHpsExchange)
                continue;
            if (flush(s, kHpsUpstream))
                s->again = true;
            if (! hpsIsActive(s) || s->phase != kHpsExchange)
                continue;
            if (s->child_established && ! s->upload_stopped && hpsProcessBody(s, kHpsUpstream) == kHpsStepProgress)
                s->again = true;
            if (! hpsIsActive(s) || s->phase != kHpsExchange)
                continue;
            if (! s->response_header)
            {
                hps_step_t step = hpsProcessBody(s, kHpsDownstream);
                if (step == kHpsStepProgress)
                    s->again = true;
                needs_input = step == kHpsStepNeedInput;
            }
            if (! hpsIsActive(s) || s->phase != kHpsExchange)
                continue;
            if (s->child_eof && down->body.kind == kHpsBodyEof && ! down->input && ! down->deferred && ! down->incoming)
                down->body.kind = kHpsBodyDone;
            if (s->child_eof && ! down->deferred && ! down->incoming && needs_input && ! s->again &&
                (s->response_header || down->body.kind != kHpsBodyDone))
            {
                hpsFail(s, 502);
                s->again = true;
                continue;
            }
            if (! s->response_header && down->body.kind == kHpsBodyDone && ! down->output)
            {
                if (down->input || down->deferred)
                {
                    hpsFail(s, 502);
                    s->again = true;
                    continue;
                }
                if (s->close_after || s->upload_stopped)
                {
                    hpsClose(s, false);
                    break;
                }
                if (up->body.kind == kHpsBodyDone && ! up->output && ! down->receiving)
                {
                    if (! s->child_reusable)
                        hpsCloseChild(s, false);
                    s->phase           = kHpsRequest;
                    s->final_committed = false;
                    s->again           = true;
                }
            }
        }
        hpsUpdatePressure(s);
    } while (s->again);
    s->pumping = false;
}

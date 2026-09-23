#include "structure.h"

/* Shared request/response progress. Callers retain the session; pumping
 * serializes reentry while each callback publishes its own direction first. */

static uint64_t retained(hps_session_t *s)
{
    uint64_t n = hpsPendingBytes(s);
    for (unsigned d = 0; d < 2; ++d)
    {
        if (s->deferred[d])
            n += sbufGetLength(s->deferred[d]);
        if (s->incoming[d])
            n += sbufGetLength(s->incoming[d]);
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
        hpsDiscardBuffer(s, &s->input[i]);
        hpsDiscardBuffer(s, &s->output[i]);
        hpsDiscardBuffer(s, &s->deferred[i]);
        hpsDiscardBuffer(s, &s->incoming[i]);
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
    if ((s->receiving_up && ! s->protected_committed) || s->child_initializing)
        return;
    for (unsigned d = 0; d < 2 && hpsIsActive(s); ++d)
    {
        /* Future requests cannot drain until the current response arrives. Reserve
         * headroom by stopping client input, without stopping that response producer.
         * Recompute after each callback: a Resume can synchronously drain buffers. */
        uint64_t n    = d == kHpsUpstream
                            ? retained(s)
                            : (uint64_t) (s->input[kHpsDownstream] ? sbufGetLength(s->input[kHpsDownstream]) : 0) +
                               (s->output[kHpsDownstream] ? sbufGetLength(s->output[kHpsDownstream]) : 0) +
                               (s->deferred[kHpsDownstream] ? sbufGetLength(s->deferred[kHpsDownstream]) : 0) +
                               (s->incoming[kHpsDownstream] ? sbufGetLength(s->incoming[kHpsDownstream]) : 0);
        bool     want = s->paused[d] || s->deferred[d] != NULL || n >= hpsSettings(s)->max_pending * 3 / 4 ||
                    (d == kHpsUpstream && (s->upload_stopped || s->phase == kHpsError));
        if (! want && n > hpsSettings(s)->max_pending / 2 && s->read_paused[d])
            want = true;
        if (want == s->read_paused[d] ||
            (d == kHpsDownstream && (! s->child || (s->phase != kHpsFallback && ! s->child_established))))
            continue;
        s->read_paused[d] = want;
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
    s->progress_at = hpsNowMs();
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
    if (! s->output[d] || s->paused[d] ||
        (d == kHpsUpstream &&
         (! s->child || s->child_initializing || (s->phase != kHpsFallback && ! s->child_established))))
        return false;
    sbuf_t *b    = s->output[d];
    s->output[d] = NULL;
    if (d == kHpsDownstream && (s->phase == kHpsError || s->phase == kHpsRelay || ! s->response_header))
        s->final_committed = true;
    hpsDeliverPayload(s, d, b);
    return true;
}

static bool admitDeferred(hps_session_t *s, hps_direction_t d)
{
    if (! s->deferred[d] || s->paused[d] || s->phase == kHpsError || s->phase == kHpsFallback || s->phase == kHpsRelay)
        return false;
    if (d == kHpsUpstream &&
        (s->upload_stopped || s->phase == kHpsConnect ||
         (s->phase == kHpsExchange && (! s->child_established || s->request_body.kind == kHpsBodyDone))))
        return false;
    size_t room = hpsSettings(s)->max_pending - hpsPendingBytes(s);
    if ((d == kHpsUpstream ? s->phase == kHpsRequest : s->response_header) && room > 1024)
        room -= 1024;
    size_t n = min(min((size_t) 16384, sbufGetLength(s->deferred[d])), room);
    if (! n)
        return false;
    if (! hpsAppendInput(s, d, sbufGetRawPtr(s->deferred[d]), n))
    {
        hpsFail(s, 503);
        return true;
    }
    if (n == sbufGetLength(s->deferred[d]))
        hpsDiscardBuffer(s, &s->deferred[d]);
    else
        sbufShiftRight(s->deferred[d], (uint32_t) n);
    s->progress_at = hpsNowMs();
    return true;
}

static bool drainRaw(hps_session_t *s, hps_direction_t d)
{
    if (s->paused[d] || s->output[d] || (d == kHpsUpstream && (! s->child || s->child_initializing)))
        return false;
    /* Raw bytes need no working copy. Drain older working input first, then
     * hand off the charged remainder even if the other direction fills P. */
    sbuf_t **slot = s->input[d] ? &s->input[d] : &s->deferred[d];
    if (! *slot)
        return false;
    sbuf_t *b = *slot;
    *slot     = NULL;
    hpsDeliverPayload(s, d, b);
    return true;
}

static void finishRaw(hps_session_t *s)
{
    if (hpsIsActive(s) && s->child_eof && ! s->input[kHpsDownstream] && ! s->output[kHpsDownstream] &&
        ! s->deferred[kHpsDownstream] && ! s->incoming[kHpsDownstream])
        hpsClose(s, false);
}

void hpsPump(hps_session_t *s)
{
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
            if (! s->output[kHpsDownstream])
                hpsClose(s, false);
            break;
        }
        if (s->phase == kHpsRequest)
        {
            if (s->input[kHpsDownstream])
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
            if (! s->receiving_up && ! s->child_initializing)
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
        if (s->phase == kHpsRelay && ! s->output[kHpsDownstream])
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
            if (s->response_header && ! s->output[kHpsDownstream])
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
            if (s->child_eof && s->response_body.kind == kHpsBodyEof && ! s->input[kHpsDownstream] &&
                ! s->deferred[kHpsDownstream] && ! s->incoming[kHpsDownstream])
                s->response_body.kind = kHpsBodyDone;
            if (s->child_eof && ! s->deferred[kHpsDownstream] && ! s->incoming[kHpsDownstream] && needs_input &&
                ! s->again && (s->response_header || s->response_body.kind != kHpsBodyDone))
            {
                hpsFail(s, 502);
                s->again = true;
                continue;
            }
            if (! s->response_header && s->response_body.kind == kHpsBodyDone && ! s->output[kHpsDownstream])
            {
                if (s->input[kHpsDownstream] || s->deferred[kHpsDownstream])
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
                if (s->request_body.kind == kHpsBodyDone && ! s->output[kHpsUpstream] && ! s->receiving_down)
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

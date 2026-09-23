#include "structure.h"

/* Child input maps back to the borrowed client. HTTP responses are parsed
 * below; fallback and CONNECT remain opaque in the shared flow coordinator. */
void httpproxyserverTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    hps_lstate_t  *ls = lineGetState(l, t);
    hps_session_t *s  = ls->session;
    hps_tstate_t  *ts = tunnelGetState(t);
    if (! s || ts->workers[lineGetWID(l)].quiescing)
    {
        lineReuseBuffer(l, buf);
        return;
    }
    hpsRetain(s);
    lineRef(l);
    ++s->receiving_down;
    hpsAcceptPayload(s, l, buf, kHpsDownstream);
    --s->receiving_down;
    if (hpsIsActive(s))
        hpsPump(s);
    lineUnref(l);
    hpsRelease(s);
}

bool hpsProcessResponse(hps_session_t *s)
{
    char *block = NULL;
    int   n     = hpsReadHeader(s, kHpsDownstream, &block);
    if (! n)
        return false;
    if (n < 0)
    {
        hpsFail(s, 502);
        return true;
    }
    hps_header_t h;
    unsigned     error = hpsParseHeader(block, (size_t) n, true, s->head, &h);
    if (! error && h.status < 200 && ++s->informationals > kHpsInformationalLimit)
        error = 502;
    if (! error)
    {
        if (h.status >= 200)
        {
            s->response_header = false;
            s->response_body   = h.body;
            s->child_reusable  = ! h.close && h.body.kind != kHpsBodyEof;
            s->close_after |= h.close || h.body.kind == kHpsBodyEof;
            if (s->request_body.kind != kHpsBodyDone)
            {
                s->upload_stopped = true;
                s->close_after    = true;
                s->child_reusable = false;
                hpsDiscardBuffer(s, &s->input[kHpsUpstream]);
                hpsDiscardBuffer(s, &s->output[kHpsUpstream]);
                hpsDiscardBuffer(s, &s->deferred[kHpsUpstream]);
                hpsDiscardBuffer(s, &s->incoming[kHpsUpstream]);
            }
        }
        if (! (s->http10 && h.status < 200) && ! hpsRewriteHeaderOutput(s, &h, kHpsDownstream))
            error = 503;
        if (! error && h.chunked && h.status >= 200)
        {
            hpsClearHeader(s, kHpsDownstream);
            s->trailer_context[kHpsDownstream] = h;
            s->header_storage[kHpsDownstream]  = block;
            s->header_length[kHpsDownstream]   = (size_t) n;
            block                              = NULL;
        }
    }
    memoryFree(block);
    if (error)
        hpsFail(s, 502);
    return true;
}

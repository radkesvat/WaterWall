#include "structure.h"

#include "loggers/network_logger.h"

bool httpclientSplitIsEnabled(tunnel_t *t)
{
    httpclient_tstate_t *ts = tunnelGetState(t);
    return ts->h1_transport_mode == kHttpClientH1TransportSplit;
}

static void httpclientSplitGenerateId(tunnel_t *t, char out[48])
{
    httpclient_tstate_t *ts  = tunnelGetState(t);
    uint64_t             seq = atomicIncU64Relaxed(&ts->split_identifier);
    uint64_t             rnd = fastRand64();
    snprintf(out, 48, "%016" PRIx64 "%016" PRIx64, seq, rnd);
}

static void httpclientSplitInitTransportState(tunnel_t *t, line_t *transport, line_t *main_line, line_t *upload_line,
                                              line_t *download_line, httpclient_split_role_t role, const char *id)
{
    httpclient_lstate_t *ls = lineGetState(transport, t);
    httpclientLinestateInitialize(ls, t, transport);
    ls->runtime_proto       = kHttpClientRuntimeHttp1;
    ls->split_role          = role;
    ls->split_main_line     = main_line;
    ls->split_upload_line   = upload_line;
    ls->split_download_line = download_line;
    stringCopyN(ls->split_id, id, sizeof(ls->split_id));
}

static void httpclientSplitClearPeerReference(tunnel_t *t, line_t *peer_line, line_t *dead_line)
{
    if (peer_line == NULL || peer_line == dead_line || ! lineIsAlive(peer_line))
    {
        return;
    }

    httpclient_lstate_t *peer_ls = lineGetState(peer_line, t);
    if (peer_ls->split_main_line == dead_line)
    {
        peer_ls->split_main_line = NULL;
    }
    if (peer_ls->split_upload_line == dead_line)
    {
        peer_ls->split_upload_line = NULL;
    }
    if (peer_ls->split_download_line == dead_line)
    {
        peer_ls->split_download_line = NULL;
    }
}

static void httpclientSplitDetachCreatedLine(tunnel_t *t, line_t *l, httpclient_lstate_t *ls)
{
    line_t *main_line     = ls->split_main_line;
    line_t *upload_line   = ls->split_upload_line;
    line_t *download_line = ls->split_download_line;

    httpclientSplitClearPeerReference(t, main_line, l);
    httpclientSplitClearPeerReference(t, upload_line, l);
    httpclientSplitClearPeerReference(t, download_line, l);
}

static void httpclientSplitDestroyCreatedLine(tunnel_t *t, line_t *l, bool send_finish)
{
    if (l == NULL || ! lineIsAlive(l))
    {
        return;
    }

    httpclient_lstate_t *ls = lineGetState(l, t);
    httpclientSplitDetachCreatedLine(t, l, ls);
    httpclientLinestateDestroy(ls);
    if (send_finish)
    {
        tunnelNextUpStreamFinish(t, l);
    }
    if (lineIsAlive(l))
    {
        lineDestroy(l);
    }
}

// finish_sender controls whether the transport line we entered on still needs its own next
// side finished. When this is called because the transport's next already finished us (a real
// downstream Finish), pass false. When we close proactively (response complete, error, peer
// died) the next side is still open and must be finished, so pass true.
static void httpclientSplitCloseFromTransport(tunnel_t *t, line_t *transport_line, bool finish_main, bool finish_sender)
{
    httpclient_lstate_t *transport_ls  = lineGetState(transport_line, t);
    line_t              *main_line     = transport_ls->split_main_line;
    line_t              *upload_line   = transport_ls->split_upload_line;
    line_t              *download_line = transport_ls->split_download_line;

    lineRef(transport_line);
    bool main_ref_held     = false;
    bool upload_ref_held   = false;
    bool download_ref_held = false;
    if (main_line != NULL && lineIsAlive(main_line))
    {
        lineRef(main_line);
        main_ref_held = true;
    }
    if (upload_line != NULL && upload_line != transport_line && lineIsAlive(upload_line))
    {
        lineRef(upload_line);
        upload_ref_held = true;
    }
    if (download_line != NULL && download_line != transport_line && lineIsAlive(download_line))
    {
        lineRef(download_line);
        download_ref_held = true;
    }

    if (upload_line != NULL && upload_line != transport_line)
    {
        httpclientSplitDestroyCreatedLine(t, upload_line, true);
    }
    if (download_line != NULL && download_line != transport_line)
    {
        httpclientSplitDestroyCreatedLine(t, download_line, true);
    }

    if (main_line != NULL && lineIsAlive(main_line))
    {
        httpclient_lstate_t *main_ls = lineGetState(main_line, t);
        httpclientLinestateDestroy(main_ls);
        if (finish_main)
        {
            tunnelPrevDownStreamFinish(t, main_line);
        }
    }

    if (lineIsAlive(transport_line))
    {
        // The transport line is one we created, so finish its next side (unless our caller
        // already received that Finish) and destroy it. We hold an extra line reference above,
        // so the allocation survives until the unref below.
        httpclientSplitDestroyCreatedLine(t, transport_line, finish_sender);
    }

    if (download_ref_held)
    {
        lineUnref(download_line);
    }
    if (upload_ref_held)
    {
        lineUnref(upload_line);
    }
    if (main_ref_held)
    {
        lineUnref(main_line);
    }
    lineUnref(transport_line);
}

static void httpclientSplitFailMain(tunnel_t *t, line_t *main_line)
{
    if (main_line == NULL || ! lineIsAlive(main_line))
    {
        return;
    }

    httpclient_lstate_t *main_ls       = lineGetState(main_line, t);
    line_t              *upload_line   = main_ls->split_upload_line;
    line_t              *download_line = main_ls->split_download_line;

    if (upload_line != NULL && lineIsAlive(upload_line))
    {
        lineRef(upload_line);
        httpclientSplitDestroyCreatedLine(t, upload_line, true);
        lineUnref(upload_line);
    }

    if (download_line != NULL && lineIsAlive(download_line))
    {
        lineRef(download_line);
        httpclientSplitDestroyCreatedLine(t, download_line, true);
        lineUnref(download_line);
    }

    httpclientLinestateDestroy(main_ls);
    tunnelPrevDownStreamFinish(t, main_line);
}

void httpclientSplitUpStreamInit(tunnel_t *t, line_t *l)
{
    httpclient_tstate_t *ts = tunnelGetState(t);
    httpclient_lstate_t *ls = lineGetState(l, t);

    httpclientLinestateInitialize(ls, t, l);
    ls->runtime_proto   = kHttpClientRuntimeHttp1;
    ls->split_role      = kHttpClientSplitRoleMain;
    ls->split_main_line = l;
    httpclientSplitGenerateId(t, ls->split_id);

    if (ts->verbose)
    {
        LOGD("HttpClient: split HTTP/1.1 init id=%s upload=%s %s download=%s %s",
             ls->split_id,
             ts->split_upload_method,
             ts->split_upload_path,
             ts->split_download_method,
             ts->split_download_path);
    }

    lineRef(l);

    line_t *upload_line   = lineCreate(tunnelchainGetLinePools(tunnelGetChain(t)), lineGetWID(l));
    ls->split_upload_line = upload_line;
    httpclientSplitInitTransportState(t, upload_line, l, upload_line, NULL, kHttpClientSplitRoleUpload, ls->split_id);

    if (! lineCallWithRef(upload_line, tunnelNextUpStreamInit, t))
    {
        if (lineIsAlive(l))
        {
            httpclientLinestateDestroy(ls);
            tunnelPrevDownStreamFinish(t, l);
        }
        lineUnref(l);
        return;
    }

    if (! lineIsAlive(l))
    {
        lineUnref(l);
        return;
    }

    line_t *download_line   = lineCreate(tunnelchainGetLinePools(tunnelGetChain(t)), lineGetWID(l));
    ls->split_download_line = download_line;

    httpclient_lstate_t *upload_ls = lineGetState(upload_line, t);
    upload_ls->split_download_line = download_line;

    httpclientSplitInitTransportState(
        t, download_line, l, upload_line, download_line, kHttpClientSplitRoleDownload, ls->split_id);

    lineRef(upload_line);
    bool download_init_ok = lineCallWithRef(download_line, tunnelNextUpStreamInit, t);
    if (! download_init_ok)
    {
        if (lineIsAlive(upload_line))
        {
            httpclientSplitDestroyCreatedLine(t, upload_line, true);
        }
        lineUnref(upload_line);
        if (lineIsAlive(l))
        {
            httpclientLinestateDestroy(ls);
            tunnelPrevDownStreamFinish(t, l);
        }
        lineUnref(l);
        return;
    }
    lineUnref(upload_line);

    if (! lineIsAlive(l))
    {
        lineUnref(l);
        return;
    }

    bool ok = true;
    lineRef(upload_line);
    if (! httpclientTransportSendHttp1SplitRequestHeaders(t, upload_line) || ! lineIsAlive(upload_line))
    {
        ok = false;
    }
    lineUnref(upload_line);

    if (ok)
    {
        lineRef(download_line);
        if (! httpclientTransportSendHttp1SplitRequestHeaders(t, download_line) || ! lineIsAlive(download_line))
        {
            ok = false;
        }
        lineUnref(download_line);
    }

    if (! ok && lineIsAlive(l))
    {
        httpclientSplitFailMain(t, l);
    }

    lineUnref(l);
}

void httpclientSplitUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    httpclient_lstate_t *ls          = lineGetState(l, t);
    line_t              *upload_line = ls->split_upload_line;

    if (upload_line == NULL || ! lineIsAlive(upload_line))
    {
        lineReuseBuffer(l, buf);
        httpclientSplitFailMain(t, l);
        return;
    }

    lineRef(l);
    lineRef(upload_line);

    bool ok = httpclientTransportSendHttp1ChunkedPayload(t, upload_line, buf);
    if ((! ok || ! lineIsAlive(upload_line)) && lineIsAlive(l))
    {
        httpclientSplitFailMain(t, l);
    }

    lineUnref(upload_line);
    lineUnref(l);
}

void httpclientSplitUpStreamFinish(tunnel_t *t, line_t *l)
{
    httpclient_lstate_t *ls            = lineGetState(l, t);
    line_t              *upload_line   = ls->split_upload_line;
    line_t              *download_line = ls->split_download_line;

    lineRef(l);
    ls->prev_finished = true;

    // The main line was created by the upstream adapter (e.g. TcpListener), which destroys it
    // as soon as this upstream Finish returns. We therefore cannot keep the main line alive to
    // wait for the response; we must tear the whole trio down now. We must NOT send a Finish
    // back toward main's prev (it just finished us), and we must NOT lineDestroy main (we did
    // not create it) - only drop our own line state so the adapter's lineDestroy stays valid.

    if (upload_line != NULL && lineIsAlive(upload_line))
    {
        lineRef(upload_line);
        httpclient_lstate_t *upload_ls = lineGetState(upload_line, t);
        // Upload backpressure is re-homed to main's prev, which has already finished this split trio.
        upload_ls->prev_finished = true;
        discard httpclientTransportSendHttp1FinalChunk(t, upload_line);
        if (lineIsAlive(upload_line))
        {
            httpclientSplitDestroyCreatedLine(t, upload_line, true);
        }
        lineUnref(upload_line);
    }

    if (download_line != NULL && lineIsAlive(download_line))
    {
        lineRef(download_line);
        httpclientSplitDestroyCreatedLine(t, download_line, true);
        lineUnref(download_line);
    }

    if (lineIsAlive(l))
    {
        httpclientLinestateDestroy(ls);
    }
    lineUnref(l);
}

void httpclientSplitDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    httpclient_lstate_t *ls = lineGetState(l, t);

    if (ls->split_role == kHttpClientSplitRoleUpload)
    {
        lineReuseBuffer(l, buf);
        return;
    }

    if (ls->split_role != kHttpClientSplitRoleDownload || ls->split_main_line == NULL)
    {
        lineReuseBuffer(l, buf);
        return;
    }

    line_t *main_line = ls->split_main_line;
    if (! lineIsAlive(main_line))
    {
        lineReuseBuffer(l, buf);
        // main is gone; tear down proactively and finish this transport's still-open next side.
        httpclientSplitCloseFromTransport(t, l, false, true);
        return;
    }

    lineRef(l);
    lineRef(main_line);

    if (ls->response_complete)
    {
        httpclient_tstate_t *ts = tunnelGetState(t);
        if (ts->verbose && ! ls->h1_trailing_bytes_logged)
        {
            LOGD("HttpClient: ignoring bytes after the split HTTP/1.1 response body");
            ls->h1_trailing_bytes_logged = true;
        }
        lineReuseBuffer(l, buf);
        lineUnref(main_line);
        lineUnref(l);
        return;
    }

    bufferstreamPush(&ls->in_stream, buf);

    bool ok = httpclientTransportHandleHttp1ResponseHeaderPhase(t, l, ls);
    if (ok && lineIsAlive(l) && lineIsAlive(main_line) && ls->h1_headers_parsed)
    {
        ok = httpclientTransportDrainHttp1Body(t, l, ls);
    }

    /* A complete response body is framing state; transport Finish closes the split trio. */

    if (! ok && lineIsAlive(l))
    {
        // Error path: close proactively, finishing both main's prev and this transport's next.
        httpclientSplitCloseFromTransport(t, l, true, true);
    }

    lineUnref(main_line);
    lineUnref(l);
}

void httpclientSplitDownStreamFinish(tunnel_t *t, line_t *l)
{
    httpclient_lstate_t *ls = lineGetState(l, t);

    if (ls->split_role == kHttpClientSplitRoleUpload)
    {
        line_t *main_line = ls->split_main_line;
        if (main_line != NULL && lineIsAlive(main_line))
        {
            lineRef(main_line);
            httpclient_lstate_t *main_ls = lineGetState(main_line, t);
            if (main_ls->prev_finished)
            {
                httpclientSplitDestroyCreatedLine(t, l, false);
                lineUnref(main_line);
                return;
            }
            lineUnref(main_line);
        }
    }

    // Entered because this transport's next finished us, so do not re-finish that next side.
    httpclientSplitCloseFromTransport(t, l, true, false);
}

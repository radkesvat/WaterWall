#include "structure.h"

#include "loggers/network_logger.h"

#include <inttypes.h>

bool httpclientSplitIsEnabled(tunnel_t *t)
{
    httpclient_tstate_t *ts = tunnelGetState(t);
    return ts->h1_transport_mode == kHttpClientH1TransportSplit;
}

static void httpclientSplitGenerateId(tunnel_t *t, char out[48])
{
    httpclient_tstate_t *ts  = tunnelGetState(t);
    uint64_t             seq = atomicIncRelaxed(&ts->split_identifier);
    uint64_t             rnd = fastRand64();
    snprintf(out, 48, "%016" PRIx64 "%016" PRIx64, seq, rnd);
}

static void httpclientSplitInitTransportState(tunnel_t *t, line_t *transport, line_t *main_line,
                                              line_t *upload_line, line_t *download_line,
                                              httpclient_split_role_t role, const char *id)
{
    httpclient_lstate_t *ls = lineGetState(transport, t);
    httpclientLinestateInitialize(ls, t, transport);
    ls->runtime_proto        = kHttpClientRuntimeHttp1;
    ls->split_role          = role;
    ls->split_main_line     = main_line;
    ls->split_upload_line   = upload_line;
    ls->split_download_line = download_line;
    stringCopyN(ls->split_id, id, sizeof(ls->split_id));
}

static void httpclientSplitDestroyCreatedLine(tunnel_t *t, line_t *l, bool send_finish)
{
    if (l == NULL || ! lineIsAlive(l))
    {
        return;
    }

    httpclient_lstate_t *ls = lineGetState(l, t);
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

static void httpclientSplitCloseFromTransport(tunnel_t *t, line_t *transport_line, bool finish_main)
{
    httpclient_lstate_t *transport_ls = lineGetState(transport_line, t);
    line_t              *main_line    = transport_ls->split_main_line;
    line_t              *upload_line  = transport_ls->split_upload_line;
    line_t              *download_line = transport_ls->split_download_line;

    lineLock(transport_line);
    bool main_locked = false;
    bool upload_locked = false;
    bool download_locked = false;
    if (main_line != NULL && lineIsAlive(main_line))
    {
        lineLock(main_line);
        main_locked = true;
    }
    if (upload_line != NULL && upload_line != transport_line && lineIsAlive(upload_line))
    {
        lineLock(upload_line);
        upload_locked = true;
    }
    if (download_line != NULL && download_line != transport_line && lineIsAlive(download_line))
    {
        lineLock(download_line);
        download_locked = true;
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
        httpclientLinestateDestroy(transport_ls);
        lineDestroy(transport_line);
    }

    if (download_locked)
    {
        lineUnlock(download_line);
    }
    if (upload_locked)
    {
        lineUnlock(upload_line);
    }
    if (main_locked)
    {
        lineUnlock(main_line);
    }
    lineUnlock(transport_line);
}

static void httpclientSplitFailMain(tunnel_t *t, line_t *main_line)
{
    if (main_line == NULL || ! lineIsAlive(main_line))
    {
        return;
    }

    httpclient_lstate_t *main_ls = lineGetState(main_line, t);
    line_t              *upload_line = main_ls->split_upload_line;
    line_t              *download_line = main_ls->split_download_line;

    if (upload_line != NULL && lineIsAlive(upload_line))
    {
        lineLock(upload_line);
        httpclientSplitDestroyCreatedLine(t, upload_line, true);
        lineUnlock(upload_line);
    }

    if (download_line != NULL && lineIsAlive(download_line))
    {
        lineLock(download_line);
        httpclientSplitDestroyCreatedLine(t, download_line, true);
        lineUnlock(download_line);
    }

    httpclientLinestateDestroy(main_ls);
    tunnelPrevDownStreamFinish(t, main_line);
}

void httpclientSplitUpStreamInit(tunnel_t *t, line_t *l)
{
    httpclient_tstate_t *ts = tunnelGetState(t);
    httpclient_lstate_t *ls = lineGetState(l, t);

    httpclientLinestateInitialize(ls, t, l);
    ls->runtime_proto    = kHttpClientRuntimeHttp1;
    ls->split_role       = kHttpClientSplitRoleMain;
    ls->split_main_line  = l;
    httpclientSplitGenerateId(t, ls->split_id);

    if (ts->verbose)
    {
        LOGD("HttpClient: split HTTP/1.1 init id=%s upload=%s %s download=%s %s", ls->split_id,
             ts->split_upload_method, ts->split_upload_path, ts->split_download_method, ts->split_download_path);
    }

    lineLock(l);

    line_t *upload_line = lineCreate(tunnelchainGetLinePools(tunnelGetChain(t)), lineGetWID(l));
    ls->split_upload_line = upload_line;
    httpclientSplitInitTransportState(t, upload_line, l, upload_line, NULL, kHttpClientSplitRoleUpload, ls->split_id);

    if (! withLineLocked(upload_line, tunnelNextUpStreamInit, t))
    {
        if (lineIsAlive(l))
        {
            httpclientLinestateDestroy(ls);
            tunnelPrevDownStreamFinish(t, l);
        }
        lineUnlock(l);
        return;
    }

    if (! lineIsAlive(l))
    {
        lineUnlock(l);
        return;
    }

    line_t *download_line = lineCreate(tunnelchainGetLinePools(tunnelGetChain(t)), lineGetWID(l));
    ls->split_download_line = download_line;

    httpclient_lstate_t *upload_ls = lineGetState(upload_line, t);
    upload_ls->split_download_line = download_line;

    httpclientSplitInitTransportState(t, download_line, l, upload_line, download_line,
                                      kHttpClientSplitRoleDownload, ls->split_id);

    lineLock(upload_line);
    bool download_init_ok = withLineLocked(download_line, tunnelNextUpStreamInit, t);
    if (! download_init_ok)
    {
        if (lineIsAlive(upload_line))
        {
            httpclientSplitDestroyCreatedLine(t, upload_line, true);
        }
        lineUnlock(upload_line);
        if (lineIsAlive(l))
        {
            httpclientLinestateDestroy(ls);
            tunnelPrevDownStreamFinish(t, l);
        }
        lineUnlock(l);
        return;
    }
    lineUnlock(upload_line);

    if (! lineIsAlive(l))
    {
        lineUnlock(l);
        return;
    }

    bool ok = true;
    lineLock(upload_line);
    if (! httpclientTransportSendHttp1SplitRequestHeaders(t, upload_line) || ! lineIsAlive(upload_line))
    {
        ok = false;
    }
    lineUnlock(upload_line);

    if (ok)
    {
        lineLock(download_line);
        if (! httpclientTransportSendHttp1SplitRequestHeaders(t, download_line) || ! lineIsAlive(download_line))
        {
            ok = false;
        }
        lineUnlock(download_line);
    }

    if (! ok && lineIsAlive(l))
    {
        httpclientSplitFailMain(t, l);
    }

    lineUnlock(l);
}

void httpclientSplitUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    httpclient_lstate_t *ls = lineGetState(l, t);
    line_t              *upload_line = ls->split_upload_line;

    if (upload_line == NULL || ! lineIsAlive(upload_line))
    {
        lineReuseBuffer(l, buf);
        httpclientSplitFailMain(t, l);
        return;
    }

    lineLock(l);
    lineLock(upload_line);

    bool ok = httpclientTransportSendHttp1ChunkedPayload(t, upload_line, buf);
    if ((! ok || ! lineIsAlive(upload_line)) && lineIsAlive(l))
    {
        httpclientSplitFailMain(t, l);
    }

    lineUnlock(upload_line);
    lineUnlock(l);
}

void httpclientSplitUpStreamFinish(tunnel_t *t, line_t *l)
{
    httpclient_lstate_t *ls = lineGetState(l, t);
    line_t              *upload_line = ls->split_upload_line;
    line_t              *download_line = ls->split_download_line;

    lineLock(l);

    if (upload_line != NULL && lineIsAlive(upload_line))
    {
        lineLock(upload_line);
        (void) httpclientTransportSendHttp1FinalChunk(t, upload_line);
        if (lineIsAlive(upload_line))
        {
            httpclientSplitDestroyCreatedLine(t, upload_line, true);
        }
        lineUnlock(upload_line);
    }

    if (download_line != NULL && lineIsAlive(download_line))
    {
        lineLock(download_line);
        httpclientSplitDestroyCreatedLine(t, download_line, true);
        lineUnlock(download_line);
    }

    if (lineIsAlive(l))
    {
        httpclientLinestateDestroy(ls);
    }
    lineUnlock(l);
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
        httpclientSplitCloseFromTransport(t, l, false);
        return;
    }

    lineLock(l);
    lineLock(main_line);

    bufferstreamPush(&ls->in_stream, buf);

    bool ok = httpclientTransportHandleHttp1ResponseHeaderPhase(t, l, ls);
    if (ok && lineIsAlive(l) && lineIsAlive(main_line) && ls->h1_headers_parsed)
    {
        ok = httpclientTransportDrainHttp1Body(t, l, ls);
    }

    bool done = ok && lineIsAlive(l) && lineIsAlive(main_line) && ls->response_complete;

    if (! ok && lineIsAlive(l))
    {
        httpclientSplitCloseFromTransport(t, l, true);
    }
    else if (done)
    {
        httpclientSplitCloseFromTransport(t, l, true);
    }

    lineUnlock(main_line);
    lineUnlock(l);
}

void httpclientSplitDownStreamFinish(tunnel_t *t, line_t *l)
{
    httpclientSplitCloseFromTransport(t, l, true);
}

#include "structure.h"

#include "loggers/network_logger.h"

static sbuf_t *handleBuffering(line_t *l, halfduplexserver_lstate_t *ls, sbuf_t *buf)
{
    if (ls->buffering)
    {
        buf           = sbufAppendMerge(lineGetBufferPool(l), ls->buffering, buf);
        ls->buffering = NULL;
    }

    if (sbufGetLength(buf) < kHLFDIntroSize)
    {
        ls->buffering = buf;
        return NULL;
    }

    return buf;
}

static bool extractPairIdAndSetupConnection(line_t *l, halfduplexserver_lstate_t *ls, const sbuf_t *buf,
                                            bool *is_upload, halfduplex_pair_id_t *pair_id)
{
    const uint8_t *intro   = sbufGetRawPtr(buf);
    const uint8_t  command = intro[kHLFDCommandOffset];
    if (command != kHLFDCmdUpload && command != kHLFDCmdDownload)
    {
        return false;
    }

    *is_upload = command == kHLFDCmdUpload;
    memoryCopy(pair_id->bytes, intro + kHLFDPairIdOffset, sizeof(pair_id->bytes));
    ls->pair_id = *pair_id;

    if (*is_upload)
    {
        ls->upload_line = l;
    }
    else
    {
        ls->download_line = l;
    }

    return true;
}

static halfduplexserver_pending_decision_t pendingClaim(halfduplexserver_tstate_t *ts, halfduplexserver_lstate_t *ls,
                                                        halfduplex_pair_id_t pair_id, bool is_upload, sbuf_t *buf)
{
    hmap_cons_t *const opposite_map = is_upload ? &ts->download_line_map : &ts->upload_line_map;
    hmap_cons_t *const own_map      = is_upload ? &ts->upload_line_map : &ts->download_line_map;
    line_t *const      current_line = is_upload ? ls->upload_line : ls->download_line;

    halfduplexserver_pending_decision_t decision = {
        .result = kHalfDuplexServerPendingDuplicate, .peer = NULL, .target_wid = kInvalidWID};

#ifdef WW_HALFDUPLEXSERVER_RENDEZVOUS_TEST_SEAM
    halfduplexserverPendingBeforeLockTestSeam(is_upload);
#endif
    mutexLock(&ts->pending_line_maps_mutex);

    hmap_cons_t_iter opposite = hmap_cons_t_find(opposite_map, pair_id);
    if (opposite.ref != hmap_cons_t_end(opposite_map).ref)
    {
        halfduplexserver_lstate_t *peer      = opposite.ref->second;
        line_t *const              peer_line = is_upload ? peer->download_line : peer->upload_line;

        decision.target_wid = lineGetWID(peer_line);
        if (decision.target_wid == lineGetWID(current_line))
        {
            hmap_cons_t_erase_at(opposite_map, opposite);
            decision.peer   = peer;
            decision.result = kHalfDuplexServerPendingMatchedLocal;
        }
        else
        {
            decision.result = kHalfDuplexServerPendingMatchedRemote;
        }
        mutexUnlock(&ts->pending_line_maps_mutex);
        return decision;
    }

#ifdef WW_HALFDUPLEXSERVER_RENDEZVOUS_TEST_SEAM
    halfduplexserverPendingMissTestSeam(is_upload);
#endif

    ls->state = is_upload ? kCsUploadInTable : kCsDownloadInTable;
    if (is_upload)
    {
        ls->buffering = buf;
    }
    decision.result = hmap_cons_t_insert(own_map, pair_id, ls).inserted ? kHalfDuplexServerPendingInserted
                                                                        : kHalfDuplexServerPendingDuplicate;
    mutexUnlock(&ts->pending_line_maps_mutex);
    return decision;
}

#ifdef WW_HALFDUPLEXSERVER_RENDEZVOUS_TEST_SEAM
halfduplexserver_pending_decision_t halfduplexserverTestPendingClaim(halfduplexserver_tstate_t *ts,
                                                                     halfduplexserver_lstate_t *ls,
                                                                     halfduplex_pair_id_t pair_id, bool is_upload,
                                                                     sbuf_t *buf)
{
    return pendingClaim(ts, ls, pair_id, is_upload, buf);
}
#endif

static line_t *createAndInitializeMainLine(tunnel_t *t, line_t *upload_line, line_t *download_line,
                                           halfduplexserver_lstate_t *upload_ls, halfduplexserver_lstate_t *download_ls)
{
    line_t *main_line = lineCreate(tunnelchainGetLinePools(tunnelGetChain(t)), lineGetWID(upload_line));

    upload_ls->main_line   = main_line;
    download_ls->main_line = main_line;

    halfduplexserver_lstate_t *ls_mainline = lineGetState(main_line, t);
    halfduplexserverLinestateInitialize(ls_mainline);

    ls_mainline->upload_line   = upload_line;
    ls_mainline->download_line = download_line;
    ls_mainline->main_line     = main_line;

    return main_line;
}

static bool initializeMainLineConnection(tunnel_t *t, line_t *main_line)
{

    if (! lineCallWithRef(main_line, tunnelNextUpStreamInit, t))
    {
        return false;
    }
    return true;
}

static bool handlePipeToWorker(tunnel_t *t, line_t *l, sbuf_t *buf, wid_t target_wid, halfduplexserver_lstate_t *ls)
{
    halfduplexserverLinestateDestroy(ls);
    if (pipeTo(t, l, target_wid))
    {
        tunnel_t *prev_tun = t->prev;
        tunnelUpStreamPayload(prev_tun, l, buf);
        return true;
    }

    lineReuseBuffer(l, buf);
    tunnelPrevDownStreamFinish(t, l);
    return true;
}

static bool handleUploadConnectionFound(tunnel_t *t, line_t *l, sbuf_t *buf, halfduplexserver_lstate_t *ls,
                                        halfduplexserver_lstate_t *download_line_ls)
{
    line_t *download_line = download_line_ls->download_line;
    ls->download_line     = download_line;

    ls->state                     = kCsUploadDirect;
    download_line_ls->state       = kCsDownloadDirect;
    download_line_ls->upload_line = l;

    line_t *main_line = createAndInitializeMainLine(t, l, download_line, ls, download_line_ls);

    buffer_pool_t *buffer_pool = lineGetBufferPool(l);
    lineRef(l);
    lineRef(download_line);

    bool initialized = initializeMainLineConnection(t, main_line);
    if (! initialized)
    {
        bufferpoolReuseBuffer(buffer_pool, buf);
        lineUnref(download_line);
        lineUnref(l);
        return true;
    }

    lineUnref(download_line);
    lineUnref(l);

    sbufShiftRight(buf, kHLFDIntroSize);
    if (sbufGetLength(buf) > 0)
    {
        tunnelNextUpStreamPayload(t, main_line, buf);
        return true;
    }
    bufferpoolReuseBuffer(buffer_pool, buf);
    return true;
}

static bool handleDuplicateUploadConnection(tunnel_t *t, line_t *l, halfduplexserver_lstate_t *ls)
{
    LOGW("HalfDuplexServer: duplicate upload connection closed");
    lineReuseBuffer(l, ls->buffering);
    ls->buffering = NULL;
    halfduplexserverLinestateDestroy(ls);
    tunnelPrevDownStreamFinish(t, l);
    return true;
}

static bool handleDownloadConnectionFound(tunnel_t *t, line_t *l, sbuf_t *buf, halfduplexserver_lstate_t *ls,
                                          halfduplexserver_lstate_t *upload_line_ls)
{
    lineReuseBuffer(l, buf);

    ls->state                     = kCsDownloadDirect;
    line_t *upload_line           = upload_line_ls->upload_line;
    ls->upload_line               = upload_line;
    upload_line_ls->state         = kCsUploadDirect;
    upload_line_ls->download_line = l;

    line_t *main_line = createAndInitializeMainLine(t, upload_line, l, upload_line_ls, ls);

    assert(upload_line_ls->buffering);
    sbuf_t *buf_upline        = upload_line_ls->buffering;
    upload_line_ls->buffering = NULL;

    buffer_pool_t *buffer_pool = lineGetBufferPool(l);
    lineRef(upload_line);
    lineRef(l);

    bool initialized = initializeMainLineConnection(t, main_line);
    if (! initialized)
    {
        bufferpoolReuseBuffer(buffer_pool, buf_upline);
        lineUnref(l);
        lineUnref(upload_line);
        return true;
    }

    lineUnref(l);
    lineUnref(upload_line);

    sbufShiftRight(buf_upline, kHLFDIntroSize);
    if (sbufGetLength(buf_upline) > 0)
    {
        tunnelNextUpStreamPayload(t, main_line, buf_upline);
    }
    else
    {
        bufferpoolReuseBuffer(buffer_pool, buf_upline);
    }
    return true;
}
static bool handleDuplicateDownloadConnection(tunnel_t *t, line_t *l, sbuf_t *buf, halfduplexserver_lstate_t *ls)
{
    lineReuseBuffer(l, buf);
    LOGW("HalfDuplexServer: duplicate download connection closed");
    halfduplexserverLinestateDestroy(ls);
    tunnelPrevDownStreamFinish(t, l);
    return true;
}

static bool handleUnknownState(tunnel_t *t, line_t *l, sbuf_t *buf, halfduplexserver_tstate_t *ts,
                               halfduplexserver_lstate_t *ls)
{
    buf = handleBuffering(l, ls, buf);
    if (! buf)
    {
        return true;
    }

    bool                 is_upload;
    halfduplex_pair_id_t pair_id;
    if (! extractPairIdAndSetupConnection(l, ls, buf, &is_upload, &pair_id))
    {
        lineReuseBuffer(l, buf);
        halfduplexserverLinestateDestroy(ls);
        tunnelPrevDownStreamFinish(t, l);
        return true;
    }

    const halfduplexserver_pending_decision_t decision = pendingClaim(ts, ls, pair_id, is_upload, buf);
    switch (decision.result)
    {
    case kHalfDuplexServerPendingInserted:
        if (! is_upload)
        {
            lineReuseBuffer(l, buf);
        }
        return true;

    case kHalfDuplexServerPendingDuplicate:
        if (is_upload)
        {
            return handleDuplicateUploadConnection(t, l, ls);
        }
        return handleDuplicateDownloadConnection(t, l, buf, ls);

    case kHalfDuplexServerPendingMatchedRemote:
        return handlePipeToWorker(t, l, buf, decision.target_wid, ls);

    case kHalfDuplexServerPendingMatchedLocal:
        if (is_upload)
        {
            return handleUploadConnectionFound(t, l, buf, ls, decision.peer);
        }
        return handleDownloadConnectionFound(t, l, buf, ls, decision.peer);
    }

    assert(false);
    return true;
}

static void handleUploadInTable(tunnel_t *t, line_t *l, sbuf_t *buf, halfduplexserver_tstate_t *ts,
                                halfduplexserver_lstate_t *ls)
{
    if (ls->buffering)
    {
        ls->buffering = sbufAppendMerge(lineGetBufferPool(l), ls->buffering, buf);
    }
    else
    {
        ls->buffering = buf;
    }

    if (sbufGetLength(ls->buffering) >= kMaxBuffering)
    {
        mutexLock(&(ts->pending_line_maps_mutex));
        hmap_cons_t_iter f_iter = hmap_cons_t_find(&(ts->upload_line_map), ls->pair_id);
        bool             found  = f_iter.ref != hmap_cons_t_end(&(ts->upload_line_map)).ref;

        if (! found)
        {
            mutexUnlock(&(ts->pending_line_maps_mutex));
            LOGF("HalfDuplexServer: Thread safety is done incorrectly  [%s:%d]", __FILENAME__, __LINE__);
            abortProgramNow(1);
        }
        hmap_cons_t_erase_at(&(ts->upload_line_map), f_iter);
        mutexUnlock(&(ts->pending_line_maps_mutex));

        lineReuseBuffer(l, ls->buffering);
        ls->buffering = NULL;
        halfduplexserverLinestateDestroy(ls);
        tunnelPrevDownStreamFinish(t, l);
    }
}

void halfduplexserverTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    halfduplexserver_tstate_t *ts = tunnelGetState(t);
    halfduplexserver_lstate_t *ls = lineGetState(l, t);

    switch (ls->state)
    {
    case kCsUnkown:
        handleUnknownState(t, l, buf, ts, ls);
        break;

    case kCsUploadInTable:
        handleUploadInTable(t, l, buf, ts, ls);
        break;

    case kCsUploadDirect:
        if (LIKELY(ls->main_line != NULL))
        {
            tunnelNextUpStreamPayload(t, ls->main_line, buf);
        }
        else
        {
            lineReuseBuffer(l, buf);
        }
        break;

    case kCsDownloadDirect:
    case kCsDownloadInTable:
        lineReuseBuffer(l, buf);
        break;
    }
}

#include "structure.h"

#include "loggers/network_logger.h"

static sbuf_t *handleBuffering(line_t *l, halfduplexserver_lstate_t *ls, sbuf_t *buf)
{
    if (ls->buffering)
    {
        buf           = sbufAppendMerge(lineGetBufferPool(l), ls->buffering, buf);
        ls->buffering = NULL;
    }

    if (sbufGetLength(buf) < sizeof(uint64_t))
    {
        ls->buffering = buf;
        return NULL;
    }

    return buf;
}

static hash_t extractHashAndSetupConnection(line_t *l, halfduplexserver_lstate_t *ls, sbuf_t *buf, bool *is_upload)
{
    *is_upload = (((uint8_t *) sbufGetRawPtr(buf))[0] & kHLFDCmdDownload) == 0x0;

    hash_t hash = 0x0;
    sbufReadUnAlignedUI64(buf, (uint64_t *) &hash);

    uint8_t *hptr = (uint8_t *) &hash;
    (hptr)[0]     = ((hptr)[0] & kHLFDCmdUpload);

    ls->hash = hash;

    if (*is_upload)
    {
        ls->upload_line = l;
    }
    else
    {
        ls->download_line = l;
    }

    return hash;
}

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
    lineLock(main_line);
    tunnelNextUpStreamInit(t, main_line);

    if (! lineIsAlive(main_line))
    {
        lineUnlock(main_line);
        return false;
    }
    lineUnlock(main_line);
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

    bufferpoolReuseBuffer(lineGetBufferPool(l), buf);
    tunnelPrevDownStreamFinish(t, l);
    return true;
}

static bool handleUploadConnectionFound(tunnel_t *t, line_t *l, sbuf_t *buf, halfduplexserver_tstate_t *ts,
                                        halfduplexserver_lstate_t *ls, hash_t hash)
{
    hmap_cons_t_iter           f_iter           = hmap_cons_t_find(&(ts->download_line_map), hash);
    halfduplexserver_lstate_t *download_line_ls = (halfduplexserver_lstate_t *) ((*f_iter.ref).second);

    wid_t wid_download_line = lineGetWID(download_line_ls->download_line);
    if (wid_download_line != lineGetWID(l))
    {
        mutexUnlock(&(ts->download_line_map_mutex));
        return handlePipeToWorker(t, l, buf, wid_download_line, ls);
    }

    line_t *download_line = download_line_ls->download_line;
    ls->download_line     = download_line;

    hmap_cons_t_erase_at(&(ts->download_line_map), f_iter);
    mutexUnlock(&(ts->download_line_map_mutex));

    ls->state                     = kCsUploadDirect;
    download_line_ls->state       = kCsDownloadDirect;
    download_line_ls->upload_line = l;

    line_t *main_line = createAndInitializeMainLine(t, l, download_line, ls, download_line_ls);

    if (! initializeMainLineConnection(t, main_line))
    {
        bufferpoolReuseBuffer(lineGetBufferPool(l), buf);
        return true;
    }

    sbufShiftRight(buf, sizeof(uint64_t));
    if (sbufGetLength(buf) > 0)
    {
        tunnelNextUpStreamPayload(t, main_line, buf);
        return true;
    }
    bufferpoolReuseBuffer(lineGetBufferPool(l), buf);
    return true;
}

static bool handleUploadConnectionNotFound(tunnel_t *t, line_t *l, sbuf_t *buf, halfduplexserver_tstate_t *ts,
                                           halfduplexserver_lstate_t *ls, hash_t hash)
{
    mutexUnlock(&(ts->download_line_map_mutex));
    ls->state     = kCsUploadInTable;
    ls->buffering = buf;

    mutexLock(&(ts->upload_line_map_mutex));
    bool push_succeed = hmap_cons_t_insert(&(ts->upload_line_map), hash, ls).inserted;
    mutexUnlock(&(ts->upload_line_map_mutex));

    if (! push_succeed)
    {
        LOGW("HalfDuplexServer: duplicate upload connection closed, hash:%lu", hash);
        bufferpoolReuseBuffer(lineGetBufferPool(l), ls->buffering);
        ls->buffering = NULL;
        halfduplexserverLinestateDestroy(ls);
        tunnelPrevDownStreamFinish(t, l);
    }
    return true;
}

static bool handleDownloadConnectionFound(tunnel_t *t, line_t *l, sbuf_t *buf, halfduplexserver_tstate_t *ts,
                                          halfduplexserver_lstate_t *ls, hash_t hash)
{
    hmap_cons_t_iter           f_iter         = hmap_cons_t_find(&(ts->upload_line_map), hash);
    halfduplexserver_lstate_t *upload_line_ls = (halfduplexserver_lstate_t *) ((*f_iter.ref).second);

    wid_t wid_upload_line = lineGetWID(upload_line_ls->upload_line);
    if (wid_upload_line != lineGetWID(l))
    {
        mutexUnlock(&(ts->upload_line_map_mutex));
        return handlePipeToWorker(t, l, buf, wid_upload_line, ls);
    }

    hmap_cons_t_erase_at(&(ts->upload_line_map), f_iter);
    mutexUnlock(&(ts->upload_line_map_mutex));

    bufferpoolReuseBuffer(lineGetBufferPool(l), buf);

    ls->state                     = kCsDownloadDirect;
    ls->upload_line               = upload_line_ls->upload_line;
    upload_line_ls->state         = kCsUploadDirect;
    upload_line_ls->download_line = l;

    line_t *main_line = createAndInitializeMainLine(t, ls->upload_line, l, upload_line_ls, ls);

    assert(upload_line_ls->buffering);
    sbuf_t *buf_upline        = upload_line_ls->buffering;
    upload_line_ls->buffering = NULL;

    if (! initializeMainLineConnection(t, main_line))
    {
        bufferpoolReuseBuffer(lineGetBufferPool(l), buf_upline);
        return true;
    }

    if (sbufGetLength(buf_upline) > 0)
    {
        sbufShiftRight(buf_upline, sizeof(uint64_t));
        tunnelNextUpStreamPayload(t, main_line, buf_upline);
    }
    else
    {
        bufferpoolReuseBuffer(lineGetBufferPool(l), buf_upline);
    }
    return true;
}
static bool handleDownloadConnectionNotFound(tunnel_t *t, line_t *l, sbuf_t *buf, halfduplexserver_tstate_t *ts,
                                             halfduplexserver_lstate_t *ls, hash_t hash)
{
    mutexUnlock(&(ts->upload_line_map_mutex));
    bufferpoolReuseBuffer(lineGetBufferPool(l), buf);

    ls->state = kCsDownloadInTable;

    mutexLock(&(ts->download_line_map_mutex));
    bool push_succeed = hmap_cons_t_insert(&(ts->download_line_map), hash, ls).inserted;
    mutexUnlock(&(ts->download_line_map_mutex));

    if (! push_succeed)
    {
        LOGW("HalfDuplexServer: duplicate download connection closed");
        halfduplexserverLinestateDestroy(ls);
        tunnelPrevDownStreamFinish(t, l);
    }
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

    bool   is_upload;
    hash_t hash = extractHashAndSetupConnection(l, ls, buf, &is_upload);

    if (is_upload)
    {
        mutexLock(&(ts->download_line_map_mutex));
        hmap_cons_t_iter f_iter = hmap_cons_t_find(&(ts->download_line_map), hash);
        bool             found  = f_iter.ref != hmap_cons_t_end(&(ts->download_line_map)).ref;

        if (found)
        {
            return handleUploadConnectionFound(t, l, buf, ts, ls, hash);
        }
        return handleUploadConnectionNotFound(t, l, buf, ts, ls, hash);
    }

    mutexLock(&(ts->upload_line_map_mutex));
    hmap_cons_t_iter f_iter = hmap_cons_t_find(&(ts->upload_line_map), hash);
    bool             found  = f_iter.ref != hmap_cons_t_end(&(ts->upload_line_map)).ref;

    if (found)
    {
        return handleDownloadConnectionFound(t, l, buf, ts, ls, hash);
    }
    return handleDownloadConnectionNotFound(t, l, buf, ts, ls, hash);
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
        hmap_cons_t_iter f_iter = hmap_cons_t_find(&(ts->upload_line_map), ls->hash);
        bool             found  = f_iter.ref != hmap_cons_t_end(&(ts->upload_line_map)).ref;

        if (! found)
        {
            LOGF("HalfDuplexServer: Thread safety is done incorrectly  [%s:%d]", __FILENAME__, __LINE__);
            exit(1);
        }
        mutexLock(&(ts->upload_line_map_mutex));
        hmap_cons_t_erase_at(&(ts->upload_line_map), f_iter);
        mutexUnlock(&(ts->upload_line_map_mutex));

        bufferpoolReuseBuffer(lineGetBufferPool(l), ls->buffering);
        ls->buffering = NULL;
        halfduplexserverLinestateDestroy(ls);
        tunnelPrevDownStreamFinish(t, l);
    }
}

void halfduplexserverTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    halfduplexserver_tstate_t *ts = tunnelGetState(t);
    halfduplexserver_lstate_t *ls = lineGetState(l, t);

    // #ifdef DEBUG
    // This bug is fixed in my event loop code, i also told libhv to fix it but by the time they have replied to my
    // issue
    if (getWID() != lineGetWID(l))
    {
        LOGF("HalfDuplexServer: WID mismatch detected, getWID: %d, line WID: %d", getWID(), lineGetWID(l));
        assert(false);
        memoryFree(ls);
        terminateProgram(1);
    }
    // #endif

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
            bufferpoolReuseBuffer(lineGetBufferPool(l), buf);
        }
        break;

    case kCsDownloadDirect:
    case kCsDownloadInTable:
        bufferpoolReuseBuffer(lineGetBufferPool(l), buf);
        break;
    }
}

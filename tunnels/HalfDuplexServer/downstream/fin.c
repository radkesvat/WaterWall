#include "structure.h"

#include "loggers/network_logger.h"

static void localAsyncCloseLineDownStream(tunnel_t *t, line_t *l)
{

    halfduplexserver_lstate_t *ls = lineGetState(l, t);

    assert(ls->upload_line != NULL);
    if (ls->buffering)
    {
        lineReuseBuffer(l, ls->buffering);
    }
    halfduplexserverLinestateDestroy(ls);
    tunnelPrevDownStreamFinish(t, l);
}

void halfduplexserverTunnelDownStreamFinish(tunnel_t *t, line_t *l)
{
    halfduplexserver_lstate_t *ls_main_line = lineGetState(l, t);

    halfduplexserver_lstate_t *ls_download_line = lineGetState(ls_main_line->download_line, t);
    halfduplexserver_lstate_t *ls_upload_line   = lineGetState(ls_main_line->upload_line, t);

    discard ls_download_line;
    assert(ls_download_line->upload_line);
    assert(ls_download_line->download_line);
    assert(ls_download_line->state == kCsDownloadDirect);

    line_t *upload_line = ls_main_line->upload_line;

    ls_upload_line->download_line = NULL;
    ls_upload_line->main_line     = NULL;

    halfduplexserverLinestateDestroy(ls_download_line);
    tunnelPrevDownStreamFinish(t, ls_main_line->download_line);

    halfduplexserverLinestateDestroy(ls_main_line);

    if (! lineScheduleTask(upload_line, localAsyncCloseLineDownStream, t) && lineIsAlive(upload_line))
    {
        localAsyncCloseLineDownStream(t, upload_line);
    }
    lineDestroy(l);
}

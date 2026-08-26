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
    halfduplexserver_lstate_t *ls_main_line  = lineGetState(l, t);
    line_t *const              download_line = ls_main_line->download_line;
    line_t *const              upload_line   = ls_main_line->upload_line;

    lineRef(l);
    lineRef(download_line);
    lineRef(upload_line);

    halfduplexserver_lstate_t *ls_download_line = lineGetState(download_line, t);
    halfduplexserver_lstate_t *ls_upload_line   = lineGetState(upload_line, t);

    discard ls_download_line;
    assert(ls_download_line->upload_line);
    assert(ls_download_line->download_line);
    assert(ls_download_line->state == kCsDownloadDirect);

    ls_upload_line->download_line = NULL;
    ls_upload_line->main_line     = NULL;

    /* Destroy every state slot needed by this close before the first
     * cross-line callback. The retained allocations remain inspectable for
     * logical life, but their destroyed state must not be read afterward. */
    halfduplexserverLinestateDestroy(ls_download_line);
    halfduplexserverLinestateDestroy(ls_main_line);
    tunnelPrevDownStreamFinish(t, download_line);

    if (lineIsAlive(upload_line))
    {
        const line_task_submit_result_e result = lineScheduleTask(upload_line, localAsyncCloseLineDownStream, t, NULL);
        if (result == kLineTaskSubmitRejectedSettled)
        {
            if (lineIsAlive(upload_line))
            {
                localAsyncCloseLineDownStream(t, upload_line);
            }
        }
        else
        {
            assert(result == kLineTaskSubmitAcceptedAsync);
        }
    }

    if (lineIsAlive(l))
    {
        lineDestroy(l);
    }

    lineUnref(upload_line);
    lineUnref(download_line);
    lineUnref(l);
}

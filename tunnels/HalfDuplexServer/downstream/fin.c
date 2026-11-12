#include "structure.h"

#include "loggers/network_logger.h"

static void localAsyncCloseLineDownStream(tunnel_t *t, line_t *l)
{

    halfduplexserver_lstate_t *ls = lineGetState(l, t);

    assert(ls->upload_line != NULL);
    if (ls->buffering)
    {
        sbuf_t *buffer = ls->buffering;
        ls->buffering  = NULL;
        lineReuseBuffer(l, buffer);
    }
    halfduplexserverLinestateDestroy(ls);
    tunnelPrevDownStreamFinish(t, l);
}

void halfduplexserverTunnelDownStreamFinish(tunnel_t *t, line_t *l)
{
    halfduplexserver_lstate_t *ls_main_line  = lineGetState(l, t);
    tunnel_t *const            download_tunnel = ls_main_line->download_tunnel;
    tunnel_t *const            upload_tunnel   = ls_main_line->upload_tunnel;
    line_t *const              download_line = ls_main_line->download_line;
    line_t *const              upload_line   = ls_main_line->upload_line;

    lineRef(l);
    lineRef(download_line);
    lineRef(upload_line);

    halfduplexserver_lstate_t *ls_download_line = lineGetState(download_line, download_tunnel);
    halfduplexserver_lstate_t *ls_upload_line   = lineGetState(upload_line, upload_tunnel);

    discard ls_download_line;
    assert(ls_download_line->upload_line);
    assert(ls_download_line->download_line);
    assert(ls_download_line->state == kCsDownloadDirect);

    ls_upload_line->download_line = NULL;
    ls_upload_line->download_tunnel = NULL;
    ls_upload_line->main_line     = NULL;

    /* Destroy every state slot needed by this close before the first
     * cross-line callback. The retained allocations remain inspectable for
     * logical life, but their destroyed state must not be read afterward. */
    halfduplexserverLinestateDestroy(ls_download_line);
    halfduplexserverLinestateDestroy(ls_main_line);
    tunnelPrevDownStreamFinish(download_tunnel, download_line);

    if (lineIsAlive(upload_line))
    {
        const line_task_submit_result_e result =
            lineScheduleTask(upload_line, localAsyncCloseLineDownStream, upload_tunnel, NULL);
        if (result == kLineTaskSubmitRejectedSettled)
        {
            if (lineIsAlive(upload_line))
            {
                localAsyncCloseLineDownStream(upload_tunnel, upload_line);
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

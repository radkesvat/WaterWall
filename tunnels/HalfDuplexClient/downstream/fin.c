#include "structure.h"

#include "loggers/network_logger.h"

static void localAsyncCloseLine(worker_t *worker, void *arg1, void *arg2, void *arg3)
{
    discard worker;
    discard arg3;

    tunnel_t *t = arg1;
    line_t   *l = arg2;

    if (! lineIsAlive(l))
    {
        // The line is already closed, no need to do anything
        lineUnlock(l);
        return;
    }
    halfduplexclient_lstate_t *ls = lineGetState(l, t);

    if (! (ls->upload_line == NULL && ls->download_line == NULL))
    {
        halfduplexclientLinestateDestroy(ls);
        tunnelNextUpStreamFinish(t, l);
    }

    lineDestroy(l);
}

void halfduplexclientTunnelDownStreamFinish(tunnel_t *t, line_t *l)
{
    halfduplexclient_lstate_t *ls = lineGetState(l, t);

    if (l == ls->download_line)
    {
        if (ls->upload_line)
        {
            halfduplexclient_lstate_t *ls_upload_line = lineGetState(ls->upload_line, t);
            ls_upload_line->download_line             = NULL;
            ls_upload_line->main_line                 = NULL;
            lineLock(ls->upload_line);
            sendWorkerMessageForceQueue(lineGetWID(ls->upload_line), localAsyncCloseLine, t, ls->upload_line, NULL);
        }
    }
    else
    {
        if (ls->download_line)
        {
            halfduplexclient_lstate_t *ls_download_line = lineGetState(ls->download_line, t);
            ls_download_line->upload_line               = NULL;
            ls_download_line->main_line                 = NULL;
            lineLock(ls->download_line);
            sendWorkerMessageForceQueue(lineGetWID(ls->download_line), localAsyncCloseLine, t, ls->download_line, NULL);
        }
    }

    if (ls->main_line)
    {
        halfduplexclientLinestateDestroy(lineGetState(ls->main_line, t));
        tunnelPrevDownStreamFinish(t, ls->main_line);
    }

    halfduplexclientLinestateDestroy(ls);
    lineDestroy(l);
}

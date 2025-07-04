#include "structure.h"

#include "loggers/network_logger.h"

static void localAsyncCloseLine(worker_t *worker, void *arg1, void *arg2, void *arg3)
{

    discard worker;
    discard arg3;

    tunnel_t                  *t  = arg1;
    line_t                    *l  = arg2;
    halfduplexserver_lstate_t *ls = lineGetState(l, t);

    halfduplexserverLinestateDestroy(ls);
    tunnelPrevDownStreamFinish(t, l);
    lineUnlock(l);
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
    lineDestroy(l);

    lineLock(upload_line);
    sendWorkerMessageForceQueue(lineGetWID(upload_line), localAsyncCloseLine, t, upload_line, NULL);
}

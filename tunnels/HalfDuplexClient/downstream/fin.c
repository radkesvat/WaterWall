#include "structure.h"

#include "loggers/network_logger.h"

static void localAsyncCloseLine(tunnel_t *t, line_t *l)
{

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
            if (! lineScheduleTask(ls->upload_line, localAsyncCloseLine, t) && lineIsAlive(ls->upload_line))
            {
                /* HalfDuplexClient creates both companions on this worker. */
                localAsyncCloseLine(t, ls->upload_line);
            }
        }
    }
    else
    {
        if (ls->download_line)
        {
            halfduplexclient_lstate_t *ls_download_line = lineGetState(ls->download_line, t);
            ls_download_line->upload_line               = NULL;
            ls_download_line->main_line                 = NULL;
            if (! lineScheduleTask(ls->download_line, localAsyncCloseLine, t) && lineIsAlive(ls->download_line))
            {
                localAsyncCloseLine(t, ls->download_line);
            }
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

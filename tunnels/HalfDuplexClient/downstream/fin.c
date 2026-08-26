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
    halfduplexclient_lstate_t *ls           = lineGetState(l, t);
    line_t *const              main_line    = ls->main_line;
    line_t *const              sibling_line = l == ls->download_line ? ls->upload_line : ls->download_line;

    /* Cross-line callbacks below can close any other tracked line. Retain all
     * three allocations and detach/destroy this tunnel's state before the
     * first callback, so no continuation reads a re-entrantly destroyed slot. */
    lineRef(l);
    if (sibling_line != NULL)
    {
        lineRef(sibling_line);
        halfduplexclient_lstate_t *sibling_ls = lineGetState(sibling_line, t);
        sibling_ls->main_line                 = NULL;
        if (l == ls->download_line)
        {
            sibling_ls->download_line = NULL;
        }
        else
        {
            sibling_ls->upload_line = NULL;
        }
    }
    if (main_line != NULL)
    {
        lineRef(main_line);
        halfduplexclientLinestateDestroy(lineGetState(main_line, t));
    }
    halfduplexclientLinestateDestroy(ls);

    if (sibling_line != NULL && lineIsAlive(sibling_line))
    {
        const line_task_submit_result_e result = lineScheduleTask(sibling_line, localAsyncCloseLine, t, NULL);
        if (result == kLineTaskSubmitRejectedSettled)
        {
            if (lineIsAlive(sibling_line))
            {
                /* HalfDuplexClient creates both companions on this worker. */
                localAsyncCloseLine(t, sibling_line);
            }
        }
        else
        {
            assert(result == kLineTaskSubmitAcceptedAsync);
        }
    }

    if (main_line != NULL && lineIsAlive(main_line))
    {
        tunnelPrevDownStreamFinish(t, main_line);
    }

    if (lineIsAlive(l))
    {
        lineDestroy(l);
    }

    if (main_line != NULL)
    {
        lineUnref(main_line);
    }
    if (sibling_line != NULL)
    {
        lineUnref(sibling_line);
    }
    lineUnref(l);
}

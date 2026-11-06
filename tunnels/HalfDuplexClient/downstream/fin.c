#include "structure.h"

void halfduplexclientTunnelDownStreamFinish(tunnel_t *t, line_t *l)
{
    halfduplexclient_lstate_t *child = lineGetState(l, t);
    line_t                    *main  = child->main_line;
    if (main != NULL)
    {
        halfduplexclient_lstate_t *ls = lineGetState(main, t);
        if (ls->upload_line == l && ls->first_packet_sent)
        {
            // Upload can finish before the last response bytes reach download.
            lineRef(main);
            line_t *download      = ls->download_line;
            ls->upload_line       = NULL;
            ls->intro_dispatching = false;
            bufferqueueDestroy(&ls->pending_up);
            halfduplexclientLinestateDestroy(child);
            lineDestroy(l);

            // Retiring upload also retires its producer hold. Resume may close main.
            halfduplexclient_lstate_t *down = lineGetState(download, t);
            halfduplexclientSetNextPaused(t, download, down->next_paused);
            lineUnref(main);
            return;
        }
    }
    halfduplexclientClosePair(t, l, false, true);
}

#include "structure.h"

void halfduplexclientTunnelUpStreamInit(tunnel_t *t, line_t *main)
{
    halfduplexclient_lstate_t *ls = lineGetState(main, t);
    halfduplexclientLinestateInitialize(ls, main);
    ls->pair_initializing = true;
    lineRef(main);
    line_t *upload = lineCreate(tunnelchainGetLinePools(tunnelGetChain(t)), lineGetWID(main));
    lineRef(upload);
    halfduplexclient_lstate_t *up = lineGetState(upload, t);
    halfduplexclientLinestateInitialize(up, main);
    ls->upload_line = up->upload_line = upload;
    up->next_started                  = true;
    tunnelNextUpStreamInit(t, upload);
    if (! lineIsAlive(main) || ! lineIsAlive(upload) || ls->main_line != main)
    {
        lineUnref(upload);
        lineUnref(main);
        return;
    }
    line_t *download = lineCreate(tunnelchainGetLinePools(tunnelGetChain(t)), lineGetWID(main));
    lineRef(download);
    halfduplexclient_lstate_t *down = lineGetState(download, t);
    halfduplexclientLinestateInitialize(down, main);
    ls->download_line = up->download_line = down->download_line = download;
    down->upload_line                                           = upload;
    down->next_started                                          = true;
    tunnelNextUpStreamInit(t, download);
    if (halfduplexclientPairAlive(t, main, upload, download))
    {
        // A Pause received before the download child existed remains effective.
        halfduplexclientSetPrevPaused(t, main, ls->prev_paused);
        if (halfduplexclientPairAlive(t, main, upload, download))
        {
            ls->pair_initializing = false;
            if (halfduplexclientNotifyEstablished(t, main) && halfduplexclientPairAlive(t, main, upload, download))
                discard halfduplexclientDrainPending(t, main, false);
        }
    }
    lineUnref(download);
    lineUnref(upload);
    lineUnref(main);
}

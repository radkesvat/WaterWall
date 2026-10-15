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
    // Publishing a child immediately precedes its adjacent Init admission.
    ls->upload_line = upload;
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
    ls->download_line = download;
    tunnelNextUpStreamInit(t, download);
    if (halfduplexclientPairAlive(t, main, upload, download))
    {
        // A Pause received before the download child existed remains effective.
        if (ls->pending_read_pause)
            halfduplexclientSetPrevPaused(t, main, true);
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

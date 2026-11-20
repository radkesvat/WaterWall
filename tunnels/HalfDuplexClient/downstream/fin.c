#include "structure.h"

void halfduplexclientTunnelDownStreamFinish(tunnel_t *t, line_t *child)
{
    halfduplexclient_pair_t *pair = halfduplexclientGetPair(t, child);
    if (pair == NULL)
    {
        lineDestroy(child);
        return;
    }
    const bool upload = pair->upload == child;
    halfduplexclientCloseChild(pair, upload ? &pair->upload : &pair->download, false);
    if (pair->ending)
        return;
    if (upload)
    {
        halfduplexclientDiscardUpload(pair);
        pair->upload_paused = false;
    }
    if (pair->main == NULL)
    {
        if ((pair->upload == NULL && pair->download == NULL) || pair->intro == kHalfDuplexIntroPending)
            halfduplexclientEndPair(pair, NULL);
        else
            halfduplexclientPump(pair, NULL);
        return;
    }
    if (upload && pair->intro == kHalfDuplexUploadIntroSent)
    {
        // Keep the independent download open for the response tail. Reconcile
        // the surviving receiver's hold before a Resume can close the source.
        halfduplexclientSetNextPaused(t, pair->download, pair->download_paused);
        return;
    }
    halfduplexclientEndPair(pair, NULL);
}

#include "structure.h"

void halfduplexclientNotifyEstablished(halfduplexclient_pair_t *pair)
{
    if (pair->est_seen && ! pair->est_forwarded && ! pair->starting)
    {
        pair->est_forwarded = true;
        tunnelPrevDownStreamEst(pair->tunnel, pair->main);
    }
}

void halfduplexclientSetPrevPaused(tunnel_t *t, line_t *main, bool paused)
{
    halfduplexclient_pair_t *pair = halfduplexclientGetPair(t, main);
    if (pair == NULL || pair->ending)
        return;
    if (pair->download == NULL)
    {
        pair->pending_read_pause = paused;
        return;
    }
    halfduplexclient_tstate_t *ts = tunnelGetState(t);
    pair->pending_read_pause      = false;
    pair->download_read_paused    = paused;
    ++pair->refs;
    ++pair->handoff_depth;
    discard lineCallWithRef(pair->download, paused ? tunnelUpStreamPause : tunnelUpStreamResume, ts->download_tunnel);
    --pair->handoff_depth;
    halfduplexclientPump(pair, NULL);
    halfduplexclientReleasePair(pair);
}

void halfduplexclientSetNextPaused(tunnel_t *t, line_t *child, bool paused)
{
    halfduplexclient_pair_t *pair = halfduplexclientGetPair(t, child);
    if (pair == NULL || pair->ending)
        return;
    if (child == pair->upload)
        pair->upload_paused = paused;
    else
        pair->download_paused = paused;
    if (pair->main != NULL && (pair->upload_paused || pair->download_paused))
    {
        if (! pair->source_pause_sent)
        {
            pair->source_pause_sent = true;
            tunnelPrevDownStreamPause(t, pair->main);
        }
        return;
    }
    ++pair->refs;
    halfduplexclientPump(pair, NULL);
    if (pair->main != NULL && ! pair->upload_paused && ! pair->download_paused && pair->source_pause_sent)
    {
        pair->source_pause_sent = false;
        tunnelPrevDownStreamResume(t, pair->main);
    }
    halfduplexclientReleasePair(pair);
}

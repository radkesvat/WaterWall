#include "structure.h"

void halfduplexclientTunnelUpStreamFinish(tunnel_t *t, line_t *main)
{
    halfduplexclient_pair_t *pair = halfduplexclientGetPair(t, main);
    if (pair == NULL)
        return;
    halfduplexclientSetPair(t, main, NULL);
    pair->main = NULL;
    if (pair->ending)
        return;
    if (pair->starting || pair->upload == NULL || pair->download == NULL ||
        (pair->intro == kHalfDuplexIntroPending && bufferqueueGetEntryCount(&pair->pending) == 0))
    {
        halfduplexclientEndPair(pair, NULL);
        return;
    }
    halfduplexclientBeginDrain(pair);
}

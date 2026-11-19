#include "structure.h"

halfduplexclient_pair_t *halfduplexclientCreatePair(tunnel_t *t, line_t *main)
{
    halfduplexclient_pair_t *pair = memoryAllocate(sizeof(*pair));
    *pair = (halfduplexclient_pair_t) {.tunnel = t, .main = main, .pool = lineGetBufferPool(main), .refs = 1};
    bufferqueueInitEmpty(&pair->pending);
    halfduplexclientSetPair(t, main, pair);
    return pair;
}

// The association owns one reference through its last Finish notification.
// Frames which continue across a neighbor callback hold a temporary reference.
void halfduplexclientReleasePair(halfduplexclient_pair_t *pair)
{
    assert(pair->refs != 0);
    if (--pair->refs == 0)
    {
        assert(pair->ending && pair->main == NULL && pair->upload == NULL && pair->download == NULL);
        memoryFree(pair);
    }
}

void halfduplexclientDiscardUpload(halfduplexclient_pair_t *pair)
{
    if (pair->upload_intro != NULL)
    {
        bufferpoolReuseBuffer(pair->pool, pair->upload_intro);
        pair->upload_intro = NULL;
    }
    bufferqueueDestroy(&pair->pending);
}

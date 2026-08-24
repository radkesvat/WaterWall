#include "structure.h"

#include "loggers/network_logger.h"

void disturberLinestateInitialize(disturber_lstate_t *ls)
{
    *ls = (disturber_lstate_t) {
        .upstream   = {.is_deadhang = false, .finished = false, .held_payload = NULL},
        .downstream = {.is_deadhang = false, .finished = false, .held_payload = NULL},
    };
}

void disturberLinestateDestroy(line_t *l, disturber_lstate_t *ls)
{
    if (UNLIKELY(l == NULL || ! lineIsOnCurrentEventWorker(l)))
    {
        LOGF("Disturber: line-state destruction ran outside its owner worker");
        abortProgramNow(1);
    }

    assert(l != NULL && lineIsOnCurrentEventWorker(l));

    if (ls->upstream.held_payload != NULL)
    {
        lineReuseBuffer(l, ls->upstream.held_payload);
        ls->upstream.held_payload = NULL;
    }
    if (ls->downstream.held_payload != NULL)
    {
        lineReuseBuffer(l, ls->downstream.held_payload);
        ls->downstream.held_payload = NULL;
    }
    memoryZeroAligned32(ls, tunnelGetCorrectAlignedLineStateSize(sizeof(disturber_lstate_t)));
}

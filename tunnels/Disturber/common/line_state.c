#include "structure.h"

#include "loggers/network_logger.h"

void disturberLinestateInitialize(disturber_lstate_t *ls)
{
    *ls = (disturber_lstate_t){
        .upstream = {.is_deadhang = false, .held_payload = NULL},
        .downstream = {.is_deadhang = false, .held_payload = NULL}
    };
}

void disturberLinestateDestroy(disturber_lstate_t *ls)
{
    if (ls->upstream.held_payload != NULL)
    {
        reuseBuffer(ls->upstream.held_payload);
        ls->upstream.held_payload = NULL;
    }
    if (ls->downstream.held_payload != NULL)
    {
        reuseBuffer(ls->downstream.held_payload);
        ls->downstream.held_payload = NULL;
    }
    memoryZeroAligned32(ls, sizeof(disturber_lstate_t));
}

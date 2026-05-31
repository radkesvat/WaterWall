#include "structure.h"

#include "loggers/network_logger.h"

void bgp4clientLinestateInitialize(bgp4client_lstate_t *ls, line_t *l)
{
    *ls = (bgp4client_lstate_t) {
        .phase       = kBgp4ClientPhaseActive,
        .read_stream = bufferstreamCreate(lineGetBufferPool(l), 0),
        .open_sent   = false,
    };
}

void bgp4clientLinestateDestroy(bgp4client_lstate_t *ls)
{
    if (ls->phase == kBgp4ClientPhaseNone)
    {
        return;
    }

    bufferstreamDestroy(&ls->read_stream);
    memoryZeroAligned32(ls, sizeof(*ls));
}

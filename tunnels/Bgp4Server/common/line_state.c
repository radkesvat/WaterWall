#include "structure.h"

#include "loggers/network_logger.h"

void bgp4serverLinestateInitialize(bgp4server_lstate_t *ls, line_t *l)
{
    *ls = (bgp4server_lstate_t) {
        .read_stream   = bufferstreamCreate(lineGetBufferPool(l), 0),
        .open_received = false,
    };
}

void bgp4serverLinestateDestroy(bgp4server_lstate_t *ls)
{
    bufferstreamDestroy(&ls->read_stream);
    memoryZeroAligned32(ls, tunnelGetCorrectAlignedLineStateSize(sizeof(*ls)));
}

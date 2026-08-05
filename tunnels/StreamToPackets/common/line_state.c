#include "structure.h"

#include "loggers/network_logger.h"

/*
 * Only stream lines carry StreamToPackets line state. The chain's persistent
 * worker packet lines are pure forwarding targets for this tunnel: they get no
 * parser, no registry identity, and no routing role.
 */
void streamtopacketsLinestateInitialize(streamtopackets_lstate_t *ls, buffer_pool_t *pool)
{
    *ls = (streamtopackets_lstate_t) {.read_stream       = bufferstreamCreate(pool, 0),
                                      .line_id           = 0,
                                      .source_generation = 0,
                                      .tracked           = false,
                                      .active            = false,
                                      .write_paused      = false};
}

void streamtopacketsLinestateReset(streamtopackets_lstate_t *ls)
{
    if (ls->read_stream.pool != NULL)
    {
        bufferstreamEmpty(&ls->read_stream);
    }

    ls->line_id           = 0;
    ls->source_generation = 0;
    ls->tracked           = false;
    ls->active            = false;
    ls->write_paused      = false;
}

void streamtopacketsLinestateDestroy(streamtopackets_lstate_t *ls)
{
    if (ls->read_stream.pool != NULL)
    {
        bufferstreamDestroy(&ls->read_stream);
    }

    memoryZeroAligned32(ls, tunnelGetCorrectAlignedLineStateSize(sizeof(streamtopackets_lstate_t)));
}

#include "structure.h"

void softiplimiterLinestateInitialize(softiplimiter_lstate_t *ls, line_t *l)
{
    *ls = (softiplimiter_lstate_t) {
        .in_stream      = bufferstreamCreate(lineGetBufferPool(l), 0),
        .identifier     = 0,
        .ip_key         = {0},
        .phase          = kSoftIpLimiterPhaseWaitIdentity,
        .closing        = false,
        .admitted       = false,
        .next_init_sent = false,
        .ip_key_valid   = false,
    };
}

void softiplimiterLinestateDestroy(softiplimiter_lstate_t *ls)
{
    bufferstreamDestroy(&ls->in_stream);
    memoryZeroAligned32(ls, tunnelGetCorrectAlignedLineStateSize(sizeof(*ls)));
}


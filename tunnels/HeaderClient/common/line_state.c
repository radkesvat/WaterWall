#include "structure.h"

#include "loggers/network_logger.h"

void headerclientLinestateInitialize(headerclient_lstate_t *ls)
{
    *ls = (headerclient_lstate_t) {
        .phase       = kHeaderClientPhaseActive,
        .header_sent = false,
    };
}

void headerclientLinestateDestroy(headerclient_lstate_t *ls)
{
    if (ls->phase == kHeaderClientPhaseNone)
    {
        return;
    }

    memoryZeroAligned32(ls, sizeof(*ls));
}

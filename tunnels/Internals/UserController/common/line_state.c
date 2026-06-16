#include "structure.h"

#include "loggers/network_logger.h"

void usercontrollerLinestateInitialize(usercontroller_lstate_t *ls)
{
    *ls = (usercontroller_lstate_t) {
        .handle        = userHandleEmpty(),
        .ip_key        = {0},
        .authenticated = false,
        .managed       = false,
        .registered    = false,
        .closing       = false,
        .prev_finished = false,
        .next_finished = false,
    };
}

void usercontrollerLinestateDestroy(usercontroller_lstate_t *ls)
{
    memoryZeroAligned32(ls, tunnelGetCorrectAlignedLineStateSize(sizeof(*ls)));
}

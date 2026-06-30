#include "structure.h"

#include "loggers/network_logger.h"

void usercontrollerLinestateInitialize(usercontroller_lstate_t *ls, bool started_from_next)
{
    *ls = (usercontroller_lstate_t) {
        .handle            = userHandleEmpty(),
        .ip_key            = {0},
        .authenticated     = false,
        .managed           = false,
        .registered        = false,
        .closing           = false,
        .started_from_next = started_from_next,
    };
}

void usercontrollerLinestateDestroy(usercontroller_lstate_t *ls)
{
    memoryZeroAligned32(ls, tunnelGetCorrectAlignedLineStateSize(sizeof(*ls)));
}

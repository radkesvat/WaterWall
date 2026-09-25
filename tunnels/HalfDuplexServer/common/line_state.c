#include "structure.h"

#include "loggers/network_logger.h"

void halfduplexserverLinestateInitialize(halfduplexserver_lstate_t *ls)
{
    *ls =
        (halfduplexserver_lstate_t) {.state = kCsUnkown, .upload_line = NULL, .download_line = NULL, .main_line = NULL};
}

void halfduplexserverLinestateDestroy(halfduplexserver_lstate_t *ls)
{
    assert(ls->buffering == NULL);
    sbuf_t *initial     = ls->startup_initial;
    ls->startup_initial = NULL;
    if (initial != NULL)
        bufferpoolReuseBuffer(ls->startup_pool, initial);
    bufferqueueDestroy(&ls->startup_pending);
    bufferbudgetAssertEmpty(&ls->startup_budget);
    memoryZeroAligned32(ls, tunnelGetCorrectAlignedLineStateSize(sizeof(halfduplexserver_lstate_t)));
}

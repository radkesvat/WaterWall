#include "structure.h"

#include "loggers/network_logger.h"

void reverseclientLinestateInitialize(reverseclient_lstate_t *ls, tunnel_t *t, line_t *u, line_t *d)
{
    *ls = (reverseclient_lstate_t){
        .t = t,
        .u = u,
        .d = d,
        .idle_handle = NULL
    };
}

void reverseclientLinestateDestroy(reverseclient_lstate_t *ls)
{

    if (ls->idle_handle != NULL)
    {
        LOGF("ReverseClient: LinestateDestroy called with non NULL idle_handle");
        terminateProgram(1);
        return;
    }


    memorySet(ls, 0, sizeof(reverseclient_lstate_t));
}

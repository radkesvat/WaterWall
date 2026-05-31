#include "structure.h"

void sniffrouterLinestateInitialize(sniffrouter_lstate_t *ls)
{
    *ls = (sniffrouter_lstate_t) {
        .pending       = NULL,
        .decided       = kSniffUndecided,
        .next_finished = false,
        .prev_finished = false,
    };
}

void sniffrouterLinestateDestroy(line_t *l, sniffrouter_lstate_t *ls)
{
    if (ls->pending != NULL)
    {
        lineReuseBuffer(l, ls->pending);
        ls->pending = NULL;
    }

    memorySet(ls, 0, sizeof(*ls));
}

#include "APIServer/structure.h"

void apiserverUpStreamFinish(tunnel_t *t, line_t *line)
{
    /* Source Finish closes the sender; do not reflect it downstream. */
    apiserverLinestateDestroy(lineGetState(line, t));
}

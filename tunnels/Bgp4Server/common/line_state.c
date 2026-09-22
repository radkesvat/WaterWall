#include "structure.h"

bool bgp4serverLinestateInitialize(bgp4server_lstate_t *ls, line_t *l)
{
    return bgpStreamInitialize(ls, l, false);
}

void bgp4serverLinestateDestroy(bgp4server_lstate_t *ls)
{
    bgpStreamDestroy(ls);
}

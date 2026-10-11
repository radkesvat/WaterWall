#include "structure.h"

void bgp4serverLinestateInitialize(bgp4server_lstate_t *ls, line_t *l)
{
    bgpStreamInitialize(ls, l, false);
}

void bgp4serverLinestateDestroy(bgp4server_lstate_t *ls)
{
    bgpStreamDestroy(ls);
}

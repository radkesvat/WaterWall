#include "structure.h"

void bgp4clientLinestateInitialize(bgp4client_lstate_t *ls, line_t *l)
{
    bgpStreamInitialize(ls, l, true);
}

void bgp4clientLinestateDestroy(bgp4client_lstate_t *ls)
{
    bgpStreamDestroy(ls);
}

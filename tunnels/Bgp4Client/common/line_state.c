#include "structure.h"

void bgp4clientLinestateInitialize(bgp4client_lstate_t *ls, line_t *l, bool splice_output)
{
    bgpStreamInitialize(ls, l, true, splice_output);
}

void bgp4clientLinestateDestroy(bgp4client_lstate_t *ls)
{
    bgpStreamDestroy(ls);
}

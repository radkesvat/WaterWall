#include "structure.h"

void bgp4serverLinestateInitialize(bgp4server_lstate_t *ls, line_t *l, bool splice_output)
{
    bgpStreamInitialize(ls, l, false, splice_output);
}

void bgp4serverLinestateDestroy(bgp4server_lstate_t *ls)
{
    bgpStreamDestroy(ls);
}

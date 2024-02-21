#pragma once
#include "basic_types.h"
#include "komihash.h"


#define KOMIHASH_SEED 0


#define calcHash(x) komihash((x), sizeof( (x) ), KOMIHASH_SEED)
#define calcHashLen(x,len) komihash((x), len, KOMIHASH_SEED)


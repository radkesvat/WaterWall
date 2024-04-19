#pragma once
#include "basic_types.h"
#include "komihash.h"

#define KOMIHASH_SEED 0

#define CALC_HASH_PRIMITIVE(x)  komihash((x), sizeof((x)), KOMIHASH_SEED)
#define CALC_HASH_BYTES(x, len) komihash((x), len, KOMIHASH_SEED)

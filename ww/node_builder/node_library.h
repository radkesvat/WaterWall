#pragma once
#include "wlibc.h"

#include "objects/node.h"


node_t nodelibraryLoadByTypeName(const char *name);
node_t nodelibraryLoadByTypeHash(hash_t htype);

void nodelibraryRegister(node_t lib);
bool nodeHasFlagChainHead(node_t *node);

void nodelibraryCleanup(void);



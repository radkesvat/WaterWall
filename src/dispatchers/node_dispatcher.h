#pragma once

#include "node.h"


void initNodeDispatcher();


// zero terminated please, merci ah!
void includeNodeFile(char* data_json);

node_t* getNode(hash_t hash);

node_array_t* getListenerNodes();

void parseNodes();


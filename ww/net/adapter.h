#pragma once
#include "tunnel.h"




void adapterDefaultOnChainUpEnd(tunnel_t *t, tunnel_chain_t *tc);
void adapterDefaultOnChainDownEnd(tunnel_t *t, tunnel_chain_t *tc);


void adapterDefaultOnIndexUpEnd(tunnel_t *t, tunnel_array_t *arr, uint16_t *index, uint16_t *mem_offset);
void adapterDefaultOnIndexDownEnd(tunnel_t *t, tunnel_array_t *arr, uint16_t *index, uint16_t *mem_offset);


tunnel_t *adapterCreate(node_t *node, uint16_t tstate_size, uint16_t lstate_size, bool up_end);












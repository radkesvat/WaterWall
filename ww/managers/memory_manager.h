#pragma once
#include "wlibc.h"


struct dedicated_memory_s;
typedef struct dedicated_memory_s dedicated_memory_t;

/// opens global memory manager (call this once before first usage of global functions below)
void memorymanagerInit(void);

/// set the memory manager global state
void memorymanagerSetState(dedicated_memory_t *new_state);

dedicated_memory_t *memorymanagerCreateDedicatedMemory(void);




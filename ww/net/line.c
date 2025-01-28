#include "line.h"



pool_item_t *allocLinePoolHandle(generic_pool_t *pool)
{
    (void) pool;
    return memoryAllocate(sizeof(line_t));
}

void destroyLinePoolHandle(generic_pool_t *pool, pool_item_t *item)
{
    (void) pool;
    memoryFree(item);
}



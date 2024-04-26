#include "idle_table.h"

#define VEC_CAP 32

idle_table_t *newIdleTable(hloop_t *loop, OnIdleExpireCallBack cb)
{
    idle_table_t *newtable = malloc(sizeof(idle_table_t));
    *newtable              = (idle_table_t){.loop           = loop,
                               .hqueue         = heapq_idles_t_with_capacity(VEC_CAP),
                               .hmap           = hmap_idles_t_with_capacity(VEC_CAP),
                               .expire_cb      = cb,
                               .last_update_ms = hloop_now_ms(loop)};
    return newtable;
}



idle_item_t *newIdleItem(idle_table_t *self, hash_t key, uint64_t expire_at_ms){
    
}
// void         keepIdleItemForAtleast(idle_item_t *item, uint64_t expire_min_ms);
// idle_item_t *getItemByHash(idle_table_t *self, hash_t key);
// void         removeItemByHandle(idle_table_t *self, idle_item_t *item);
// void         removeItemByHash(idle_table_t *self, hash_t key);

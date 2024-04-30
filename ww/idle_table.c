#include "idle_table.h"
#include "basic_types.h"
#include "hdef.h"
#include "hloop.h"
#include "hmutex.h"
#include "ww.h"
#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

enum
{
    kVecCap = 32
};
void idleCallBack(hidle_t *idle);

void destoryIdleTable(idle_table_t *self)
{
    hidle_del(self->idle_handle);
    heapq_idles_t_drop(&(self->hqueue));
    hmap_idles_t_drop(&(self->hmap));
}

idle_table_t *newIdleTable(hloop_t *loop, OnIdleExpireCallBack cb)
{
    idle_table_t *newtable = malloc(sizeof(idle_table_t));
    *newtable              = (idle_table_t){.loop           = loop,
                                            .idle_handle    = hidle_add(loop, idleCallBack, INFINITE),
                                            .hqueue         = heapq_idles_t_with_capacity(kVecCap),
                                            .hmap           = hmap_idles_t_with_capacity(kVecCap),
                                            .expire_cb      = cb,
                                            .last_update_ms = hloop_now_ms(loop)};

    hhybridmutex_init(&(newtable->mutex));
    hevent_set_userdata(newtable->idle_handle, newtable);
    return newtable;
}

idle_item_t *newIdleItem(idle_table_t *self, hash_t key, void *userdata, uint8_t tid, uint64_t age_ms)
{
    assert(self && self->expire_cb);
    idle_item_t *item = malloc(sizeof(idle_item_t));
    hhybridmutex_lock(&(self->mutex));

    *item = (idle_item_t){.expire_at_ms = hloop_now_ms(self->loop) + age_ms,
                          .hash         = key,
                          .tid          = tid,
                          .userdata     = userdata,
                          .cb           = self->expire_cb};

    heapq_idles_t_push(&(self->hqueue), item);

    hmap_idles_t_push(&(self->hmap), (hmap_idles_t_value){item->hash, item});
    hhybridmutex_unlock(&(self->mutex));
    return item;
}
void keepIdleItemForAtleast(idle_table_t *self, idle_item_t *item, uint64_t age_ms)
{
    hhybridmutex_lock(&(self->mutex));
    item->expire_at_ms += self->last_update_ms + age_ms;
    heapq_idles_t_make_heap(&self->hqueue);
    hhybridmutex_unlock(&(self->mutex));
}
idle_item_t *getIdleItemByHash(idle_table_t *self, hash_t key)
{
    hhybridmutex_lock(&(self->mutex));

    hmap_idles_t_iter find_result = hmap_idles_t_find(&(self->hmap), key);
    if (find_result.ref == hmap_idles_t_end(&(self->hmap)).ref)
    {
        hhybridmutex_unlock(&(self->mutex));
        return NULL;
    }
    hhybridmutex_unlock(&(self->mutex));
    return (find_result.ref->second);
}

void removeIdleItemByHandle(idle_table_t *self, idle_item_t *item)
{
    assert(item != NULL && item->hash != 0x0);
    hash_t item_hash = item->hash;

    // enough to say its no longer in heap queue
    *item = (idle_item_t){};

    hhybridmutex_lock(&(self->mutex));
    hmap_idles_t_erase(&(self->hmap), item_hash);
    heapq_idles_t_make_heap(&self->hqueue);
    hhybridmutex_unlock(&(self->mutex));

    // alternative:
    // const uint64_t et         = item->expire_at_ms;
    // idle_item_t  **heap_items = (idle_item_t **) heapq_idles_t_top(&(self->hqueue));
    // size_t         heap_size  = heapq_idles_t_size(&(self->hqueue));
    // for (size_t i = 0; i < heap_size; i++)
    // {
    //     if (et == heap_items[i]->expire_at_ms)
    //     {
    //         heapq_idles_t_erase_at(&(self->hqueue), i);
    //         break;
    //     }
    // }
}
void removeIdleItemByHash(idle_table_t *self, hash_t key)
{
    removeIdleItemByHandle(self, getIdleItemByHash(self, key));
}

static void beforeCloseCallBack(hevent_t *ev)
{
    idle_item_t   *item  = hevent_userdata(ev);
    const uint64_t oldex = item->expire_at_ms;
    item->cb(item);
    if (oldex <= item->expire_at_ms)
    {
        free(item);
    }
}
void idleCallBack(hidle_t *idle)
{
    idle_table_t  *self  = hevent_userdata(idle);
    const uint64_t now   = hloop_now_ms(self->loop);
    self->last_update_ms = now;
    hhybridmutex_lock(&(self->mutex));

    while (heapq_idles_t_size(&(self->hqueue)) > 0)
    {
        idle_item_t *item = *heapq_idles_t_top(&(self->hqueue));

        if (item->expire_at_ms <= now)
        {
            heapq_idles_t_pop(&(self->hqueue));

            if (! item->cb)

            {
                hmap_idles_t_erase(&(self->hmap), item->hash);
                hevent_t ev;
                memset(&ev, 0, sizeof(ev));
                ev.loop = loops[item->tid];
                ev.cb   = beforeCloseCallBack;
                hevent_set_userdata(&ev, item);

                hloop_post_event(loops[item->tid], &ev);
            }
        }
        else
        {
            break;
        }
    }
    hhybridmutex_unlock(&(self->mutex));
}
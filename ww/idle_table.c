#include "idle_table.h"
#include "ww.h"

#define VEC_CAP 32
void idleCallBack(hidle_t *idle);

void destoryIdleTable(idle_table_t *self)
{
    hidle_del(self->idle_handle);
    heapq_idles_t_drop(&(self->hqueue));
    hmap_idles_t_drop(&(self->hmap));
}

idle_table_t *newIdleTable(uint8_t tid, OnIdleExpireCallBack cb)
{
    idle_table_t *newtable = malloc(sizeof(idle_table_t));
    *newtable              = (idle_table_t){.tid            = tid,
                                            .loop           = loops[tid],
                                            .idle_handle    = hidle_add(loops[tid], idleCallBack, INFINITE),
                                            .hqueue         = heapq_idles_t_with_capacity(VEC_CAP),
                                            .hmap           = hmap_idles_t_with_capacity(VEC_CAP),
                                            .expire_cb      = cb,
                                            .last_update_ms = hloop_now_ms(loops[tid])};

    hspinlock_init(&(newtable->slock));
    hevent_set_userdata(newtable->idle_handle, newtable);
    return newtable;
}

idle_item_t *newIdleItem(idle_table_t *self, hash_t key, void *userdata, uint8_t tid, uint64_t age_ms)
{
    assert(self && self->expire_cb);
    idle_item_t *item = malloc(sizeof(idle_item_t));
    hspinlock_lock(&(self->slock));

    *item = (idle_item_t){.expire_at_ms = hloop_now_ms(self->loop) + age_ms,
                          .hash         = key,
                          .tid          = tid,
                          .userdata     = userdata,
                          .cb           = self->expire_cb};

    heapq_idles_t_push(&(self->hqueue), item);
    
    hmap_idles_t_push(&(self->hmap), (hmap_idles_t_value){item->hash, item});
    hspinlock_unlock(&(self->slock));
    return item;
}
void keepIdleItemForAtleast(idle_table_t *self, idle_item_t *item, uint64_t age_ms)
{
    hspinlock_lock(&(self->slock));
    item->expire_at_ms += self->last_update_ms + age_ms;
    heapq_idles_t_make_heap(&self->hqueue);
    hspinlock_unlock(&(self->slock));
}
idle_item_t *getIdleItemByHash(idle_table_t *self, hash_t key)
{
    hspinlock_lock(&(self->slock));

    hmap_idles_t_iter find_result = hmap_idles_t_find(&(self->hmap), key);
    if (find_result.ref == hmap_idles_t_end(&(self->hmap)).ref)
    {
        hspinlock_unlock(&(self->slock));
        return NULL;
    }
    hspinlock_unlock(&(self->slock));
    return (find_result.ref->second);
}

void removeIdleItemByHandle(idle_table_t *self, idle_item_t *item)
{
    if (item == NULL)
    {
        return;
    }
    // enough to say its no longer in heap queue
    item->userdata == NULL;

    hspinlock_lock(&(self->slock));
    hmap_idles_t_erase(&(self->hmap), item->hash);
    hspinlock_unlock(&(self->slock));

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

void beforeCloseCallBack(hevent_t *ev)
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
    hspinlock_lock(&(self->slock));

    while (heapq_idles_t_size(&(self->hqueue)) > 0)
    {
        idle_item_t *item = *heapq_idles_t_top(&(self->hqueue));

        if (item->expire_at_ms <= now)
        {
            heapq_idles_t_pop(&(self->hqueue));

            if (item->userdata)
            {
                hmap_idles_t_erase(&(self->hmap), item->hash);
                hevent_t ev;
                memset(&ev, 0, sizeof(ev));
                ev.loop = loops[item->tid];
                ev.cb   = beforeCloseCallBack;
                hevent_set_userdata(&ev, item);
                if (item->tid == self->tid)
                {
                    beforeCloseCallBack(&ev);
                }
                else
                {
                    hloop_post_event(loops[item->tid], &ev);
                }
            }
        }
        else
        {
            break;
        }
    }
    hspinlock_unlock(&(self->slock));
}
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

#define i_TYPE                    heapq_idles_t, struct idle_item_s *
#define i_cmp                     -c_default_cmp                                // NOLINT
#define idletable_less_func(x, y) ((*(x))->expire_at_ms < (*(y))->expire_at_ms) // NOLINT
#define i_less                    idletable_less_func                           // NOLINT
#include "stc/pque.h"

#define i_TYPE hmap_idles_t, uint64_t, struct idle_item_s *
#include "stc/hmap.h"

struct udp_listener_state_s
{
    // settings
    char    *address;
    int      multiport_backend;
    uint16_t port_min;
    uint16_t port_max;
    char   **white_list_raddr;
    char   **black_list_raddr;
};
struct idle_table_s
{
    hloop_t       *loop;
    htimer_t      *idle_handle;
    heapq_idles_t  hqueue;
    hmap_idles_t   hmap;
    hhybridmutex_t mutex;
    uint64_t       last_update_ms;
};

void idleCallBack(htimer_t *timer);

void destoryIdleTable(idle_table_t *self)
{
    htimer_del(self->idle_handle);
    heapq_idles_t_drop(&(self->hqueue));
    hmap_idles_t_drop(&(self->hmap));
}

idle_table_t *newIdleTable(hloop_t *loop)
{
    idle_table_t *newtable = malloc(sizeof(idle_table_t));
    *newtable              = (idle_table_t){.loop           = loop,
                                            .idle_handle    = htimer_add_period(loop, idleCallBack, 1, 0, 0, 0, 0, INFINITE),
                                            .hqueue         = heapq_idles_t_with_capacity(kVecCap),
                                            .hmap           = hmap_idles_t_with_capacity(kVecCap),
                                            .last_update_ms = hloop_now_ms(loop)};

    hhybridmutex_init(&(newtable->mutex));
    hevent_set_userdata(newtable->idle_handle, newtable);
    return newtable;
}

idle_item_t *newIdleItem(idle_table_t *self, hash_t key, void *userdata, ExpireCallBack cb, uint8_t tid,
                         uint64_t age_ms)
{
    assert(self);
    idle_item_t *item = malloc(sizeof(idle_item_t));
    hhybridmutex_lock(&(self->mutex));

    *item = (idle_item_t){
        .expire_at_ms = hloop_now_ms(loops[tid]) + age_ms, .hash = key, .tid = tid, .userdata = userdata, .cb = cb};

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

// static void removeIdleItemByHandle(idle_table_t *self, idle_item_t *item)
// {
//     hash_t item_hash = item->hash;

//     // enough to say its no longer in heap queue
//     *item = (idle_item_t){};

//     hhybridmutex_lock(&(self->mutex));
//     hmap_idles_t_erase(&(self->hmap), item_hash);
//     heapq_idles_t_make_heap(&self->hqueue);
//     hhybridmutex_unlock(&(self->mutex));

//     // alternative:
//     // const uint64_t et         = item->expire_at_ms;
//     // idle_item_t  **heap_items = (idle_item_t **) heapq_idles_t_top(&(self->hqueue));
//     // size_t         heap_size  = heapq_idles_t_size(&(self->hqueue));
//     // for (size_t i = 0; i < heap_size; i++)
//     // {
//     //     if (et == heap_items[i]->expire_at_ms)
//     //     {
//     //         heapq_idles_t_erase_at(&(self->hqueue), i);
//     //         break;
//     //     }
//     // }
// }
bool removeIdleItemByHash(idle_table_t *self, hash_t key)
{
    hhybridmutex_lock(&(self->mutex));

    hmap_idles_t_iter find_result = hmap_idles_t_find(&(self->hmap), key);
    if (find_result.ref == hmap_idles_t_end(&(self->hmap)).ref)
    {
        hhybridmutex_unlock(&(self->mutex));
        return false;
    }
    idle_item_t *item = (find_result.ref->second);
    hmap_idles_t_erase_at(&(self->hmap), find_result);
    *item = (idle_item_t){0};
    heapq_idles_t_make_heap(&self->hqueue);

    hhybridmutex_unlock(&(self->mutex));
    return true;
}

static void beforeCloseCallBack(hevent_t *ev)
{
    idle_item_t   *item  = hevent_userdata(ev);
    item->cb(item);
    free(item);
}
void idleCallBack(htimer_t *timer)
{
    idle_table_t  *self  = hevent_userdata(timer);
    const uint64_t now   = hloop_now_ms(self->loop);
    self->last_update_ms = now;
    hhybridmutex_lock(&(self->mutex));

    while (heapq_idles_t_size(&(self->hqueue)) > 0)
    {
        idle_item_t *item = *heapq_idles_t_top(&(self->hqueue));

        if (item->expire_at_ms <= now)
        {
            heapq_idles_t_pop(&(self->hqueue));

            if (item->cb)
            {
                // destruction must happen on other thread
                hmap_idles_t_erase(&(self->hmap), item->hash);
                hevent_t ev;
                memset(&ev, 0, sizeof(ev));
                ev.loop = loops[item->tid];
                ev.cb   = beforeCloseCallBack;
                hevent_set_userdata(&ev, item);

                hloop_post_event(loops[item->tid], &ev);
            }
            else
            {
                // already removed
                free(item);
            }
        }
        else
        {
            break;
        }
    }
    hhybridmutex_unlock(&(self->mutex));
}

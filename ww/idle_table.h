#pragma once

#include "hloop.h"
#include "hmutex.h"
#include "utils/hashutils.h"
// thread safe idle table

// NOLINTBEGIN
#define i_TYPE heapq_idles_t, struct idle_item_s *
#define i_less idletable_less_func(x, y)((*x)->expire_at_ms < (*y)->expire_at_ms)
#define i_cmp  -c_default_cmp
#include "stc/pque.h"

#define i_TYPE hmap_idles_t, uint64_t, struct idle_item_s * // NOLINT
#include "stc/hmap.h"
// NOLINTEND


typedef struct idle_item_s
{
    uint64_t expire_at_ms;
    hash_t   hash;
    void *   userdata

} idle_item_t;

typedef void (*OnIdleExpireCallBack)(struct idle_item_s *);

typedef struct idle_table_s
{
    hloop_t *            loop;
    heapq_idles_t        hqueue;
    hmap_idles_t         hmap;
    uint64_t             last_update_ms;
    OnIdleExpireCallBack expire_cb;
} idle_table_t;

idle_table_t *newIdleTable(hloop_t *loop, OnIdleExpireCallBack cb);
idle_item_t * newIdleItem(idle_table_t *self, hash_t key, uint64_t expire_at_ms);
void          keepIdleItemForAtleast(idle_item_t *item, uint64_t expire_min_ms);
idle_item_t * getItemByHash(idle_table_t *self, hash_t key);
void          removeItemByHandle(idle_table_t *self, idle_item_t *item);
void          removeItemByHash(idle_table_t *self, hash_t key);

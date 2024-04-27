#pragma once

#include "hloop.h"
#include "hmutex.h"
#include "utils/hashutils.h"

/*
    Thread safe idle table

    What dose it mean "idle table?"
    in simple words, you put a object (idle_item) inside the table 
    the idle_item has a timeout (or deadline), if the timeout expires
    the idle_item is removed from the table and the callback you provided is called.
    you also can keep updating the item timeout

    The time checking has no cost and won't syscall at all, and the checking is synced by the 
    eventloop which by default wakes up every 100 ms.

*/

struct idle_item_s;
typedef void (*OnIdleExpireCallBack)(struct idle_item_s *);

typedef struct idle_item_s
{
    uint64_t             expire_at_ms;
    hash_t               hash;
    void                *userdata;
    uint8_t              tid;
    OnIdleExpireCallBack cb; // shortcut table cb
} idle_item_t;


#define i_TYPE                    heapq_idles_t, struct idle_item_s *
#define i_cmp                     -c_default_cmp                                // NOLINT
#define idletable_less_func(x, y) ((*(x))->expire_at_ms < (*(y))->expire_at_ms) // NOLINT
#define i_less                    idletable_less_func                           // NOLINT

#include "stc/pque.h"

#define i_TYPE hmap_idles_t, uint64_t, struct idle_item_s *
#include "stc/hmap.h"


typedef struct idle_table_s
{
    uint8_t              tid;
    hloop_t             *loop;
    hidle_t             *idle_handle;
    heapq_idles_t        hqueue;
    hmap_idles_t         hmap;
    hspinlock_t          slock;
    uint64_t             last_update_ms;
    OnIdleExpireCallBack expire_cb;
} idle_table_t;

idle_table_t *newIdleTable(uint8_t tid, OnIdleExpireCallBack cb);
idle_item_t  *newIdleItem(idle_table_t *self, hash_t key, void *userdata, uint8_t tid, uint64_t age_ms);
idle_item_t  *getIdleItemByHash(idle_table_t *self, hash_t key);
void          destoryIdleTable(idle_table_t *self);
void          keepIdleItemForAtleast(idle_table_t *self, idle_item_t *item, uint64_t age_ms);
void          removeIdleItemByHandle(idle_table_t *self, idle_item_t *item);
void          removeIdleItemByHash(idle_table_t *self, hash_t key);

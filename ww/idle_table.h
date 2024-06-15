#pragma once

#include "basic_types.h"
#include "hloop.h"
#include <stdint.h>

/*
    Thread safe idle table

    What dose it mean "idle table?"
    in simple words, you put a object (idle_item) inside the table
    the idle_item has a timeout (or deadline), if the timeout expires
    the idle_item is removed from the table and the callback you provided is called.
    you also can keep updating the item timeout

    The time checking has no cost and won't syscall at all, and the checking is synced by the
    eventloop which by default wakes up every 100 ms. (debug note: current idletable interval is set to 1s)

    idle item is a threadlocal item, it belongs to the thread that created it
    and other threads must not change , remove or do anything to it
    because of that, tid parameter is required in order to find the item

    -- valgrind unfriendly, since we required 64byte alignment, so it says "possibly lost"
       but the pointer is saved in "memptr" field inside the object
*/

struct idle_item_s;
typedef void (*ExpireCallBack)(struct idle_item_s *);

struct idle_item_s;
typedef struct idle_item_s idle_item_t;

// idle item is threadlocal
struct idle_item_s
{
    void          *userdata;
    hash_t         hash;
    ExpireCallBack cb;
    uint64_t       expire_at_ms;
    uint8_t        tid;
    bool           removed;
};

typedef struct idle_table_s idle_table_t;

idle_table_t *newIdleTable(hloop_t *loop);
void          destoryIdleTable(idle_table_t *self);

idle_item_t *newIdleItem(idle_table_t *self, hash_t key, void *userdata, ExpireCallBack cb, uint8_t tid,
                         uint64_t age_ms);
idle_item_t *getIdleItemByHash(uint8_t tid, idle_table_t *self, hash_t key);
void         keepIdleItemForAtleast(idle_table_t *self, idle_item_t *item, uint64_t age_ms);
bool         removeIdleItemByHash(uint8_t tid, idle_table_t *self, hash_t key);

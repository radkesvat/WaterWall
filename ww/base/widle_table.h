#pragma once

#include "wlibc.h"
#include "worker.h"
#include "wloop.h"

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

    -- valgrind unfriendly, since we required 64byte alignment, so it says "possibly/definitely lost"
       but the pointer is saved in "memptr" field inside the object

    note that libhv timer is also not a real timer, but is a heap like timer
    i didnt know this when i created the idle table but, this is still useful i believe and
    has its own usecases
*/

struct widle_item_s;
typedef void (*ExpireCallBack)(struct widle_item_s *);

struct widle_item_s;
typedef struct widle_item_s  idle_item_t;
typedef struct widle_table_s widle_table_t;

// idle item is threadlocal
struct widle_item_s
{
    void          *userdata;
    widle_table_t  *table;
    hash_t         hash;
    ExpireCallBack cb;
    uint64_t       expire_at_ms;
    uint8_t        tid;
    bool           removed;
};

widle_table_t *idleTableCreate(wloop_t *loop);
void          idleTableDestroy(widle_table_t *self);

idle_item_t *idleItemNew(widle_table_t *self, hash_t key, void *userdata, ExpireCallBack cb, wid_t tid,
                         uint64_t age_ms);
idle_item_t *idleTableGetIdleItemByHash(wid_t tid, widle_table_t *self, hash_t key);
void         idleTableKeepIdleItemForAtleast(widle_table_t *self, idle_item_t *item, uint64_t age_ms);
bool         idleTableRemoveIdleItemByHash(wid_t tid, widle_table_t *self, hash_t key);

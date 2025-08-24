/**
 * @file widle_table.c
 * @brief Implementation of a thread-safe idle table.
 *
 * This file implements a heap-based timer mechanism that periodically
 * checks idle items for expiration and invokes their callbacks.
 */

#include "widle_table.h"

#include "global_state.h"
#include "wdef.h"
#include "wloop.h"
#include "wmutex.h"

#include "loggers/internal_logger.h"

enum
{
    kIdleTableCap   = 32,
    kDefaultTimeout = 1000 // 1 second
};

#define i_type                    heapq_idles_t
#define i_key                     idle_item_t *
#define i_cmp                     -c_default_cmp                                // NOLINT
#define idletable_less_func(x, y) ((*(x))->expire_at_ms > (*(y))->expire_at_ms) // NOLINT
#define i_less                    idletable_less_func                           // NOLINT
#include "stc/pqueue.h"

#define i_type hmap_idles_t
#define i_key  uint64_t
#define i_val  idle_item_t *
#include "stc/hmap.h"

typedef MSVC_ATTR_ALIGNED_LINE_CACHE struct idle_table_s
{
    wloop_t      *loop;
    wtimer_t     *idle_handle;
    heapq_idles_t hqueue;
    hmap_idles_t  hmap;
    wmutex_t      mutex;
    uint64_t      last_update_ms;
    uintptr_t     memptr;

} GNU_ATTR_ALIGNED_LINE_CACHE idle_table_t;

void idleCallBack(wtimer_t *timer);


idle_table_t *idleTableCreate(wloop_t *loop)
{
    wloopUpdateTime(loop);
    // assert(sizeof(idle_table_t) <= kCpuLineCacheSize); promotion to 128 bytes
    size_t memsize = sizeof(idle_table_t);
    // ensure we have enough space to offset the allocation by line cache (for alignment)
    memsize = ALIGN2(memsize + ((kCpuLineCacheSize + 1) / 2), kCpuLineCacheSize);

    // check for overflow
    if (memsize < sizeof(idle_table_t))
    {
        printError("buffer size out of range");
        terminateProgram(1);
    }

    // allocate memory, placing idle_table_t at a line cache address boundary
    uintptr_t ptr = (uintptr_t) memoryAllocate(memsize);

    idle_table_t *newtable = (idle_table_t *) ALIGN2(ptr, kCpuLineCacheSize); // NOLINT

    *newtable = (idle_table_t){.memptr         = ptr,
                               .loop           = loop,
                               .idle_handle    = wtimerAdd(loop, idleCallBack, kDefaultTimeout, INFINITE),
                               .hqueue         = heapq_idles_t_with_capacity(kIdleTableCap),
                               .hmap           = hmap_idles_t_with_capacity(kIdleTableCap),
                               .last_update_ms = wloopNowMS(loop)};

    mutexInit(&(newtable->mutex));
    weventSetUserData(newtable->idle_handle, newtable);
    return newtable;
}


idle_item_t *idletableCreateItem(idle_table_t *self, hash_t key, void *userdata, ExpireCallBack cb, wid_t wid,
                                 uint64_t age_ms)
{
    assert(self);
    idle_item_t *item = memoryAllocate(sizeof(idle_item_t));
    mutexLock(&(self->mutex));

    *item = (idle_item_t){.expire_at_ms = wloopNowMS(self->loop) + age_ms,
                          .hash         = key,
                          .wid          = wid,
                          .userdata     = userdata,
                          .cb           = cb,
                          .table        = self};

    // LOGD("add to expire on idle table, wid: %ld, hash: %lx, expire_at_ms: %lu", wid, key, item->expire_at_ms);
    if (! hmap_idles_t_insert(&(self->hmap), item->hash, item).inserted)
    {
        // hash is already in the table !
        mutexUnlock(&(self->mutex));
        memoryFree(item);
        return NULL;
    }
    heapq_idles_t_push(&(self->hqueue), item);
    mutexUnlock(&(self->mutex));
    return item;
}


void idletableKeepIdleItemForAtleast(idle_table_t *self, idle_item_t *item, uint64_t age_ms)
{
    if (item->removed)
    {
        printError("IdleTable: Attempt to keep an already removed idle item alive");
        terminateProgram(1);
        return;
    }
    item->expire_at_ms = wloopNowMS(self->loop) + age_ms;

    // calling it before processing the heap
    // mutexLock(&(self->mutex));
    // heapq_idles_t_make_heap(&self->hqueue);
    // mutexUnlock(&(self->mutex));
}


idle_item_t *idletableGetIdleItemByHash(wid_t wid, idle_table_t *self, hash_t key)
{
    mutexLock(&(self->mutex));

    hmap_idles_t_iter find_result = hmap_idles_t_find(&(self->hmap), key);
    if (find_result.ref == hmap_idles_t_end(&(self->hmap)).ref || find_result.ref->second->wid != wid)
    {
        mutexUnlock(&(self->mutex));
        return NULL;
    }
    mutexUnlock(&(self->mutex));
    return (find_result.ref->second);
}


bool idletableRemoveIdleItemByHash(wid_t wid, idle_table_t *self, hash_t key)
{
    mutexLock(&(self->mutex));
    hmap_idles_t_iter find_result = hmap_idles_t_find(&(self->hmap), key);
    if (find_result.ref == hmap_idles_t_end(&(self->hmap)).ref || find_result.ref->second->wid != wid)
    {
        mutexUnlock(&(self->mutex));
        return false;
    }
    idle_item_t *item = (find_result.ref->second);
    hmap_idles_t_erase_at(&(self->hmap), find_result);
    item->removed = true; // Note: The item remains in the heap (lazy deletion)
    // heapq_idles_t_make_heap(&self->hqueue);

    mutexUnlock(&(self->mutex));
    return true;
}

/**
 * @brief Callback invoked by the timer when an idle item is about to be closed.
 *
 * This function executes the expiration callback if applicable or removes
 * the idle item.
 *
 * @param ev Pointer to the event structure.
 */
static void beforeCloseCallBack(wevent_t *ev)
{
    idle_item_t *item = weventGetUserdata(ev);
    if (! item->removed)
    {
        if (item->expire_at_ms > wloopNowMS(getWorkerLoop(item->wid)))
        {
            mutexLock(&(item->table->mutex));
            heapq_idles_t_push(&(item->table->hqueue), item);
            mutexUnlock(&(item->table->mutex));
            return;
        }

        // LOGD("item expired, wid: %ld, hash: %lx, expire_at_ms: %lu, now: %lu", item->wid, item->hash,
        //      item->expire_at_ms, wloopNowMS(getWorkerLoop(item->wid)));

        uint64_t old_expire_at_ms = item->expire_at_ms;

        if (item->cb)
        {
            item->cb(item);
        }

        if (old_expire_at_ms != item->expire_at_ms && item->expire_at_ms > wloopNowMS(getWorkerLoop(item->wid)))
        {
            mutexLock(&(item->table->mutex));
            heapq_idles_t_push(&(item->table->hqueue), item);
            mutexUnlock(&(item->table->mutex));
        }
        else
        {
            bool removal_result = idletableRemoveIdleItemByHash(item->wid, item->table, item->hash);
            assert(removal_result);
            discard removal_result;
            memoryFree(item);
        }
    }
    else
    {
        memoryFree(item);
    }
}


void idleCallBack(wtimer_t *timer)
{
    uint64_t next_timeout = kDefaultTimeout;

    idle_table_t  *self  = weventGetUserdata(timer);
    const uint64_t now   = wloopNowMS(self->loop);
    self->last_update_ms = now;
    mutexLock(&(self->mutex));
    // LOGD("idleCallBack called, wid: %ld , loop current ms: %lu", getWID(), wloopNowMS(self->loop));

    heapq_idles_t_make_heap(&self->hqueue);

    while (heapq_idles_t_size(&(self->hqueue)) > 0)
    {
        idle_item_t *item = *heapq_idles_t_top(&(self->hqueue));

        if (item->expire_at_ms <= now)
        {
            heapq_idles_t_pop(&(self->hqueue));

            if (item->removed)
            {
                // already removed
                memoryFree(item);
            }
            else
            {
                // Post event to process item on its worker thread.
                wevent_t ev;
                memorySet(&ev, 0, sizeof(ev));
                ev.loop = getWorkerLoop(item->wid);
                ev.cb   = beforeCloseCallBack;
                weventSetUserData(&ev, item);
                wloopPostEvent(getWorkerLoop(item->wid), &ev);
            }
        }
        else
        {
            next_timeout = min(next_timeout, item->expire_at_ms - now);
            break;
        }
    }
    mutexUnlock(&(self->mutex));

    wtimerReset(timer, (uint32_t) (next_timeout));
}


void idletableDestroy(idle_table_t *self)
{
    // if our loop is destroyed then the loop it self has freed the timer handle
    if (! atomicLoadExplicit(&GSTATE.application_stopping_flag, memory_order_acquire))
    {
        wtimerDelete(self->idle_handle);
    }

    // Free all idle items before dropping the containers
    mutexLock(&(self->mutex));

    // Iterate through the hash map and free each idle item
    while (heapq_idles_t_size(&(self->hqueue)) > 0)
    {
        idle_item_t *item = *heapq_idles_t_top(&(self->hqueue));
        heapq_idles_t_pop(&(self->hqueue));
        memoryFree(item);
    }

    mutexUnlock(&(self->mutex));

    heapq_idles_t_drop(&self->hqueue);
    hmap_idles_t_drop(&self->hmap);
    mutexDestroy(&self->mutex);
    memoryFree((void *) (self->memptr)); // NOLINT
}

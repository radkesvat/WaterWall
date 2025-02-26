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

enum
{
    kVecCap = 32
};

#define i_type                    heapq_idles_t
#define i_key                     struct widle_item_s *
#define i_cmp                     -c_default_cmp                                // NOLINT
#define idletable_less_func(x, y) ((*(x))->expire_at_ms < (*(y))->expire_at_ms) // NOLINT
#define i_less                    idletable_less_func                           // NOLINT
#include "stc/pqueue.h"

#define i_type hmap_idles_t
#define i_key  uint64_t
#define i_val  struct widle_item_s *
#include "stc/hmap.h"

typedef MSVC_ATTR_ALIGNED_LINE_CACHE struct widle_table_s
{
    wloop_t      *loop;
    wtimer_t     *idle_handle;
    heapq_idles_t hqueue;
    hmap_idles_t  hmap;
    wmutex_t      mutex;
    uint64_t      last_update_ms;
    uintptr_t     memptr;

} GNU_ATTR_ALIGNED_LINE_CACHE widle_table_t;

void idleCallBack(wtimer_t *timer);

/**
 * @brief Creates and initializes a new idle table.
 *
 * Allocates memory aligned to cache boundaries, initializes the internal heap and map,
 * and starts the timer callback.
 *
 * @param loop Pointer to the event loop.
 * @return Pointer to the newly created idle table.
 */
widle_table_t *idleTableCreate(wloop_t *loop)
{
    // assert(sizeof(widle_table_t) <= kCpuLineCacheSize); promotion to 128 bytes
    size_t memsize = sizeof(widle_table_t);
    // ensure we have enough space to offset the allocation by line cache (for alignment)
    MUSTALIGN2(memsize + ((kCpuLineCacheSize + 1) / 2), kCpuLineCacheSize);
    memsize = ALIGN2(memsize + ((kCpuLineCacheSize + 1) / 2), kCpuLineCacheSize);

    // check for overflow
    if (memsize < sizeof(widle_table_t))
    {
        printError("buffer size out of range");
        exit(1);
    }

    // allocate memory, placing widle_table_t at a line cache address boundary
    uintptr_t ptr = (uintptr_t) memoryAllocate(memsize);

    // align c to line cache boundary
    MUSTALIGN2(ptr, kCpuLineCacheSize);

    widle_table_t *newtable = (widle_table_t *) ALIGN2(ptr, kCpuLineCacheSize); // NOLINT

    *newtable = (widle_table_t){.memptr         = ptr,
                                .loop           = loop,
                                .idle_handle    = wtimerAdd(loop, idleCallBack, 1000, INFINITE),
                                .hqueue         = heapq_idles_t_with_capacity(kVecCap),
                                .hmap           = hmap_idles_t_with_capacity(kVecCap),
                                .last_update_ms = wloopNowMS(loop)};

    mutexInit(&(newtable->mutex));
    weventSetUserData(newtable->idle_handle, newtable);
    return newtable;
}

/**
 * @brief Creates a new idle item and inserts it into the table.
 *
 * @param self Pointer to the idle table.
 * @param key Hash key used for the item.
 * @param userdata User data pointer.
 * @param cb Callback to be invoked upon expiration.
 * @param tid Thread ID.
 * @param age_ms Expiration delay in milliseconds.
 * @return Pointer to the idle item; NULL if insertion fails.
 */
idle_item_t *idleItemNew(widle_table_t *self, hash_t key, void *userdata, ExpireCallBack cb, wid_t tid, uint64_t age_ms)
{
    assert(self);
    idle_item_t *item = memoryAllocate(sizeof(idle_item_t));
    mutexLock(&(self->mutex));

    *item = (idle_item_t){.expire_at_ms = wloopNowMS(getWorkerLoop(tid)) + age_ms,
                          .hash         = key,
                          .tid          = tid,
                          .userdata     = userdata,
                          .cb           = cb,
                          .table        = self};

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

/**
 * @brief Keeps an idle item alive for at least the specified duration.
 *
 * Updates the item's expiration based on current loop time.
 *
 * @param self Pointer to the idle table.
 * @param item Idle item to update.
 * @param age_ms Time in milliseconds to extend the item.
 */
void idleTableKeepIdleItemForAtleast(widle_table_t *self, idle_item_t *item, uint64_t age_ms)
{
    if (item->removed)
    {
        return;
    }
    item->expire_at_ms = wloopNowMS(self->loop) + age_ms;

    mutexLock(&(self->mutex));
    heapq_idles_t_make_heap(&self->hqueue);
    mutexUnlock(&(self->mutex));
}

/**
 * @brief Retrieves an idle item from the table by its hash key.
 *
 * @param tid Thread ID.
 * @param self Pointer to the idle table.
 * @param key Hash key of the idle item.
 * @return Pointer to the idle item if found; NULL otherwise.
 */
idle_item_t *idleTableGetIdleItemByHash(wid_t tid, widle_table_t *self, hash_t key)
{
    mutexLock(&(self->mutex));

    hmap_idles_t_iter find_result = hmap_idles_t_find(&(self->hmap), key);
    if (find_result.ref == hmap_idles_t_end(&(self->hmap)).ref || find_result.ref->second->tid != tid)
    {
        mutexUnlock(&(self->mutex));
        return NULL;
    }
    mutexUnlock(&(self->mutex));
    return (find_result.ref->second);
}

/**
 * @brief Removes an idle item from the table by its hash key.
 *
 * Performs a lazy deletion by marking the item as removed.
 *
 * @param tid Thread ID.
 * @param self Pointer to the idle table.
 * @param key Hash key of the idle item.
 * @return true if the item was found and removed; false otherwise.
 */
bool idleTableRemoveIdleItemByHash(wid_t tid, widle_table_t *self, hash_t key)
{
    mutexLock(&(self->mutex));
    hmap_idles_t_iter find_result = hmap_idles_t_find(&(self->hmap), key);
    if (find_result.ref == hmap_idles_t_end(&(self->hmap)).ref || find_result.ref->second->tid != tid)
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
        if (item->expire_at_ms > wloopNowMS(getWorkerLoop(item->tid)))
        {
            mutexLock(&(item->table->mutex));
            heapq_idles_t_push(&(item->table->hqueue), item);
            mutexUnlock(&(item->table->mutex));
            return;
        }

        uint64_t old_expire_at_ms = item->expire_at_ms;

        if (item->cb)
        {
            item->cb(item);
        }

        if (old_expire_at_ms != item->expire_at_ms && item->expire_at_ms > wloopNowMS(getWorkerLoop(item->tid)))
        {
            mutexLock(&(item->table->mutex));
            heapq_idles_t_push(&(item->table->hqueue), item);
            mutexUnlock(&(item->table->mutex));
        }
        else
        {
            bool removal_result = idleTableRemoveIdleItemByHash(item->tid, item->table, item->hash);
            assert(removal_result);
            (void) removal_result;
            memoryFree(item);
        }
    }
    else
    {
        memoryFree(item);
    }
}

/**
 * @brief Timer callback for processing idle items.
 *
 * Iterates through idle items in the heap and processes those that have expired.
 *
 * @param timer Pointer to the timer.
 */
void idleCallBack(wtimer_t *timer)
{
    widle_table_t *self  = weventGetUserdata(timer);
    const uint64_t now   = wloopNowMS(self->loop);
    self->last_update_ms = now;
    mutexLock(&(self->mutex));

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
                ev.loop = getWorkerLoop(item->tid);
                ev.cb   = beforeCloseCallBack;
                weventSetUserData(&ev, item);
                wloopPostEvent(getWorkerLoop(item->tid), &ev);
            }
        }
        else
        {
            break;
        }
    }
    mutexUnlock(&(self->mutex));
}

/**
 * @brief Destroys the idle table and releases all resources.
 *
 * Deletes the timer handle, drops internal data structures, and frees allocated memory.
 *
 * @param self Pointer to the idle table.
 */
void idleTableDestroy(widle_table_t *self)
{
    wtimerDelete(self->idle_handle);
    heapq_idles_t_drop(&self->hqueue);
    hmap_idles_t_drop(&self->hmap);
    mutexDestroy(&self->mutex);
    memoryFree((void *) (self->memptr)); // NOLINT
}

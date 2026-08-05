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

static uint64_t idleItemGetExpireAt(const idle_item_t *item);
static void     idleItemKeepExpireAtForAtleast(idle_item_t *item, uint64_t expire_at_ms);

#define i_type                    heapq_idles_t
#define i_key                     idle_item_t *
#define i_cmp                     -c_default_cmp                                          // NOLINT
#define idletable_less_func(x, y) (idleItemGetExpireAt(*(x)) > idleItemGetExpireAt(*(y))) // NOLINT
#define i_less                    idletable_less_func                                     // NOLINT
#include "stc/pqueue.h"

#define i_type hmap_idles_t
#define i_key  uint64_t
#define i_val  idle_item_t *
#include "stc/hmap.h"

#define i_type idle_item_deque_t
#define i_key  idle_item_t *
#include "stc/deque.h"

typedef struct idle_drain_item_s
{
    idle_item_t *item;
    bool         worker_message_pending;
} idle_drain_item_t;

typedef MSVC_ATTR_ALIGNED_LINE_CACHE struct idle_table_s
{
    wloop_t      *loop;
    wtimer_t     *idle_handle;
    heapq_idles_t hqueue;
    hmap_idles_t  hmap;
    wmutex_t      mutex;

} GNU_ATTR_ALIGNED_LINE_CACHE idle_table_t;

void idleCallBack(wtimer_t *timer);

// Detaching the table hands the item memory to whoever observes NULL, and that observer frees it
// without holding the mutex. The release/acquire pair is what keeps the detaching thread's last
// writes into the item from sinking past the store and landing in an already freed block. These two
// must not be weakened to relaxed.
static idle_table_t *idleItemGetTable(const idle_item_t *item)
{
    return (idle_table_t *) (uintptr_t) atomicLoadExplicit(&(item->table), memory_order_acquire);
}

static void idleItemSetTable(idle_item_t *item, idle_table_t *table)
{
    atomicStoreExplicit(&(item->table), (uintptr_t) table, memory_order_release);
}

static bool idleItemIsRemoved(const idle_item_t *item)
{
    return atomicLoadExplicit(&(item->removed), memory_order_acquire);
}

static void idleItemSetRemoved(idle_item_t *item)
{
    atomicStoreExplicit(&(item->removed), true, memory_order_release);
}

static bool idleItemHasWorkerMessagePending(const idle_item_t *item)
{
    return atomicLoadExplicit(&(item->worker_message_pending), memory_order_acquire);
}

static void idleItemSetWorkerMessagePending(idle_item_t *item, bool pending)
{
    atomicStoreExplicit(&(item->worker_message_pending), pending, memory_order_release);
}

// The expiration stamp gates no other memory: every reader wants the timestamp itself and nothing
// that was written before it, so relaxed is enough. Item lifetime is published by the table pointer
// and the table mutex, not by this field.
static uint64_t idleItemGetExpireAt(const idle_item_t *item)
{
    return atomicLoadU64Explicit(&(item->expire_at_ms), memory_order_relaxed);
}

static void idleItemSetExpireAt(idle_item_t *item, uint64_t expire_at_ms)
{
    atomicStoreU64Explicit(&(item->expire_at_ms), expire_at_ms, memory_order_relaxed);
}

static bool idleItemCompareExchangeExpireAt(idle_item_t *item, uint64_t *expected, uint64_t desired)
{
    return atomicCompareExchangeWeakU64Explicit(&(item->expire_at_ms), expected, desired, memory_order_relaxed,
                                                memory_order_relaxed);
}

static void idleItemKeepExpireAtForAtleast(idle_item_t *item, uint64_t expire_at_ms)
{
    uint64_t current_expire_at_ms = idleItemGetExpireAt(item);

    while (current_expire_at_ms < expire_at_ms)
    {
        if (idleItemCompareExchangeExpireAt(item, &current_expire_at_ms, expire_at_ms))
        {
            return;
        }
    }
}

idle_table_t *idleTableCreate(wloop_t *loop)
{
    // assert(sizeof(idle_table_t) <= kCpuLineCacheSize); promotion to 128 bytes
    const size_t  required_size = sizeof(idle_table_t);
    idle_table_t *newtable      = memoryAllocateCacheAligned(required_size);
    if (newtable == NULL)
    {
        printError("buffer size out of range");
        abortProgramNow(1);
    }

    *newtable = (idle_table_t) {.loop   = loop,
                                .hqueue = heapq_idles_t_with_capacity(kIdleTableCap),
                                .hmap   = hmap_idles_t_with_capacity(kIdleTableCap)};
    mutexInit(&(newtable->mutex));

    newtable->idle_handle = wtimerAdd(loop, idleCallBack, kDefaultTimeout, INFINITE);
    if (UNLIKELY(newtable->idle_handle == NULL))
    {
        mutexDestroy(&(newtable->mutex));
        heapq_idles_t_drop(&(newtable->hqueue));
        hmap_idles_t_drop(&(newtable->hmap));
        memoryFreeAligned(newtable);
        printError("IdleTable: failed to create idle timer");
        abortProgramNow(1);
    }

    weventSetUserData(newtable->idle_handle, newtable);
    return newtable;
}

idle_item_t *idletableCreateItem(idle_table_t *self, hash_t key, void *userdata, ExpireCallBack cb, wid_t wid,
                                 uint64_t age_ms)
{
    assert(self);
    idle_item_t *item = memoryAllocate(sizeof(idle_item_t));
    mutexLock(&(self->mutex));

    *item = (idle_item_t) {.expire_at_ms           = wloopNowMS(self->loop) + age_ms,
                           .hash                   = key,
                           .wid                    = wid,
                           .userdata               = userdata,
                           .cb                     = cb,
                           .table                  = (uintptr_t) self,
                           .removed                = false,
                           .worker_message_pending = false};

    // LOGD("add to expire on idle table, wid: %ld, hash: %lx", wid, key);
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
    assert(self != NULL);
    assert(item != NULL);
    assert(idleItemGetTable(item) == self);

    if (UNLIKELY(idleItemGetTable(item) != self || idleItemIsRemoved(item)))
    {
        printError("IdleTable: Attempt to keep an already removed idle item alive");
        abortProgramNow(1);
        return;
    }

    idleItemKeepExpireAtForAtleast(item, getTimeOfDayMS() + age_ms);
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
    idle_item_t *item = find_result.ref->second;
    mutexUnlock(&(self->mutex));
    return item;
}

static bool idleItemIsInDrainList(idle_item_t *item, idle_drain_item_t *items, size_t items_count)
{
    for (size_t i = 0; i < items_count; ++i)
    {
        if (items[i].item == item)
        {
            return true;
        }
    }

    return false;
}

static void idletableEraseItemFromMapLocked(idle_table_t *table, idle_item_t *item)
{
    assert(table != NULL);
    assert(item != NULL);

    hmap_idles_t_iter find_result = hmap_idles_t_find(&(table->hmap), item->hash);
    if (find_result.ref != hmap_idles_t_end(&(table->hmap)).ref && find_result.ref->second == item)
    {
        hmap_idles_t_erase_at(&(table->hmap), find_result);
    }
    idleItemSetRemoved(item);
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

    idle_item_t *item = find_result.ref->second;
    idletableEraseItemFromMapLocked(self, item);
    if (idleItemHasWorkerMessagePending(item))
    {
        idleItemSetTable(item, NULL);
    }

    mutexUnlock(&(self->mutex));
    return true;
}

static void idlePostedCloseMessageCleanup(void *arg1, void *arg2, void *arg3)
{
    discard arg2;
    discard arg3;

    idle_item_t *item = arg1;
    if (item == NULL)
    {
        return;
    }

    idle_table_t *table = idleItemGetTable(item);
    if (table != NULL)
    {
        mutexLock(&(table->mutex));
        idletableEraseItemFromMapLocked(table, item);
        idleItemSetWorkerMessagePending(item, false);
        mutexUnlock(&(table->mutex));
    }
    memoryFree(item);
}

/**
 * @brief Drain active idle items owned by one worker.
 *
 * Must run on worker @p wid, because the expiration callbacks it invokes touch that worker's
 * line pools.
 *
 * Items that a posted expiration message already owns (worker_message_pending) are only detached
 * here, never called back and never freed: that message frees them. Doing anything else to such an
 * item after the mutex is released would race with the free on the message side.
 */
void idletableDrainWorkerItems(idle_table_t *self, wid_t wid)
{
    assert(self != NULL);

    // The expiration callbacks below run inline on the caller and reach into worker wid's line
    // pools, so draining from any other thread corrupts them.
    if (UNLIKELY(! currentThreadIsEventWorkerWID(wid)))
    {
        LOGF("IdleTable: drain of worker %d items was called on worker %d", workerWIDForLog(wid),
             workerWIDForLog(getWID()));
        abortProgramNow(1);
        return;
    }

    mutexLock(&(self->mutex));

    size_t items_count = 0;
    c_foreach(item_iter, hmap_idles_t, self->hmap)
    {
        idle_item_t *item = item_iter.ref->second;
        if (! idleItemIsRemoved(item) && item->wid == wid)
        {
            items_count += 1;
        }
    }

    if (items_count == 0)
    {
        mutexUnlock(&(self->mutex));
        return;
    }

    idle_drain_item_t *items = memoryAllocate(sizeof(*items) * items_count);
    size_t             index = 0;
    c_foreach(item_iter, hmap_idles_t, self->hmap)
    {
        idle_item_t *item = item_iter.ref->second;
        if (! idleItemIsRemoved(item) && item->wid == wid)
        {
            items[index++] =
                (idle_drain_item_t) {.item = item, .worker_message_pending = idleItemHasWorkerMessagePending(item)};
        }
    }

    for (size_t i = 0; i < items_count; ++i)
    {
        idle_item_t *item = items[i].item;
        idletableEraseItemFromMapLocked(self, item);

        if (items[i].worker_message_pending)
        {
            // Hand the item over to the posted message while still holding the mutex, exactly like
            // idletableRemoveIdleItemByHash does. After the unlock this pointer is not ours to touch.
            idleItemSetTable(item, NULL);
        }
    }

    heapq_idles_t kept = heapq_idles_t_with_capacity(heapq_idles_t_size(&(self->hqueue)));
    while (heapq_idles_t_size(&(self->hqueue)) > 0)
    {
        idle_item_t *item = *heapq_idles_t_top(&(self->hqueue));
        heapq_idles_t_pop(&(self->hqueue));

        if (! idleItemIsInDrainList(item, items, items_count))
        {
            heapq_idles_t_push(&kept, item);
        }
    }

    heapq_idles_t_drop(&(self->hqueue));
    self->hqueue = kept;

    mutexUnlock(&(self->mutex));

    for (size_t i = 0; i < items_count; ++i)
    {
        if (items[i].worker_message_pending)
        {
            // Detached above and owned by the posted message. Its expiration callback is skipped for
            // the same reason a removed item's is: removal is not expiration.
            continue;
        }

        // Erased from the map and lifted out of the heap under the mutex, and not pending, so this
        // item is unreachable from every other path and we are its only owner.
        idle_item_t *item = items[i].item;
        if (item->cb != NULL)
        {
            item->cb(item);
        }
        memoryFree(item);
    }

    memoryFree(items);
}

/**
 * @brief Worker message invoked when an idle item is about to be closed.
 *
 * This function executes the expiration callback if applicable or removes
 * the idle item.
 */
static void beforeCloseWorkerMessage(void *worker_arg, void *arg1, void *arg2, void *arg3)
{
    worker_t *worker = worker_arg;
    discard   arg2;
    discard   arg3;

    idle_item_t *item = arg1;

    idle_table_t *table = idleItemGetTable(item);
    if (UNLIKELY(table == NULL))
    {
        memoryFree(item);
        return;
    }

    // worker_message_pending stays set for as long as this message holds the item. It is what tells
    // every table path that the memory is ours, so none of them frees it underneath us. It is cleared
    // only under the mutex, at the moment the item is handed back to the heap.
    bool removed = idleItemIsRemoved(item);

    if (removed)
    {
        memoryFree(item);
        return;
    }

    if (idleItemGetExpireAt(item) > wloopNowMS(worker->loop))
    {
        bool should_free = false;
        mutexLock(&(table->mutex));
        if (! idleItemIsRemoved(item) && idleItemGetTable(item) == table)
        {
            idleItemSetWorkerMessagePending(item, false);
            heapq_idles_t_push(&(table->hqueue), item);
        }
        else
        {
            should_free = true;
        }
        mutexUnlock(&(table->mutex));
        if (should_free)
        {
            memoryFree(item);
        }
        return;
    }

    // LOGD("item expired, wid: %ld, hash: %lx", item->wid, item->hash);

    uint64_t old_expire_at_ms = idleItemGetExpireAt(item);

    if (item->cb)
    {
        item->cb(item);
    }

    const uint64_t new_expire_at_ms = idleItemGetExpireAt(item);
    const bool     keep_alive = old_expire_at_ms != new_expire_at_ms && new_expire_at_ms > wloopNowMS(worker->loop);

    mutexLock(&(table->mutex));
    removed = idleItemIsRemoved(item) || idleItemGetTable(item) != table;
    if (! removed && keep_alive)
    {
        idleItemSetWorkerMessagePending(item, false);
        heapq_idles_t_push(&(table->hqueue), item);
    }
    else if (! removed)
    {
        idletableEraseItemFromMapLocked(table, item);
        removed = true;
    }
    mutexUnlock(&(table->mutex));

    if (removed)
    {
        memoryFree(item);
    }
}

void idleCallBack(wtimer_t *timer)
{
    uint64_t next_timeout = kDefaultTimeout;

    idle_table_t *self = weventGetUserdata(timer);
    if (UNLIKELY(self == NULL))
    {
        return;
    }

    const uint64_t    now           = wloopNowMS(self->loop);
    idle_item_deque_t expired_items = idle_item_deque_t_with_capacity(8);
    mutexLock(&(self->mutex));
    // LOGD("idleCallBack called, wid: %ld , loop current ms: %lu", getWID(), wloopNowMS(self->loop));

    heapq_idles_t_make_heap(&self->hqueue);

    while (heapq_idles_t_size(&(self->hqueue)) > 0)
    {
        idle_item_t *item = *heapq_idles_t_top(&(self->hqueue));

        const uint64_t item_expire_at_ms = idleItemGetExpireAt(item);
        if (item_expire_at_ms <= now)
        {
            heapq_idles_t_pop(&(self->hqueue));

            if (idleItemIsRemoved(item))
            {
                // already removed
                memoryFree(item);
            }
            else
            {
                idleItemSetWorkerMessagePending(item, true);
                if (UNLIKELY(idle_item_deque_t_push_back(&expired_items, item) == NULL))
                {
                    idletableEraseItemFromMapLocked(self, item);
                    idleItemSetWorkerMessagePending(item, false);
                    memoryFree(item);
                }
            }
        }
        else
        {
            next_timeout = min(next_timeout, item_expire_at_ms - now);
            break;
        }
    }
    mutexUnlock(&(self->mutex));

    while (! idle_item_deque_t_is_empty(&expired_items))
    {
        idle_item_t *item = idle_item_deque_t_pull_front(&expired_items);
        discard      sendWorkerMessageForceQueueWithCleanup(
            item->wid, beforeCloseWorkerMessage, idlePostedCloseMessageCleanup, item, NULL, NULL);
    }
    idle_item_deque_t_drop(&expired_items);

    wtimerReset(timer, (uint32_t) (next_timeout));
}

void idletableDestroy(idle_table_t *self)
{
    assert(self != NULL);

    // if our loop is destroyed then the loop it self has freed the timer handle
    if (LIKELY(! isApplicationTerminating()))
    {
        weventSetUserData(self->idle_handle, NULL);
        wtimerDelete(self->idle_handle);
    }

    // Free heap-owned idle items before dropping the containers.
    mutexLock(&(self->mutex));

    // Posted close messages carry their own item pointer and will free it from
    // the worker callback or worker-message cleanup path.
    c_foreach(item_iter, hmap_idles_t, self->hmap)
    {
        idle_item_t *item = item_iter.ref->second;
        if (idleItemHasWorkerMessagePending(item))
        {
            idleItemSetRemoved(item);
            idleItemSetTable(item, NULL);
        }
    }

    while (heapq_idles_t_size(&(self->hqueue)) > 0)
    {
        idle_item_t *item = *heapq_idles_t_top(&(self->hqueue));
        heapq_idles_t_pop(&(self->hqueue));
        if (! idleItemHasWorkerMessagePending(item))
        {
            memoryFree(item);
        }
    }

    mutexUnlock(&(self->mutex));

    heapq_idles_t_drop(&self->hqueue);
    hmap_idles_t_drop(&self->hmap);
    mutexDestroy(&self->mutex);
    memoryFreeAligned(self);
}

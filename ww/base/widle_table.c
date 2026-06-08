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
    uintptr_t     memptr;

} GNU_ATTR_ALIGNED_LINE_CACHE idle_table_t;

void idleCallBack(wtimer_t *timer);

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

static uint64_t idleItemGetExpireAt(const idle_item_t *item)
{
    return (uint64_t) atomicLoadExplicit(&(item->expire_at_ms), memory_order_acquire);
}

static void idleItemSetExpireAt(idle_item_t *item, uint64_t expire_at_ms)
{
    atomicStoreExplicit(&(item->expire_at_ms), expire_at_ms, memory_order_release);
}

idle_table_t *idleTableCreate(wloop_t *loop)
{
    wloopUpdateTime(loop);
    // assert(sizeof(idle_table_t) <= kCpuLineCacheSize); promotion to 128 bytes
    const size_t  required_size = sizeof(idle_table_t);
    idle_table_t *newtable      = memoryAllocateCacheAligned(required_size);
    if (newtable == NULL)
    {
        printError("buffer size out of range");
        terminateProgram(1);
    }

    *newtable = (idle_table_t) {.memptr = (uintptr_t) newtable,
                                .loop   = loop,
                                .hqueue = heapq_idles_t_with_capacity(kIdleTableCap),
                                .hmap   = hmap_idles_t_with_capacity(kIdleTableCap)};
    mutexInit(&(newtable->mutex));

    newtable->idle_handle = wtimerAdd(loop, idleCallBack, kDefaultTimeout, INFINITE);
    if (UNLIKELY(newtable->idle_handle == NULL))
    {
        mutexDestroy(&(newtable->mutex));
        heapq_idles_t_drop(&(newtable->hqueue));
        hmap_idles_t_drop(&(newtable->hmap));
        memoryFreeAligned((void *) (newtable->memptr)); // NOLINT
        printError("IdleTable: failed to create idle timer");
        terminateProgram(1);
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

    mutexLock(&(self->mutex));
    if (idleItemIsRemoved(item))
    {
        mutexUnlock(&(self->mutex));
        printError("IdleTable: Attempt to keep an already removed idle item alive");
        terminateProgram(1);
        return;
    }
    idleItemSetExpireAt(item, wloopNowMS(self->loop) + age_ms);
    mutexUnlock(&(self->mutex));

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

void idletableDrainWorkerItems(idle_table_t *self, wid_t wid)
{
    assert(self != NULL);

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
        idle_item_t *item = items[i].item;
        if (item->cb != NULL)
        {
            item->cb(item);
        }
        if (! items[i].worker_message_pending)
        {
            memoryFree(item);
        }
        else
        {
            idleItemSetTable(item, NULL);
        }
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

    idleItemSetWorkerMessagePending(item, false);
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
    memoryFreeAligned((void *) (self->memptr)); // NOLINT
}

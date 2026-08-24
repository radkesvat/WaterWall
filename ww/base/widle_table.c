/**
 * @file widle_table.c
 * @brief Implementation of a synchronized, multi-worker idle table.
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
static void     idletableEraseItemFromMapLocked(idle_table_t *table, idle_item_t *item);

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
    size_t        posted_messages;   ///< Queued expiration messages; each one pins this table alive.
    bool          destroy_requested; ///< idletableDestroy ran and left teardown to the last message.
#ifdef WW_IDLE_TABLE_TEST_SEAM
    atomic_ullong test_now_ms;
    atomic_bool   test_now_enabled;
#endif

} GNU_ATTR_ALIGNED_LINE_CACHE idle_table_t;

void idleCallBack(wtimer_t *timer);
#ifdef WW_IDLE_TABLE_TEST_SEAM
void idletableTestRefuseNextInitialStagingReserve(void);
void idletableTestRefuseNextStagingGrowth(void);
void idletableTestRefuseNextCreateHeapPublication(void);

static bool        refuse_next_initial_staging_reserve;
static bool        refuse_next_staging_growth;
static bool        refuse_next_create_heap_publication;
static atomic_uint test_live_items;
static atomic_uint test_live_tables;

void idletableTestRefuseNextInitialStagingReserve(void)
{
    refuse_next_initial_staging_reserve = true;
}

void idletableTestRefuseNextStagingGrowth(void)
{
    refuse_next_staging_growth = true;
}

void idletableTestRefuseNextCreateHeapPublication(void)
{
    refuse_next_create_heap_publication = true;
}

void idletableTestSetNowMS(idle_table_t *self, uint64_t now_ms)
{
    assert(self != NULL);
    atomicStoreU64Explicit(&self->test_now_ms, now_ms, memory_order_relaxed);
    atomicStoreExplicit(&self->test_now_enabled, true, memory_order_release);
}

void idletableTestRunExpiry(idle_table_t *self)
{
    assert(self != NULL && self->idle_handle != NULL);
    idleCallBack(self->idle_handle);
}

uint64_t idletableTestGetDeadline(const idle_item_t *item)
{
    assert(item != NULL);
    return idleItemGetExpireAt(item);
}

size_t idletableTestGetActiveItemCount(idle_table_t *self)
{
    assert(self != NULL);
    mutexLock(&self->mutex);
    const size_t count = (size_t) hmap_idles_t_size(&self->hmap);
    mutexUnlock(&self->mutex);
    return count;
}

unsigned int idletableTestGetLiveItemCount(void)
{
    return atomicLoadRelaxed(&test_live_items);
}

unsigned int idletableTestGetLiveTableCount(void)
{
    return atomicLoadRelaxed(&test_live_tables);
}
#endif

static idle_item_t *idleItemAllocate(void)
{
    idle_item_t *item = memoryAllocate(sizeof(*item));
#ifdef WW_IDLE_TABLE_TEST_SEAM
    if (item != NULL)
    {
        atomicIncRelaxed(&test_live_items);
    }
#endif
    return item;
}

static void idleItemFree(idle_item_t *item)
{
    if (item == NULL)
    {
        return;
    }
#ifdef WW_IDLE_TABLE_TEST_SEAM
    assert(atomicLoadRelaxed(&test_live_items) > 0);
    atomicDecRelaxed(&test_live_items);
#endif
    memoryFree(item);
}

static uint64_t idletableNowMS(const idle_table_t *self)
{
#ifdef WW_IDLE_TABLE_TEST_SEAM
    if (atomicLoadExplicit(&self->test_now_enabled, memory_order_acquire))
    {
        return atomicLoadU64Explicit(&self->test_now_ms, memory_order_relaxed);
    }
#else
    discard self;
#endif
    return getTimeOfDayMS();
}

static uint64_t idletableDeadlineFromAge(const idle_table_t *self, uint64_t age_ms)
{
    const uint64_t now = idletableNowMS(self);
    return age_ms > UINT64_MAX - now ? UINT64_MAX : now + age_ms;
}

static void idletableAssertItemOwner(wid_t wid)
{
    if (UNLIKELY(! currentThreadIsEventWorkerWID(wid)))
    {
        LOGF("IdleTable: item for worker %d accessed from worker %d", workerWIDForLog(wid), workerWIDForLog(getWID()));
        abortProgramNow(1);
    }
}

static bool idletableTestTakeInitialStagingReserveRefusal(void)
{
#ifdef WW_IDLE_TABLE_TEST_SEAM
    if (refuse_next_initial_staging_reserve)
    {
        refuse_next_initial_staging_reserve = false;
        return true;
    }
#endif
    return false;
}

static bool idletableTestTakeStagingGrowthRefusal(void)
{
#ifdef WW_IDLE_TABLE_TEST_SEAM
    if (refuse_next_staging_growth)
    {
        refuse_next_staging_growth = false;
        return true;
    }
#endif
    return false;
}

static bool idletableTestTakeCreateHeapPublicationRefusal(void)
{
#ifdef WW_IDLE_TABLE_TEST_SEAM
    if (refuse_next_create_heap_publication)
    {
        refuse_next_create_heap_publication = false;
        return true;
    }
#endif
    return false;
}

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

static void idletableRestoreItemToHeapLocked(idle_table_t *table, idle_item_t *item)
{
    if (UNLIKELY(heapq_idles_t_size(&table->hqueue) >= heapq_idles_t_capacity(&table->hqueue)))
    {
        assert(false && "IdleTable pending delivery lost its reserved restoration slot");
        abortProgramNow(1);
    }
    if (UNLIKELY(heapq_idles_t_push(&table->hqueue, item) == NULL))
    {
        assert(false && "IdleTable restoration must not allocate");
        abortProgramNow(1);
    }
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
    return atomicCompareExchangeWeakU64Explicit(
        &(item->expire_at_ms), expected, desired, memory_order_relaxed, memory_order_relaxed);
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
    assert(loop != NULL);
    const wid_t timer_wid = (wid_t) wloopGetWID(loop);
    if (UNLIKELY(! currentThreadIsEventWorkerWID(timer_wid)))
    {
        LOGF("IdleTable: table timer was created outside worker %d", workerWIDForLog(timer_wid));
        abortProgramNow(1);
    }

    // assert(sizeof(idle_table_t) <= kCpuLineCacheSize); promotion to 128 bytes
    const size_t  required_size = sizeof(idle_table_t);
    idle_table_t *newtable      = memoryAllocateCacheAligned(required_size);
    if (newtable == NULL)
    {
        printError("buffer size out of range");
        abortProgramNow(1);
    }

    *newtable = (idle_table_t) {
        .loop = loop,
    };
#ifdef WW_IDLE_TABLE_TEST_SEAM
    atomic_init(&newtable->test_now_ms, 0);
    atomic_init(&newtable->test_now_enabled, false);
#endif
    newtable->hqueue = heapq_idles_t_init();
    newtable->hmap   = hmap_idles_t_init();
    if (UNLIKELY(! heapq_idles_t_reserve(&newtable->hqueue, kIdleTableCap) ||
                 ! hmap_idles_t_reserve(&newtable->hmap, kIdleTableCap) || ! mutexTryInit(&(newtable->mutex))))
    {
        heapq_idles_t_drop(&(newtable->hqueue));
        hmap_idles_t_drop(&(newtable->hmap));
        memoryFreeAligned(newtable);
        printError("IdleTable: failed to initialize table storage");
        abortProgramNow(1);
    }

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
#ifdef WW_IDLE_TABLE_TEST_SEAM
    atomicIncRelaxed(&test_live_tables);
#endif
    return newtable;
}

idle_item_t *idletableCreateItem(idle_table_t *self, hash_t key, void *userdata, ExpireCallBack cb, wid_t wid,
                                 uint64_t age_ms)
{
    assert(self);
    idletableAssertItemOwner(wid);

    idle_item_t *item = idleItemAllocate();
    if (UNLIKELY(item == NULL))
    {
        return NULL;
    }

    *item = (idle_item_t) {.expire_at_ms           = idletableDeadlineFromAge(self, age_ms),
                           .hash                   = key,
                           .wid                    = wid,
                           .userdata               = userdata,
                           .cb                     = cb,
                           .table                  = (uintptr_t) self,
                           .removed                = false,
                           .worker_message_pending = false};

    mutexLock(&(self->mutex));

    // LOGD("add to expire on idle table, wid: %ld, hash: %lx", wid, key);
    if (! hmap_idles_t_insert(&(self->hmap), item->hash, item).inserted)
    {
        // hash is already in the table !
        mutexUnlock(&(self->mutex));
        idleItemFree(item);
        return NULL;
    }

    const isize_t heap_size = heapq_idles_t_size(&(self->hqueue));
    const bool    restoration_capacity_overflow =
        heap_size >= ISIZE_MAX || self->posted_messages > (size_t) (ISIZE_MAX - heap_size - 1);
    const isize_t required_heap_capacity =
        restoration_capacity_overflow ? 0 : heap_size + (isize_t) self->posted_messages + 1;
    bool heap_capacity_ready = ! restoration_capacity_overflow;
    if (heap_capacity_ready && required_heap_capacity > heapq_idles_t_capacity(&(self->hqueue)))
    {
        const isize_t current_capacity = heapq_idles_t_capacity(&(self->hqueue));
        const isize_t half_capacity    = current_capacity / 2;
        isize_t       grown_capacity   = ISIZE_MAX;
        if (current_capacity <= ISIZE_MAX - half_capacity - 4)
        {
            grown_capacity = current_capacity + half_capacity + 4;
        }
        if (grown_capacity < required_heap_capacity)
        {
            grown_capacity = required_heap_capacity;
        }
        heap_capacity_ready = heapq_idles_t_reserve(&(self->hqueue), grown_capacity);
    }
    if (UNLIKELY(! heap_capacity_ready))
    {
        idletableEraseItemFromMapLocked(self, item);
        idleItemSetTable(item, NULL);
        mutexUnlock(&(self->mutex));
        idleItemFree(item);
        return NULL;
    }

    idle_item_t **heap_slot = NULL;
    if (! idletableTestTakeCreateHeapPublicationRefusal())
    {
        heap_slot = heapq_idles_t_push(&(self->hqueue), item);
    }
    if (UNLIKELY(heap_slot == NULL))
    {
        idletableEraseItemFromMapLocked(self, item);
        idleItemSetTable(item, NULL);
        mutexUnlock(&(self->mutex));
        idleItemFree(item);
        return NULL;
    }

    mutexUnlock(&(self->mutex));
    return item;
}

void idletableKeepIdleItemForAtleast(idle_table_t *self, idle_item_t *item, uint64_t age_ms)
{
    assert(self != NULL);
    assert(item != NULL);
    assert(idleItemGetTable(item) == self);
    idletableAssertItemOwner(item->wid);

    if (UNLIKELY(idleItemGetTable(item) != self || idleItemIsRemoved(item)))
    {
        printError("IdleTable: Attempt to keep an already removed idle item alive");
        abortProgramNow(1);
        return;
    }

    idleItemKeepExpireAtForAtleast(item, idletableDeadlineFromAge(self, age_ms));
}

idle_item_t *idletableGetIdleItemByHash(wid_t wid, idle_table_t *self, hash_t key)
{
    assert(self != NULL);
    idletableAssertItemOwner(wid);
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

static bool idletableMapsItemLocked(idle_table_t *table, idle_item_t *item)
{
    hmap_idles_t_iter find_result = hmap_idles_t_find(&(table->hmap), item->hash);
    return find_result.ref != hmap_idles_t_end(&(table->hmap)).ref && find_result.ref->second == item;
}

bool idletableRemoveIdleItemByHash(wid_t wid, idle_table_t *self, hash_t key)
{
    assert(self != NULL);
    idletableAssertItemOwner(wid);
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

/**
 * @brief Release the table storage. The caller must hold the last reference to it.
 */
static void idletableFreeResources(idle_table_t *self)
{
    heapq_idles_t_drop(&(self->hqueue));
    hmap_idles_t_drop(&(self->hmap));
    mutexDestroy(&(self->mutex));
#ifdef WW_IDLE_TABLE_TEST_SEAM
    assert(atomicLoadRelaxed(&test_live_tables) > 0);
    atomicDecRelaxed(&test_live_tables);
#endif
    memoryFreeAligned(self);
}

/**
 * @brief Drop one posted-message reference to the table.
 *
 * Every queued expiration message owns one reference, taken under the mutex before the message is
 * posted. That is what keeps the table -- and therefore the mutex the message is about to lock --
 * alive for as long as the message can still run, no matter when idletableDestroy is called. The
 * last reference out after a destroy request performs the real teardown.
 */
static void idletableReleaseMessageRef(idle_table_t *self)
{
    if (self == NULL)
    {
        return;
    }

    mutexLock(&(self->mutex));
    assert(self->posted_messages > 0);
    if (UNLIKELY(self->posted_messages == 0))
    {
        LOGF("IdleTable: posted-message counter underflow during message release");
        abortProgramNow(1);
    }
    self->posted_messages -= 1;
    const bool destroy_now = self->posted_messages == 0 && self->destroy_requested;
    mutexUnlock(&(self->mutex));

    if (destroy_now)
    {
        idletableFreeResources(self);
    }
}

static void idlePostedCloseMessageCleanup(void *arg1, void *arg2, void *arg3, worker_message_cancel_reason_e reason)
{
    discard reason;
    discard arg3;

    idle_item_t  *item  = arg1;
    idle_table_t *table = arg2; // carried by the message, so it is reachable even once item detaches

    bool should_free = item != NULL;
    if (item != NULL && table != NULL)
    {
        mutexLock(&(table->mutex));
        if (! table->destroy_requested && ! idleItemIsRemoved(item) && idleItemGetTable(item) == table &&
            idletableMapsItemLocked(table, item))
        {
            assert(idleItemHasWorkerMessagePending(item));
            idleItemSetWorkerMessagePending(item, false);
            idletableRestoreItemToHeapLocked(table, item);
            should_free = false;
        }
        mutexUnlock(&(table->mutex));
    }

    if (should_free)
    {
        // Detached items remain message-owned until this cleanup runs.
        idleItemFree(item);
    }

    idletableReleaseMessageRef(table);
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
        LOGF("IdleTable: drain of worker %d items was called on worker %d",
             workerWIDForLog(wid),
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
        idleItemFree(item);
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
    discard   arg3;

    idle_item_t  *item  = arg1;
    idle_table_t *table = arg2; // pinned by this message's reference, so the mutex below is alive
    if (UNLIKELY(worker == NULL || worker->wid != item->wid))
    {
        LOGF("IdleTable: expiration delivered on the wrong owner worker");
        abortProgramNow(1);
    }

    // worker_message_pending stays set for as long as this message holds the item. It is what tells
    // every table path that the memory is ours, so none of them frees it underneath us. It is cleared
    // only under the mutex, at the moment the item is handed back to the heap.
    bool should_free = false;

    if (UNLIKELY(idleItemGetTable(item) != table || idleItemIsRemoved(item)))
    {
        // Detached or removed while we sat in the queue; that path left the item to us.
        should_free = true;
    }
    else if (idleItemGetExpireAt(item) > idletableNowMS(table))
    {
        mutexLock(&(table->mutex));
        if (! idleItemIsRemoved(item) && idleItemGetTable(item) == table)
        {
            idleItemSetWorkerMessagePending(item, false);
            idletableRestoreItemToHeapLocked(table, item);
        }
        else
        {
            should_free = true;
        }
        mutexUnlock(&(table->mutex));
    }
    else
    {
        // LOGD("item expired, wid: %ld, hash: %lx", item->wid, item->hash);

        const uint64_t old_expire_at_ms = idleItemGetExpireAt(item);

        if (item->cb)
        {
            item->cb(item);
        }

        const uint64_t new_expire_at_ms = idleItemGetExpireAt(item);
        const bool     keep_alive = old_expire_at_ms != new_expire_at_ms && new_expire_at_ms > idletableNowMS(table);

        mutexLock(&(table->mutex));
        const bool removed = idleItemIsRemoved(item) || idleItemGetTable(item) != table;
        if (! removed && keep_alive)
        {
            idleItemSetWorkerMessagePending(item, false);
            idletableRestoreItemToHeapLocked(table, item);
        }
        else
        {
            if (! removed)
            {
                idletableEraseItemFromMapLocked(table, item);
            }
            should_free = true;
        }
        mutexUnlock(&(table->mutex));
    }

    if (should_free)
    {
        idleItemFree(item);
    }

    idletableReleaseMessageRef(table);
}

void idleCallBack(wtimer_t *timer)
{
    uint64_t next_timeout = kDefaultTimeout;

    idle_table_t *self = weventGetUserdata(timer);
    if (UNLIKELY(self == NULL))
    {
        return;
    }

    const uint64_t    now           = idletableNowMS(self);
    idle_item_deque_t expired_items = idle_item_deque_t_init();
    bool              staging_ready = false;
    if (! idletableTestTakeInitialStagingReserveRefusal())
    {
        staging_ready = idle_item_deque_t_reserve(&expired_items, 8);
    }
    if (UNLIKELY(! staging_ready))
    {
        idle_item_deque_t_drop(&expired_items);
        discard wtimerReset(timer, kDefaultTimeout);
        return;
    }

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
                idleItemFree(item);
            }
            else
            {
                idleItemSetWorkerMessagePending(item, true);
                idle_item_t **staged = NULL;
                const bool    needs_growth =
                    idle_item_deque_t_size(&expired_items) > 0 &&
                    idle_item_deque_t_size(&expired_items) == idle_item_deque_t_capacity(&expired_items);
                if (! (needs_growth && idletableTestTakeStagingGrowthRefusal()))
                {
                    staged = idle_item_deque_t_push_back(&expired_items, item);
                }
                if (UNLIKELY(staged == NULL))
                {
                    idleItemSetWorkerMessagePending(item, false);
                    idletableRestoreItemToHeapLocked(self, item);
                    next_timeout = kDefaultTimeout;
                    break;
                }
                else
                {
                    // Pin the table for the message posted below. Exactly one of its callback or its
                    // cleanup always runs, and whichever it is drops this reference.
                    self->posted_messages += 1;
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
        sendWorkerMessageForceQueueBestEffortWithCleanup(
            item->wid, beforeCloseWorkerMessage, idlePostedCloseMessageCleanup, item, self, NULL);
    }
    idle_item_deque_t_drop(&expired_items);

    wtimerReset(timer, (uint32_t) (next_timeout));
}

void idletableDestroy(idle_table_t *self)
{
    assert(self != NULL);

    if (self->idle_handle != NULL)
    {
        weventSetUserData(self->idle_handle, NULL);
        wtimerDelete(self->idle_handle);
        self->idle_handle = NULL;
    }

    // Free heap-owned idle items before dropping the containers.
    mutexLock(&(self->mutex));

    self->destroy_requested = true;

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
            idleItemFree(item);
        }
    }

    // A queued message is still going to lock this mutex, so the table has to outlive us. The last
    // message out sees destroy_requested and frees it instead.
    const bool defer_teardown = self->posted_messages > 0;

    mutexUnlock(&(self->mutex));

    if (defer_teardown)
    {
        return;
    }

    idletableFreeResources(self);
}

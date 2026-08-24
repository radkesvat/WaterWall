/**
 * @file local_widle_table.c
 * @brief Implementation of a worker-local indexed idle table.
 */

#include "local_widle_table.h"

#include "loggers/internal_logger.h"

enum
{
    kLocalIdleTableCap   = 32,
    kLocalDefaultTimeout = 1000 // 1 second
};

#define i_type local_hmap_idles_t
#define i_key  uint64_t
#define i_val  local_idle_item_t *
#include "stc/hmap.h"

typedef MSVC_ATTR_ALIGNED_LINE_CACHE struct local_idle_table_s
{
    wloop_t            *loop;
    wtimer_t           *idle_handle;
    local_idle_item_t **heap;
    size_t              heap_len;
    size_t              heap_cap;
    local_hmap_idles_t  hmap;
    wid_t               wid;
#ifdef WW_IDLE_TABLE_TEST_SEAM
    uint64_t test_now_ms;
    bool     test_now_enabled;
#endif
} GNU_ATTR_ALIGNED_LINE_CACHE local_idle_table_t;

static void localIdleCallBack(wtimer_t *timer);
static void localidletableAssertOwner(const local_idle_table_t *self);

#ifdef WW_IDLE_TABLE_TEST_SEAM
static atomic_uint test_live_items;
static atomic_uint test_live_tables;

void localidletableTestSetNowMS(local_idle_table_t *self, uint64_t now_ms)
{
    localidletableAssertOwner(self);
    self->test_now_ms      = now_ms;
    self->test_now_enabled = true;
}

void localidletableTestRunExpiry(local_idle_table_t *self)
{
    localidletableAssertOwner(self);
    assert(self->idle_handle != NULL);
    localIdleCallBack(self->idle_handle);
}

uint64_t localidletableTestGetDeadline(const local_idle_item_t *item)
{
    assert(item != NULL);
    return item->expire_at_ms;
}

bool localidletableTestIsQuiesced(const local_idle_table_t *self)
{
    localidletableAssertOwner(self);
    return self->idle_handle == NULL;
}

unsigned int localidletableTestGetLiveItemCount(void)
{
    return atomicLoadRelaxed(&test_live_items);
}

unsigned int localidletableTestGetLiveTableCount(void)
{
    return atomicLoadRelaxed(&test_live_tables);
}
#endif

static void localidletableAssertOwner(const local_idle_table_t *self)
{
    assert(self != NULL);
    assert(currentThreadIsEventWorkerWID(self->wid));
    discard self;
}

static local_idle_item_t *localIdleItemAllocate(void)
{
    local_idle_item_t *item = memoryAllocate(sizeof(*item));
#ifdef WW_IDLE_TABLE_TEST_SEAM
    if (item != NULL)
    {
        atomicIncRelaxed(&test_live_items);
    }
#endif
    return item;
}

static void localIdleItemFree(local_idle_item_t *item)
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

static uint64_t localidletableNowMS(const local_idle_table_t *self)
{
#ifdef WW_IDLE_TABLE_TEST_SEAM
    if (self->test_now_enabled)
    {
        return self->test_now_ms;
    }
#endif
    return wloopNowMS(self->loop);
}

static uint64_t localidletableDeadlineFromAge(local_idle_table_t *self, uint64_t age_ms)
{
    const uint64_t now = localidletableNowMS(self);
    return age_ms > UINT64_MAX - now ? UINT64_MAX : now + age_ms;
}

static bool localidletableItemLess(const local_idle_item_t *left, const local_idle_item_t *right)
{
    if (left->expire_at_ms != right->expire_at_ms)
    {
        return left->expire_at_ms < right->expire_at_ms;
    }
    return left->hash < right->hash;
}

static void localidletableHeapSwap(local_idle_table_t *self, size_t left, size_t right)
{
    local_idle_item_t *temporary  = self->heap[left];
    self->heap[left]              = self->heap[right];
    self->heap[right]             = temporary;
    self->heap[left]->heap_index  = left;
    self->heap[right]->heap_index = right;
}

static void localidletableHeapSiftUp(local_idle_table_t *self, size_t index)
{
    while (index > 0)
    {
        const size_t parent = (index - 1U) / 2U;
        if (! localidletableItemLess(self->heap[index], self->heap[parent]))
        {
            break;
        }
        localidletableHeapSwap(self, index, parent);
        index = parent;
    }
}

static void localidletableHeapSiftDown(local_idle_table_t *self, size_t index)
{
    for (;;)
    {
        const size_t left = (index * 2U) + 1U;
        if (left >= self->heap_len)
        {
            return;
        }

        const size_t right    = left + 1U;
        size_t       smallest = left;
        if (right < self->heap_len && localidletableItemLess(self->heap[right], self->heap[left]))
        {
            smallest = right;
        }
        if (! localidletableItemLess(self->heap[smallest], self->heap[index]))
        {
            return;
        }
        localidletableHeapSwap(self, index, smallest);
        index = smallest;
    }
}

static void localidletableHeapReserve(local_idle_table_t *self)
{
    if (self->heap_len < self->heap_cap)
    {
        return;
    }

    if (UNLIKELY(self->heap_cap > SIZE_MAX / 2U || (self->heap_cap * 2U) > SIZE_MAX / sizeof(*self->heap)))
    {
        printError("LocalIdleTable: indexed heap capacity overflow");
        abortProgramNow(1);
    }

    const size_t new_cap  = self->heap_cap * 2U;
    void        *new_heap = memoryReAllocate(self->heap, new_cap * sizeof(*self->heap));
    if (UNLIKELY(new_heap == NULL))
    {
        printError("LocalIdleTable: failed to grow indexed heap");
        abortProgramNow(1);
    }
    self->heap     = new_heap;
    self->heap_cap = new_cap;
}

static void localidletableHeapPush(local_idle_table_t *self, local_idle_item_t *item)
{
    localidletableHeapReserve(self);
    item->heap_index           = self->heap_len;
    self->heap[self->heap_len] = item;
    self->heap_len++;
    localidletableHeapSiftUp(self, item->heap_index);
}

static void localidletableHeapRemoveAt(local_idle_table_t *self, size_t index)
{
    assert(index < self->heap_len);

    local_idle_item_t *removed = self->heap[index];
    const size_t       last    = self->heap_len - 1U;
    self->heap_len             = last;
    removed->heap_index        = SIZE_MAX;

    if (index == last)
    {
        return;
    }

    self->heap[index]             = self->heap[last];
    self->heap[index]->heap_index = index;
    if (index > 0 && localidletableItemLess(self->heap[index], self->heap[(index - 1U) / 2U]))
    {
        localidletableHeapSiftUp(self, index);
    }
    else
    {
        localidletableHeapSiftDown(self, index);
    }
}

static bool localidletableEraseMapEntry(local_idle_table_t *self, local_idle_item_t *item)
{
    local_hmap_idles_t_iter found = local_hmap_idles_t_find(&self->hmap, item->hash);
    if (found.ref == local_hmap_idles_t_end(&self->hmap).ref || found.ref->second != item)
    {
        return false;
    }
    local_hmap_idles_t_erase_at(&self->hmap, found);
    return true;
}

local_idle_table_t *localIdleTableCreate(wloop_t *loop)
{
    assert(loop != NULL);

    const wid_t owner_wid = (wid_t) wloopGetWID(loop);
    if (UNLIKELY(! currentThreadIsEventWorkerWID(owner_wid)))
    {
        printError("LocalIdleTable: created off its owning event worker");
        abortProgramNow(1);
    }

    local_idle_table_t *newtable = memoryAllocateCacheAligned(sizeof(*newtable));
    if (UNLIKELY(newtable == NULL))
    {
        printError("LocalIdleTable: failed to allocate local idle table");
        abortProgramNow(1);
    }

    local_idle_item_t **heap = memoryAllocate(kLocalIdleTableCap * sizeof(*heap));
    if (UNLIKELY(heap == NULL))
    {
        memoryFreeAligned(newtable);
        printError("LocalIdleTable: failed to allocate indexed heap");
        abortProgramNow(1);
    }

    *newtable = (local_idle_table_t) {.loop     = loop,
                                      .heap     = heap,
                                      .heap_len = 0,
                                      .heap_cap = kLocalIdleTableCap,
                                      .hmap     = local_hmap_idles_t_with_capacity(kLocalIdleTableCap),
                                      .wid      = owner_wid};

    newtable->idle_handle = wtimerAdd(loop, localIdleCallBack, kLocalDefaultTimeout, INFINITE);
    if (UNLIKELY(newtable->idle_handle == NULL))
    {
        local_hmap_idles_t_drop(&newtable->hmap);
        memoryFree(newtable->heap);
        memoryFreeAligned(newtable);
        printError("LocalIdleTable: failed to create idle timer");
        abortProgramNow(1);
    }

    weventSetUserData(newtable->idle_handle, newtable);
#ifdef WW_IDLE_TABLE_TEST_SEAM
    atomicIncRelaxed(&test_live_tables);
#endif
    return newtable;
}

local_idle_item_t *localidletableCreateItem(local_idle_table_t *self, hash_t key, void *userdata,
                                            LocalIdleExpireCallBack cb, uint64_t age_ms)
{
    localidletableAssertOwner(self);

    local_idle_item_t *item = localIdleItemAllocate();
    if (UNLIKELY(item == NULL))
    {
        printError("LocalIdleTable: failed to allocate local idle item");
        abortProgramNow(1);
    }

    *item = (local_idle_item_t) {.userdata     = userdata,
                                 .table        = self,
                                 .expire_at_ms = localidletableDeadlineFromAge(self, age_ms),
                                 .cb           = cb,
                                 .hash         = key,
                                 .heap_index   = SIZE_MAX,
                                 .removed      = false,
                                 .expiring     = false};

    if (! local_hmap_idles_t_insert(&self->hmap, item->hash, item).inserted)
    {
        localIdleItemFree(item);
        return NULL;
    }

    localidletableHeapPush(self, item);
    return item;
}

local_idle_item_t *localidletableGetIdleItemByHash(local_idle_table_t *self, hash_t key)
{
    localidletableAssertOwner(self);

    local_hmap_idles_t_iter found = local_hmap_idles_t_find(&self->hmap, key);
    if (found.ref == local_hmap_idles_t_end(&self->hmap).ref)
    {
        return NULL;
    }
    return found.ref->second;
}

void localidletableKeepIdleItemForAtleast(local_idle_table_t *self, local_idle_item_t *item, uint64_t age_ms)
{
    localidletableAssertOwner(self);
    assert(item != NULL);
    assert(item->table == self);

    if (UNLIKELY(item->table != self || item->removed))
    {
        printError("LocalIdleTable: attempt to keep an already removed idle item alive");
        abortProgramNow(1);
    }

    const uint64_t deadline = localidletableDeadlineFromAge(self, age_ms);
    if (deadline <= item->expire_at_ms)
    {
        return;
    }

    item->expire_at_ms = deadline;
    if (! item->expiring)
    {
        assert(item->heap_index < self->heap_len);
        localidletableHeapSiftDown(self, item->heap_index);
    }
}

bool localidletableRemoveIdleItem(local_idle_table_t *self, local_idle_item_t *item)
{
    localidletableAssertOwner(self);
    if (item == NULL || item->table != self || item->removed)
    {
        return false;
    }

    if (UNLIKELY(! localidletableEraseMapEntry(self, item)))
    {
        printError("LocalIdleTable: direct item and key map disagree");
        abortProgramNow(1);
    }

    item->removed = true;
    item->table   = NULL;
    if (item->expiring)
    {
        return true;
    }

    if (UNLIKELY(item->heap_index >= self->heap_len || self->heap[item->heap_index] != item))
    {
        printError("LocalIdleTable: direct item and indexed heap disagree");
        abortProgramNow(1);
    }
    localidletableHeapRemoveAt(self, item->heap_index);
    localIdleItemFree(item);
    return true;
}

bool localidletableRemoveIdleItemByHash(local_idle_table_t *self, hash_t key)
{
    localidletableAssertOwner(self);
    return localidletableRemoveIdleItem(self, localidletableGetIdleItemByHash(self, key));
}

size_t localidletableGetItemCount(local_idle_table_t *self)
{
    localidletableAssertOwner(self);
    return local_hmap_idles_t_size(&self->hmap);
}

void localidletableDrainItems(local_idle_table_t *self)
{
    localidletableAssertOwner(self);

    while (self->heap_len > 0)
    {
        local_idle_item_t *item = self->heap[0];
        localidletableHeapRemoveAt(self, 0);
        if (UNLIKELY(! localidletableEraseMapEntry(self, item)))
        {
            printError("LocalIdleTable: drain found an unindexed heap item");
            abortProgramNow(1);
        }
        item->removed = true;
        item->table   = NULL;
        if (item->cb != NULL)
        {
            item->cb(item);
        }
        localIdleItemFree(item);
    }
    assert(local_hmap_idles_t_size(&self->hmap) == 0);
}

static void localIdleCallBack(wtimer_t *timer)
{
    uint64_t next_timeout = kLocalDefaultTimeout;

    local_idle_table_t *self = weventGetUserdata(timer);
    if (UNLIKELY(self == NULL))
    {
        return;
    }
    localidletableAssertOwner(self);

    const uint64_t now = localidletableNowMS(self);
    while (self->heap_len > 0)
    {
        local_idle_item_t *item = self->heap[0];
        if (item->expire_at_ms > now)
        {
            next_timeout = min(next_timeout, item->expire_at_ms - now);
            break;
        }

        const uint64_t old_deadline = item->expire_at_ms;
        localidletableHeapRemoveAt(self, 0);
        item->expiring = true;

        if (item->cb != NULL)
        {
            item->cb(item);
        }

        item->expiring                = false;
        const uint64_t after_callback = localidletableNowMS(self);
        if (! item->removed && item->table == self && item->expire_at_ms != old_deadline &&
            item->expire_at_ms > after_callback)
        {
            localidletableHeapPush(self, item);
            continue;
        }

        if (! item->removed)
        {
            if (UNLIKELY(! localidletableEraseMapEntry(self, item)))
            {
                printError("LocalIdleTable: expiry found an unindexed item");
                abortProgramNow(1);
            }
            item->removed = true;
            item->table   = NULL;
        }
        localIdleItemFree(item);
    }

    discard wtimerReset(timer, (uint32_t) next_timeout);
}

void localidletableQuiesce(local_idle_table_t *self)
{
    localidletableAssertOwner(self);

    if (self->idle_handle != NULL)
    {
        weventSetUserData(self->idle_handle, NULL);
        wtimerDelete(self->idle_handle);
        self->idle_handle = NULL;
    }
}

void localidletableDestroy(local_idle_table_t *self)
{
    localidletableAssertOwner(self);
    localidletableQuiesce(self);

    while (self->heap_len > 0)
    {
        local_idle_item_t *item = self->heap[0];
        localidletableHeapRemoveAt(self, 0);
        localIdleItemFree(item);
    }

    local_hmap_idles_t_drop(&self->hmap);
    memoryFree(self->heap);
#ifdef WW_IDLE_TABLE_TEST_SEAM
    assert(atomicLoadRelaxed(&test_live_tables) > 0);
    atomicDecRelaxed(&test_live_tables);
#endif
    memoryFreeAligned(self);
}

/**
 * @file local_widle_table.c
 * @brief Implementation of a worker-local idle table.
 */

#include "local_widle_table.h"

#include "loggers/internal_logger.h"

enum
{
    kLocalIdleTableCap   = 32,
    kLocalDefaultTimeout = 1000 // 1 second
};

static uint64_t localIdleItemGetExpireAt(const local_idle_item_t *item);

#define i_type                         local_heapq_idles_t
#define i_key                          local_idle_item_t *
#define i_cmp                          -c_default_cmp
#define localidletable_less_func(x, y) (localIdleItemGetExpireAt(*(x)) > localIdleItemGetExpireAt(*(y))) // NOLINT
#define i_less                         localidletable_less_func                                           // NOLINT
#include "stc/pqueue.h"

#define i_type local_hmap_idles_t
#define i_key  uint64_t
#define i_val  local_idle_item_t *
#include "stc/hmap.h"

typedef MSVC_ATTR_ALIGNED_LINE_CACHE struct local_idle_table_s
{
    wloop_t             *loop;
    wtimer_t            *idle_handle;
    local_heapq_idles_t  hqueue;
    local_hmap_idles_t   hmap;
    wid_t                wid;
    uintptr_t            memptr;

} GNU_ATTR_ALIGNED_LINE_CACHE local_idle_table_t;

static void localIdleCallBack(wtimer_t *timer);

static void localidletableAssertOwner(const local_idle_table_t *self)
{
    assert(self != NULL);
    assert(self->wid == getWID());
    discard self;
}

static uint64_t localIdleItemGetExpireAt(const local_idle_item_t *item)
{
    return item->expire_at_ms;
}

static bool localIdleItemIsRemoved(const local_idle_item_t *item)
{
    return item->removed;
}

static void localIdleItemSetRemoved(local_idle_item_t *item)
{
    item->removed = true;
}

static void localIdleItemKeepExpireAtForAtleast(local_idle_item_t *item, uint64_t expire_at_ms)
{
    if (item->expire_at_ms < expire_at_ms)
    {
        item->expire_at_ms = expire_at_ms;
    }
}

static void localidletableEraseItemFromMap(local_idle_table_t *self, local_idle_item_t *item)
{
    localidletableAssertOwner(self);
    assert(self != NULL);
    assert(item != NULL);

    local_hmap_idles_t_iter find_result = local_hmap_idles_t_find(&(self->hmap), item->hash);
    if (find_result.ref != local_hmap_idles_t_end(&(self->hmap)).ref && find_result.ref->second == item)
    {
        local_hmap_idles_t_erase_at(&(self->hmap), find_result);
    }
    localIdleItemSetRemoved(item);
}

static local_idle_item_t *localidletableGetFirstActiveItem(local_idle_table_t *self)
{
    localidletableAssertOwner(self);

    c_foreach(item_iter, local_hmap_idles_t, self->hmap)
    {
        local_idle_item_t *item = item_iter.ref->second;
        if (! localIdleItemIsRemoved(item))
        {
            return item;
        }
    }

    return NULL;
}

static void localidletableRemoveItemFromHeap(local_idle_table_t *self, local_idle_item_t *target)
{
    localidletableAssertOwner(self);
    assert(target != NULL);

    local_heapq_idles_t_make_heap(&(self->hqueue));

    local_heapq_idles_t kept = local_heapq_idles_t_with_capacity(local_heapq_idles_t_size(&(self->hqueue)));
    while (local_heapq_idles_t_size(&(self->hqueue)) > 0)
    {
        local_idle_item_t *item = *local_heapq_idles_t_top(&(self->hqueue));
        local_heapq_idles_t_pop(&(self->hqueue));

        if (item != target)
        {
            local_heapq_idles_t_push(&kept, item);
        }
    }

    local_heapq_idles_t_drop(&(self->hqueue));
    self->hqueue = kept;
}

local_idle_table_t *localIdleTableCreate(wloop_t *loop)
{
    assert(loop != NULL);
    assert((wid_t) wloopGetWID(loop) == getWID());

    wloopUpdateTime(loop);

    const size_t        required_size = sizeof(local_idle_table_t);
    local_idle_table_t *newtable      = memoryAllocateCacheAligned(required_size);
    if (newtable == NULL)
    {
        printError("LocalIdleTable: failed to allocate local idle table");
        terminateProgram(1);
    }

    *newtable = (local_idle_table_t) {.memptr = (uintptr_t) newtable,
                                      .loop   = loop,
                                      .hqueue = local_heapq_idles_t_with_capacity(kLocalIdleTableCap),
                                      .hmap   = local_hmap_idles_t_with_capacity(kLocalIdleTableCap),
                                      .wid    = getWID()};

    newtable->idle_handle = wtimerAdd(loop, localIdleCallBack, kLocalDefaultTimeout, INFINITE);
    if (UNLIKELY(newtable->idle_handle == NULL))
    {
        local_heapq_idles_t_drop(&(newtable->hqueue));
        local_hmap_idles_t_drop(&(newtable->hmap));
        memoryFreeAligned((void *) (newtable->memptr)); // NOLINT
        printError("LocalIdleTable: failed to create idle timer");
        terminateProgram(1);
    }

    localidletableAssertOwner(newtable);
    weventSetUserData(newtable->idle_handle, newtable);
    return newtable;
}

local_idle_item_t *localidletableCreateItem(local_idle_table_t *self, hash_t key, void *userdata,
                                            LocalIdleExpireCallBack cb, uint64_t age_ms)
{
    localidletableAssertOwner(self);

    local_idle_item_t *item = memoryAllocate(sizeof(local_idle_item_t));
    if (UNLIKELY(item == NULL))
    {
        printError("LocalIdleTable: failed to allocate local idle item");
        terminateProgram(1);
    }

    *item = (local_idle_item_t) {.expire_at_ms = wloopNowMS(self->loop) + age_ms,
                                 .hash         = key,
                                 .userdata     = userdata,
                                 .cb           = cb,
                                 .table        = self,
                                 .removed      = false};

    if (! local_hmap_idles_t_insert(&(self->hmap), item->hash, item).inserted)
    {
        memoryFree(item);
        return NULL;
    }

    local_heapq_idles_t_push(&(self->hqueue), item);
    return item;
}

local_idle_item_t *localidletableGetIdleItemByHash(local_idle_table_t *self, hash_t key)
{
    localidletableAssertOwner(self);

    local_hmap_idles_t_iter find_result = local_hmap_idles_t_find(&(self->hmap), key);
    if (find_result.ref == local_hmap_idles_t_end(&(self->hmap)).ref)
    {
        return NULL;
    }

    local_idle_item_t *item = find_result.ref->second;
    if (localIdleItemIsRemoved(item))
    {
        return NULL;
    }
    return item;
}

void localidletableKeepIdleItemForAtleast(local_idle_table_t *self, local_idle_item_t *item, uint64_t age_ms)
{
    localidletableAssertOwner(self);
    assert(item != NULL);
    assert(item->table == self);

    if (UNLIKELY(item->table != self || localIdleItemIsRemoved(item)))
    {
        printError("LocalIdleTable: attempt to keep an already removed idle item alive");
        terminateProgram(1);
        return;
    }

    localIdleItemKeepExpireAtForAtleast(item, wloopNowMS(self->loop) + age_ms);
}

bool localidletableRemoveIdleItemByHash(local_idle_table_t *self, hash_t key)
{
    localidletableAssertOwner(self);

    local_hmap_idles_t_iter find_result = local_hmap_idles_t_find(&(self->hmap), key);
    if (find_result.ref == local_hmap_idles_t_end(&(self->hmap)).ref)
    {
        return false;
    }

    local_idle_item_t *item = find_result.ref->second;
    localidletableEraseItemFromMap(self, item);
    return true;
}

void localidletableDrainItems(local_idle_table_t *self)
{
    localidletableAssertOwner(self);

    for (;;)
    {
        local_idle_item_t *item = localidletableGetFirstActiveItem(self);
        if (item == NULL)
        {
            return;
        }

        localidletableEraseItemFromMap(self, item);
        localidletableRemoveItemFromHeap(self, item);

        if (item->cb != NULL && item->userdata != NULL)
        {
            item->cb(item);
        }
        memoryFree(item);
    }
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

    const uint64_t now = wloopNowMS(self->loop);

    local_heapq_idles_t_make_heap(&self->hqueue);

    while (local_heapq_idles_t_size(&(self->hqueue)) > 0)
    {
        local_idle_item_t *item = *local_heapq_idles_t_top(&(self->hqueue));

        const uint64_t item_expire_at_ms = localIdleItemGetExpireAt(item);
        if (item_expire_at_ms > now)
        {
            next_timeout = min(next_timeout, item_expire_at_ms - now);
            break;
        }

        local_heapq_idles_t_pop(&(self->hqueue));

        if (localIdleItemIsRemoved(item))
        {
            memoryFree(item);
            continue;
        }

        const uint64_t old_expire_at_ms = localIdleItemGetExpireAt(item);

        if (item->cb != NULL)
        {
            item->cb(item);
        }

        const uint64_t new_expire_at_ms = localIdleItemGetExpireAt(item);
        const bool keep_alive = ! localIdleItemIsRemoved(item) && item->table == self &&
                                old_expire_at_ms != new_expire_at_ms &&
                                new_expire_at_ms > wloopNowMS(self->loop);

        if (keep_alive)
        {
            local_heapq_idles_t_push(&(self->hqueue), item);
        }
        else
        {
            if (! localIdleItemIsRemoved(item) && item->table == self)
            {
                localidletableEraseItemFromMap(self, item);
            }
            memoryFree(item);
        }
    }

    wtimerReset(timer, (uint32_t) next_timeout);
}

void localidletableDestroy(local_idle_table_t *self)
{
    localidletableAssertOwner(self);

    if (self->idle_handle != NULL)
    {
        weventSetUserData(self->idle_handle, NULL);
        wtimerDelete(self->idle_handle);
        self->idle_handle = NULL;
    }

    while (local_heapq_idles_t_size(&(self->hqueue)) > 0)
    {
        local_idle_item_t *item = *local_heapq_idles_t_top(&(self->hqueue));
        local_heapq_idles_t_pop(&(self->hqueue));
        memoryFree(item);
    }

    local_heapq_idles_t_drop(&self->hqueue);
    local_hmap_idles_t_drop(&self->hmap);
    memoryFreeAligned((void *) (self->memptr)); // NOLINT
}

/**
 * @file widle_table.h
 * @brief Synchronized idle table for items owned by multiple event workers.
 *
 * The table structure and its indexes are synchronized, but raw idle_item_t
 * handles are worker-owned borrowed references rather than thread-safe handles.
 * Each item records one owner WID. Create, lookup, refresh, and explicit removal
 * for that item run on that exact event worker; a handle must never be retained
 * or dereferenced by another thread. Expiration is staged by the table's timer
 * and posted to the recorded owner worker.
 *
 * Common logical lifecycle shared with local_idle_table_t:
 *
 * 1. Successful creation publishes one active item in both the lookup and
 *    expiration indexes. Keys are unique across this entire shared table; WID
 *    is not part of key identity. Duplicate keys return NULL without partial
 *    publication.
 * 2. Lookup returns only an active item visible to the requested owner WID.
 * 3. Keep...ForAtleast only extends a deadline. Deadline arithmetic saturates
 *    at UINT64_MAX and never wraps to an earlier expiration.
 * 4. Successful explicit removal removes lookup visibility before returning,
 *    suppresses expiration, and logically invalidates every raw handle
 *    immediately. The caller must not inspect any item field afterward.
 * 5. A natural-expiration callback receives a pointer valid only for that
 *    invocation. An authoritative owner slot must be cleared before a terminal
 *    callback returns or destroys its consumer. The callback may instead extend
 *    itself and remain active, or remove itself, without duplicate delivery.
 * 6. Refreshing or removing an invalid handle is a caller lifetime error; stale
 *    raw pointers are not made safe by delayed physical reclamation.
 *
 * Physical reclamation is deliberately different from local_idle_table_t. An
 * expiring item can be message-owned. Cancellation restores an attached item;
 * removal, worker drain, or destruction detaches it so message settlement frees
 * it. Posted messages pin the table until their callback or cleanup completes.
 * Deadline refresh remains mutex-free and does not reorder the heap. The timer
 * rebuilds heap ordering under the mutex, keeping traffic-path refreshes cheap.
 */

#pragma once

#include "wlibc.h"
#include "wloop.h"
#include "worker.h"

typedef struct idle_item_s idle_item_t;

/**
 * @brief Callback type to be invoked on item expiration.
 *
 * Natural expiration is posted to item->wid. The item is still active during
 * that invocation and may extend or remove itself. Worker drain invokes the
 * same callback inline after lookup invalidation; a drain callback is terminal
 * and must only settle its consumer.
 *
 * @param item Pointer to the expired idle_item_t object.
 */
typedef void (*ExpireCallBack)(idle_item_t *);

/**
 * @brief Idle item structure.
 *
 * This structure represents an item in the idle table.
 */
struct idle_item_s
{
    void            *userdata;               ///< User data associated with the item.
    atomic_uintptr_t table;                  ///< Parent idle table pointer, or 0 when detached.
    atomic_ullong    expire_at_ms;           ///< Expiration time in milliseconds.
    ExpireCallBack   cb;                     ///< Expiration callback.
    hash_t           hash;                   ///< Hash used for item lookup.
    wid_t            wid;                    ///< Worker ID that owns this item.
    atomic_bool      removed;                ///< Logically invalid/detached item.
    atomic_bool      worker_message_pending; ///< A posted expiration message temporarily owns delivery. Cancellation
                                             ///< restores an attached item to the table; detached items are freed.
};
typedef struct idle_table_s idle_table_t;

/**
 * @brief Create an idle table.
 *
 * The caller must own @p loop while installing its timer. Initialization
 * failures are invariant/resource failures and abort under the current policy.
 *
 * @param loop Pointer to the event loop.
 * @return Pointer to a new idle table instance.
 */
idle_table_t *idleTableCreate(wloop_t *loop);

/**
 * @brief Destroy an idle table.
 *
 * Releases all resources associated with the idle table.
 * The caller must first stop timer admission and ensure no owner will begin a
 * new public item operation. Destruction may run from the shutdown coordinator;
 * queued expiration messages retain the table until they settle. Active items
 * are detached without invoking their callbacks.
 *
 * @param self Pointer to the idle table.
 */
void idletableDestroy(idle_table_t *self);

/**
 * @brief Create a new idle item.
 *
 * Allocates and adds an idle item into the table.
 * Must run on event worker @p wid. The returned pointer is borrowed from the
 * table and remains valid only while the item is active and owned by that
 * worker. Successful publication is atomic across both indexes.
 *
 * @param self Pointer to the idle table.
 * @param key Hash key for the item.
 * @param userdata Pointer to user data.
 * @param cb Expiration callback.
 * @param wid Worker ID of the caller.
 * @param age_ms Expiration age (in milliseconds).
 * @return Borrowed pointer to the new idle item; NULL if allocation or either index
 * publication fails, or if the key already exists.
 */
idle_item_t *idletableCreateItem(idle_table_t *self, hash_t key, void *userdata, ExpireCallBack cb, wid_t wid,
                                 uint64_t age_ms);

/**
 * @brief Retrieve an idle item by hash.
 *
 * Must run on event worker @p wid. The returned pointer is a turn-local borrowed
 * owner handle. It is NULL when the globally unique key is absent or belongs to
 * another WID.
 *
 * @param wid Worker ID of the caller.
 * @param self Pointer to the idle table.
 * @param key Hash key of the item.
 * @return Pointer to the idle item if found; otherwise, NULL.
 */
idle_item_t *idletableGetIdleItemByHash(wid_t wid, idle_table_t *self, hash_t key);

/**
 * @brief Update the expiration of an idle item.
 *
 * The idle item will be kept for at least the specified duration from now.
 * Must run on item->wid with an active borrowed handle. This operation is
 * mutex-free, never shortens the deadline, and intentionally does not reorder
 * the heap; the next timer scan rebuilds ordering under the table mutex.
 *
 * @param self Pointer to the idle table.
 * @param item The idle item to update.
 * @param age_ms Minimum age to keep the item.
 */
void idletableKeepIdleItemForAtleast(idle_table_t *self, idle_item_t *item, uint64_t age_ms);

/**
 * @brief Drain active idle items owned by one worker.
 *
 * Invokes each item's expiration callback and releases the idle item. This is
 * intended for worker shutdown, before that worker's line pools are destroyed.
 * Must be called on worker @p wid, since the callbacks run inline on the caller.
 *
 * Items whose expiration message is already posted are detached and left to that
 * message, so their callback is not invoked here.
 * Lookup visibility is removed before each inline callback. A drain callback is
 * terminal and must not refresh or remove the already invalid item.
 *
 * @param self Pointer to the idle table.
 * @param wid Worker ID whose active items should be drained.
 */
void idletableDrainWorkerItems(idle_table_t *self, wid_t wid);

/**
 * @brief Remove an idle item by hash.
 *
 * Must run on event worker @p wid. Success removes lookup visibility
 * synchronously, suppresses expiration, and invalidates all raw handles before
 * return. Physical reclamation can remain heap- or message-owned. False means
 * the key is absent or belongs to another owner; no state changed.
 *
 * @param wid Worker ID of the caller.
 * @param self Pointer to the idle table.
 * @param key Hash key of the item.
 * @return true if the item was removed; false otherwise.
 */
bool idletableRemoveIdleItemByHash(wid_t wid, idle_table_t *self, hash_t key);

#ifdef WW_IDLE_TABLE_TEST_SEAM
void         idleCallBack(wtimer_t *timer);
void         idletableTestRefuseNextInitialStagingReserve(void);
void         idletableTestRefuseNextStagingGrowth(void);
void         idletableTestRefuseNextCreateHeapPublication(void);
void         idletableTestSetNowMS(idle_table_t *self, uint64_t now_ms);
void         idletableTestRunExpiry(idle_table_t *self);
uint64_t     idletableTestGetDeadline(const idle_item_t *item);
size_t       idletableTestGetActiveItemCount(idle_table_t *self);
unsigned int idletableTestGetLiveItemCount(void);
unsigned int idletableTestGetLiveTableCount(void);
#endif

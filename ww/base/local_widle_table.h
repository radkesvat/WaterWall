/**
 * @file local_widle_table.h
 * @brief Worker-local idle table implementation.
 *
 * The local idle table stores idle items that are created, refreshed, removed,
 * expired, drained, and destroyed only on the worker that owns the table.
 * It intentionally has no table mutex, atomic item fields, or cross-worker
 * expiration messages.
 *
 * Common logical lifecycle shared with idle_table_t:
 *
 * 1. Successful creation publishes one active item in both the lookup and
 *    expiration indexes. A key is unique within this local table; duplicate
 *    keys return NULL without partial publication.
 * 2. Lookup returns only an active item on the table's owner worker.
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
 *    raw pointers are not made safe.
 *
 * Physical reclamation is worker-local: explicit removal normally frees an
 * active heap item immediately. While the expiry loop owns the callback
 * allocation, removal detaches it and the loop frees it after the callback.
 */

#pragma once

#include "wlibc.h"
#include "wloop.h"
#include "worker.h"

typedef struct local_idle_item_s  local_idle_item_t;
typedef struct local_idle_table_s local_idle_table_t;

/**
 * @brief Callback type invoked when a local idle item expires or is drained.
 *
 * A natural-expiration item is still active during the callback and may extend
 * or remove itself. A drain callback is terminal: lookup was already removed,
 * so it must only settle its consumer and clear any authoritative owner slot.
 *
 * @param item Expired idle item.
 */
typedef void (*LocalIdleExpireCallBack)(local_idle_item_t *);

/**
 * @brief Worker-local idle item.
 */
struct local_idle_item_s
{
    void                   *userdata;     ///< User data associated with the item.
    local_idle_table_t     *table;        ///< Parent local idle table.
    uint64_t                expire_at_ms; ///< Expiration time in milliseconds.
    LocalIdleExpireCallBack cb;           ///< Expiration callback.
    hash_t                  hash;         ///< Hash used for item lookup.
    size_t                  heap_index;   ///< Indexed-heap slot, or SIZE_MAX while expiring.
    bool                    removed;      ///< Detached while the expiry callback owned it.
    bool                    expiring;     ///< Expiry loop currently owns the allocation.
};

/**
 * @brief Create a worker-local idle table.
 *
 * Must be called on the same worker that owns @p loop.
 * Allocation or timer failure is fail-fast under the current invariant policy.
 *
 * @param loop Owner worker event loop.
 * @return local_idle_table_t* New local idle table.
 */
local_idle_table_t *localIdleTableCreate(wloop_t *loop);

/**
 * @brief Destroy a worker-local idle table.
 *
 * Must be called on the table owner worker. Active items are released without
 * invoking expiration callbacks; call localidletableDrainItems() first if the
 * callbacks must run.
 *
 * @param self Local idle table.
 */
void localidletableDestroy(local_idle_table_t *self);

/**
 * @brief Stop the table's expiration timer on its owner worker.
 *
 * This suppresses future natural-expiration callbacks but leaves every active
 * item indexed for owner-worker drain or callback-suppressing destruction.
 */
void localidletableQuiesce(local_idle_table_t *self);

/**
 * @brief Create and add one worker-local idle item.
 *
 * Must run on the table owner worker. The returned pointer is borrowed from the
 * table and remains valid only while the item stays active. Item allocation or
 * heap growth failure is fail-fast; duplicate-key rejection returns NULL.
 *
 * @param self Local idle table.
 * @param key Hash key for lookup.
 * @param userdata User data associated with the item.
 * @param cb Expiration callback.
 * @param age_ms Expiration age in milliseconds.
 * @return local_idle_item_t* New item, or NULL if @p key already exists.
 */
local_idle_item_t *localidletableCreateItem(local_idle_table_t *self, hash_t key, void *userdata,
                                            LocalIdleExpireCallBack cb, uint64_t age_ms);

/**
 * @brief Retrieve a worker-local idle item by hash.
 *
 * Must run on the table owner worker. The returned pointer is borrowed and must
 * not be transferred across workers.
 *
 * @param self Local idle table.
 * @param key Hash key for lookup.
 * @return local_idle_item_t* Found item, or NULL.
 */
local_idle_item_t *localidletableGetIdleItemByHash(local_idle_table_t *self, hash_t key);

/**
 * @brief Keep an item alive for at least @p age_ms from the owner loop's current time.
 *
 * This only extends expiration; it does not shorten a later expiration.
 * Must run on the table owner worker with an active borrowed handle.
 *
 * @param self Local idle table.
 * @param item Item to refresh.
 * @param age_ms Minimum age in milliseconds.
 */
void localidletableKeepIdleItemForAtleast(local_idle_table_t *self, local_idle_item_t *item, uint64_t age_ms);

/**
 * @brief Remove an item through its direct handle.
 *
 * Outside an expiry callback this unlinks the item from both indexes and frees
 * it immediately. An expiring item remains owned by the expiry loop until its
 * callback returns. Success invalidates @p item before return; do not inspect it
 * afterward. False means no active item was removable; passing a stale pointer
 * is a caller lifetime error rather than a supported absence check.
 *
 * @param self Local idle table.
 * @param item Item owned by @p self.
 * @return true if the item was active and removed; false otherwise.
 */
bool localidletableRemoveIdleItem(local_idle_table_t *self, local_idle_item_t *item);

/**
 * @brief Remove an item by hash.
 *
 * The item is removed from both indexes and released immediately unless its
 * expiry callback currently owns it. Success invalidates every raw handle before
 * return and suppresses the callback. False means the key is absent.
 *
 * @param self Local idle table.
 * @param key Hash key for lookup.
 * @return true if an item was removed; false otherwise.
 */
bool localidletableRemoveIdleItemByHash(local_idle_table_t *self, hash_t key);

/**
 * @brief Return the number of active worker-owned items.
 *
 * Must run on the table owner worker. This is an invariant/diagnostic query;
 * returned item ownership is unchanged.
 */
size_t localidletableGetItemCount(local_idle_table_t *self);

/**
 * @brief Drain all active items.
 *
 * Invokes each active item's callback and releases the item. This is intended
 * for owner-worker shutdown before worker-local resources referenced by
 * callbacks are destroyed.
 * Lookup visibility is removed before each inline callback; drain callbacks may
 * not refresh or remove the already invalid item.
 *
 * @param self Local idle table.
 */
void localidletableDrainItems(local_idle_table_t *self);

#ifdef WW_IDLE_TABLE_TEST_SEAM
void         localidletableTestSetNowMS(local_idle_table_t *self, uint64_t now_ms);
void         localidletableTestRunExpiry(local_idle_table_t *self);
uint64_t     localidletableTestGetDeadline(const local_idle_item_t *item);
bool         localidletableTestIsQuiesced(const local_idle_table_t *self);
unsigned int localidletableTestGetLiveItemCount(void);
unsigned int localidletableTestGetLiveTableCount(void);
#endif

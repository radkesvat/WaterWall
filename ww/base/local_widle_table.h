/**
 * @file local_widle_table.h
 * @brief Worker-local idle table implementation.
 *
 * The local idle table stores idle items that are created, refreshed, removed,
 * expired, drained, and destroyed only on the worker that owns the table.
 * It intentionally has no table mutex, atomic item fields, or cross-worker
 * expiration messages.
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
 * @param item Expired idle item.
 */
typedef void (*LocalIdleExpireCallBack)(local_idle_item_t *);

/**
 * @brief Worker-local idle item.
 */
struct local_idle_item_s
{
    void                    *userdata;     ///< User data associated with the item.
    local_idle_table_t      *table;        ///< Parent local idle table.
    uint64_t                 expire_at_ms; ///< Expiration time in milliseconds.
    LocalIdleExpireCallBack  cb;           ///< Expiration callback.
    hash_t                   hash;         ///< Hash used for item lookup.
    bool                     removed;      ///< Lazy removal flag.
};

/**
 * @brief Create a worker-local idle table.
 *
 * Must be called on the same worker that owns @p loop.
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
 * @brief Create and add one worker-local idle item.
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
 * @param self Local idle table.
 * @param key Hash key for lookup.
 * @return local_idle_item_t* Found item, or NULL.
 */
local_idle_item_t *localidletableGetIdleItemByHash(local_idle_table_t *self, hash_t key);

/**
 * @brief Keep an item alive for at least @p age_ms from the owner loop's current time.
 *
 * This only extends expiration; it does not shorten a later expiration.
 *
 * @param self Local idle table.
 * @param item Item to refresh.
 * @param age_ms Minimum age in milliseconds.
 */
void localidletableKeepIdleItemForAtleast(local_idle_table_t *self, local_idle_item_t *item, uint64_t age_ms);

/**
 * @brief Remove an item by hash.
 *
 * The item is removed from lookup immediately and released lazily when the
 * timer reaches its heap entry or when the table is destroyed.
 *
 * @param self Local idle table.
 * @param key Hash key for lookup.
 * @return true if an item was removed; false otherwise.
 */
bool localidletableRemoveIdleItemByHash(local_idle_table_t *self, hash_t key);

/**
 * @brief Drain all active items.
 *
 * Invokes each active item's callback and releases the item. This is intended
 * for owner-worker shutdown before worker-local resources referenced by
 * callbacks are destroyed.
 *
 * @param self Local idle table.
 */
void localidletableDrainItems(local_idle_table_t *self);

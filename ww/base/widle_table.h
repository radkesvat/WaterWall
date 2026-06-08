/**
 * @file widle_table.h
 * @brief Thread-safe idle table implementation.
 *
 * The idle table stores idle_item_t objects that each have an expiration timeout.
 * When the timeout expires, the idle item is removed and its callback is invoked.
 * Each item belongs to a worker. Expiration callbacks run on that worker via the
 * worker-message queue when the table's timer loop is not the item owner.
 *
 * The adding or modifying of idle items will not cause heap reordering and therefore is performant.
 *
 *
 * Note: The underlying timer uses a heap-based mechanism.
 */

#pragma once

#include "wlibc.h"
#include "wloop.h"
#include "worker.h"

typedef struct idle_item_s idle_item_t;

/**
 * @brief Callback type to be invoked on item expiration.
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
    atomic_bool      removed;                ///< Flag indicating if the item is removed.
    atomic_bool      worker_message_pending; ///< An expiration worker message owns the item memory.
};
typedef struct idle_table_s idle_table_t;

/**
 * @brief Create an idle table.
 *
 * @param loop Pointer to the event loop.
 * @return Pointer to a new idle table instance.
 */
idle_table_t *idleTableCreate(wloop_t *loop);

/**
 * @brief Destroy an idle table.
 *
 * Releases all resources associated with the idle table.
 *
 * @param self Pointer to the idle table.
 */
void idletableDestroy(idle_table_t *self);

/**
 * @brief Create a new idle item.
 *
 * Allocates and adds an idle item into the table.
 *
 * @param self Pointer to the idle table.
 * @param key Hash key for the item.
 * @param userdata Pointer to user data.
 * @param cb Expiration callback.
 * @param wid Worker ID of the caller.
 * @param age_ms Expiration age (in milliseconds).
 * @return Pointer to the new idle item; NULL if key already exists.
 */
idle_item_t *idletableCreateItem(idle_table_t *self, hash_t key, void *userdata, ExpireCallBack cb, wid_t wid,
                                 uint64_t age_ms);

/**
 * @brief Retrieve an idle item by hash.
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
 *
 * @param self Pointer to the idle table.
 * @param wid Worker ID whose active items should be drained.
 */
void idletableDrainWorkerItems(idle_table_t *self, wid_t wid);

/**
 * @brief Remove an idle item by hash.
 *
 * Marks the idle item as removed and removes it from the table (lazy deletion).
 *
 * @param wid Worker ID of the caller.
 * @param self Pointer to the idle table.
 * @param key Hash key of the item.
 * @return true if the item was removed; false otherwise.
 */
bool idletableRemoveIdleItemByHash(wid_t wid, idle_table_t *self, hash_t key);

/**
 * @file widle_table.h
 * @brief Thread-safe idle table implementation.
 *
 * The idle table stores idle_item_t objects that each have an expiration timeout.
 * When the timeout expires, the idle item is removed and its callback is invoked.
 * Items are thread-local, and operations must be performed on the same thread that created them.
 *
 * Note: The underlying timer uses a heap-based mechanism.
 */

#pragma once

#include "wlibc.h"
#include "wloop.h"
#include "worker.h"


/**
 * @brief Callback type to be invoked on item expiration.
 *
 * @param item Pointer to the expired idle_item_t object.
 */
typedef void (*ExpireCallBack)(struct widle_item_s *);

/**
 * @brief Idle item structure (thread-local).
 *
 * This structure represents an item in the idle table.
 */
struct widle_item_s
{
    void                 *userdata;     ///< User data associated with the item.
    struct widle_table_s *table;        ///< Pointer to the parent idle table.
    hash_t                hash;         ///< Hash used for item lookup.
    ExpireCallBack        cb;           ///< Expiration callback.
    uint64_t              expire_at_ms; ///< Expiration time in milliseconds.
    uint8_t               tid;          ///< Thread ID that owns this item.
    bool                  removed;      ///< Flag indicating if the item is removed.
};
typedef struct widle_item_s  idle_item_t;
typedef struct widle_table_s widle_table_t;

/**
 * @brief Create an idle table.
 *
 * @param loop Pointer to the event loop.
 * @return Pointer to a new idle table instance.
 */
widle_table_t *idleTableCreate(wloop_t *loop);

/**
 * @brief Destroy an idle table.
 *
 * Releases all resources associated with the idle table.
 *
 * @param self Pointer to the idle table.
 */
void idleTableDestroy(widle_table_t *self);

/**
 * @brief Create a new idle item.
 *
 * Allocates and adds an idle item into the table.
 *
 * @param self Pointer to the idle table.
 * @param key Hash key for the item.
 * @param userdata Pointer to user data.
 * @param cb Expiration callback.
 * @param tid Thread ID of the caller.
 * @param age_ms Expiration age (in milliseconds).
 * @return Pointer to the new idle item; NULL if key already exists.
 */
idle_item_t *idleItemNew(widle_table_t *self, hash_t key, void *userdata, ExpireCallBack cb, wid_t tid,
                         uint64_t age_ms);

/**
 * @brief Retrieve an idle item by hash.
 *
 * @param tid Thread ID of the caller.
 * @param self Pointer to the idle table.
 * @param key Hash key of the item.
 * @return Pointer to the idle item if found; otherwise, NULL.
 */
idle_item_t *idleTableGetIdleItemByHash(wid_t tid, widle_table_t *self, hash_t key);

/**
 * @brief Update the expiration of an idle item.
 *
 * The idle item will be kept for at least the specified duration from now.
 *
 * @param self Pointer to the idle table.
 * @param item The idle item to update.
 * @param age_ms Minimum age to keep the item.
 */
void idleTableKeepIdleItemForAtleast(widle_table_t *self, idle_item_t *item, uint64_t age_ms);

/**
 * @brief Remove an idle item by hash.
 *
 * Marks the idle item as removed and removes it from the table (lazy deletion).
 *
 * @param tid Thread ID of the caller.
 * @param self Pointer to the idle table.
 * @param key Hash key of the item.
 * @return true if the item was removed; false otherwise.
 */
bool idleTableRemoveIdleItemByHash(wid_t tid, widle_table_t *self, hash_t key);

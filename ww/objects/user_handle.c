#include "user_handle.h"

#include "global_state.h"
#include "loggers/internal_logger.h"

enum
{
    kUserHandleIdentifierInitialCap = 64
};

typedef struct user_handle_identifier_key_s
{
    uint8_t sha256[SHA256_DIGEST_SIZE];
} user_handle_identifier_key_t;

static uint64_t userHandleIdentifierKeyHash(const user_handle_identifier_key_t *key)
{
    return calcHashBytes(key->sha256, SHA256_DIGEST_SIZE);
}

static bool userHandleIdentifierKeyEq(const user_handle_identifier_key_t *a, const user_handle_identifier_key_t *b)
{
    return memoryCompare(a->sha256, b->sha256, SHA256_DIGEST_SIZE) == 0;
}

#define i_type user_handle_identifier_map_t // NOLINT
#define i_key  user_handle_identifier_key_t // NOLINT
#define i_val  uint64_t                     // NOLINT
#define i_hash userHandleIdentifierKeyHash  // NOLINT
#define i_eq   userHandleIdentifierKeyEq    // NOLINT
#include "stc/hmap.h"
#undef i_eq
#undef i_hash
#undef i_val
#undef i_key
#undef i_type

struct user_handle_identifier_registry_s
{
    wrwlock_t                    lock;
    user_handle_identifier_map_t map;
};

static user_handle_identifier_key_t userHandleIdentifierKeyFromSHA256(const uint8_t sha256[SHA256_DIGEST_SIZE])
{
    user_handle_identifier_key_t key = {0};

    memoryCopy(key.sha256, sha256, SHA256_DIGEST_SIZE);
    return key;
}

user_handle_identifier_registry_t *userHandleIdentifierRegistryCreate(void)
{
    user_handle_identifier_registry_t *registry = memoryAllocate(sizeof(*registry));
    if (UNLIKELY(registry == NULL))
    {
        LOGF("UserHandle: failed to allocate identifier registry");
        terminateProgram(1);
        return NULL;
    }

    memoryZero(registry, sizeof(*registry));
    rwlockinit(&registry->lock);
    registry->map = user_handle_identifier_map_t_with_capacity(kUserHandleIdentifierInitialCap);

    return registry;
}

void userHandleIdentifierRegistryDestroy(user_handle_identifier_registry_t *registry)
{
    if (registry == NULL)
    {
        return;
    }

    user_handle_identifier_map_t_drop(&registry->map);
    rwlockDestroy(&registry->lock);
    memoryFree(registry);
}

static uint64_t userHandleGetOrCreateIdentifier(const uint8_t sha256[SHA256_DIGEST_SIZE])
{
    user_handle_identifier_registry_t *registry = GSTATE.user_handle_identifier_registry;
    if (UNLIKELY(registry == NULL))
    {
        LOGF("UserHandle: identifier registry is not initialized");
        terminateProgram(1);
        return 0;
    }

    user_handle_identifier_key_t key = userHandleIdentifierKeyFromSHA256(sha256);

    rwlockReadLock(&registry->lock);
    user_handle_identifier_map_t_iter it = user_handle_identifier_map_t_find(&registry->map, key);
    if (it.ref != user_handle_identifier_map_t_end(&registry->map).ref)
    {
        uint64_t id = it.ref->second;
        rwlockReadUnlock(&registry->lock);
        return id;
    }
    rwlockReadUnlock(&registry->lock);

    rwlockWriteLock(&registry->lock);

    it = user_handle_identifier_map_t_find(&registry->map, key);
    if (it.ref != user_handle_identifier_map_t_end(&registry->map).ref)
    {
        uint64_t id = it.ref->second;
        rwlockWriteUnlock(&registry->lock);
        return id;
    }

    uint64_t id = (uint64_t) atomicAddExplicit(&GSTATE.next_user_handle_identifier, 1, memory_order_relaxed);
    if (UNLIKELY(id == 0 || id == UINT64_MAX))
    {
        rwlockWriteUnlock(&registry->lock);
        LOGF("UserHandle: identifier counter overflow");
        terminateProgram(1);
        return 0;
    }

    user_handle_identifier_map_t_result result = user_handle_identifier_map_t_insert(&registry->map, key, id);
    if (UNLIKELY(! result.inserted))
    {
        rwlockWriteUnlock(&registry->lock);
        LOGF("UserHandle: failed to register identifier");
        terminateProgram(1);
        return 0;
    }

    rwlockWriteUnlock(&registry->lock);
    return id;
}

user_handle_t userHandleEmpty(void)
{
    user_handle_t handle;
    userHandleClear(&handle);
    return handle;
}

void userHandleClear(user_handle_t *handle)
{
    if (handle == NULL)
    {
        return;
    }

    memoryZero(handle, sizeof(*handle));
}

void userHandleSet(user_handle_t *handle, const uint8_t sha256[SHA256_DIGEST_SIZE], uint64_t generation)
{
    if (handle == NULL)
    {
        return;
    }

    if (sha256 == NULL || generation == 0)
    {
        userHandleClear(handle);
        return;
    }

    memoryCopy(handle->sha256, sha256, SHA256_DIGEST_SIZE);
    handle->generation               = generation;
    handle->local_global_identifier  = userHandleGetOrCreateIdentifier(sha256);
}

bool userHandleIsValid(const user_handle_t *handle)
{
    uint8_t zero[SHA256_DIGEST_SIZE] = {0};

    return handle != NULL && handle->generation != 0 && ! memoryEqual(handle->sha256, zero, sizeof(zero));
}

#include "user_handle.h"

#include <stddef.h>

_Static_assert(offsetof(user_handle_t, sha256) % 32U == 0, "user_handle_t.sha256 must be 32-byte aligned");

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

void userHandleSet(user_handle_t *handle, const uint8_t sha256[SHA256_DIGEST_SIZE], uint64_t generation,
                   uint64_t user_id)
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
    handle->generation = generation;
    handle->user_id    = user_id;
}

bool userHandleIsValid(const user_handle_t *handle)
{
    uint8_t zero[SHA256_DIGEST_SIZE] = {0};

    return handle != NULL && handle->generation != 0 && ! memoryEqual(handle->sha256, zero, sizeof(zero));
}

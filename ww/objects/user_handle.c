#include "user_handle.h"

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

void userHandleSet(user_handle_t *handle, uint64_t generation, uint64_t user_id)
{
    if (handle == NULL)
    {
        return;
    }

    if (generation == 0 || user_id == 0)
    {
        userHandleClear(handle);
        return;
    }

    handle->generation = generation;
    handle->user_id    = user_id;
}

bool userHandleIsValid(const user_handle_t *handle)
{
    return handle != NULL && handle->generation != 0 && handle->user_id != 0;
}

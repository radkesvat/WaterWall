#pragma once

/*
 * Stable value handle for a user entry in a users_t snapshot.
 *
 * The handle identifies a user only by durable server-assigned user id. It is
 * not an owned pointer and may become stale for generation-gated read helpers
 * after the table is replaced.
 */

#include "wlibc.h"

typedef struct user_handle_s
{
    uint64_t generation;
    uint64_t user_id;
} user_handle_t;

user_handle_t userHandleEmpty(void);
void          userHandleClear(user_handle_t *handle);
void          userHandleSet(user_handle_t *handle, uint64_t generation, uint64_t user_id);
bool          userHandleIsValid(const user_handle_t *handle);

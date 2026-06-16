#pragma once

/*
 * Stable value handle for a user entry in a users_t snapshot.
 *
 * The handle identifies a user by durable server-assigned user id when one is
 * available, with SHA-256 password lookup key as the legacy fallback. It is
 * not an owned pointer and may become stale for generation-gated read helpers
 * after the table is replaced.
 */

#include "wlibc.h"

#include "wcrypto.h"

typedef struct user_handle_s
{
    MSVC_ATTR_ALIGNED_32 uint8_t sha256[SHA256_DIGEST_SIZE] GNU_ATTR_ALIGNED_32;
    uint64_t generation;
    uint64_t user_id;
} user_handle_t;

user_handle_t userHandleEmpty(void);
void          userHandleClear(user_handle_t *handle);
void          userHandleSet(user_handle_t *handle, const uint8_t sha256[SHA256_DIGEST_SIZE], uint64_t generation,
                            uint64_t user_id);
bool          userHandleIsValid(const user_handle_t *handle);

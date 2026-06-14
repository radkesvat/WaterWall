#pragma once

/*
 * Stable value handle for a user entry in a users_t snapshot.
 *
 * The handle identifies a user by SHA-256 password lookup key plus the users
 * table generation that produced it. It is not an owned pointer and may become
 * stale after the table is replaced.
 */

#include "wlibc.h"

#include "wcrypto.h"

typedef struct user_handle_s
{
    uint8_t  sha256[SHA256_DIGEST_SIZE];
    uint64_t generation;
} user_handle_t;

void userHandleClear(user_handle_t *handle);
void userHandleSet(user_handle_t *handle, const uint8_t sha256[SHA256_DIGEST_SIZE], uint64_t generation);
bool userHandleIsValid(const user_handle_t *handle);

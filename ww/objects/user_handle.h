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
    uint64_t local_global_identifier;
} user_handle_t;

typedef struct user_handle_identifier_registry_s user_handle_identifier_registry_t;

user_handle_t userHandleEmpty(void);
void          userHandleClear(user_handle_t *handle);
void          userHandleSet(user_handle_t *handle, const uint8_t sha256[SHA256_DIGEST_SIZE], uint64_t generation);
bool          userHandleIsValid(const user_handle_t *handle);

user_handle_identifier_registry_t *userHandleIdentifierRegistryCreate(void);
void                              userHandleIdentifierRegistryDestroy(user_handle_identifier_registry_t *registry);

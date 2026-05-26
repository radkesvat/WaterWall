#pragma once

/*
 * Internal user helpers shared only by user.c and users.c.
 *
 * The sync index is part of the in-memory user object but intentionally stays
 * out of the public user_t layout. Authentication sync code must go through
 * users_t helpers so database-level locking and pull snapshots remain coherent.
 */

#include "objects/user.h"

enum
{
    kUserSyncIndexInitial = 1U
};

struct user_private_s
{
    atomic_uint sync_index;
};

bool     userInternalStateCreate(User *user, uint32_t sync_index);
void     userInternalStateDestroy(User *user);
uint32_t userInternalSyncIndexLoad(const User *user);
uint32_t userInternalSyncIndexIncrement(User *user);

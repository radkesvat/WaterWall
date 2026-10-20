#include "user_internal.h"
#include "users_internal.h"
#include "utils/json_helpers.h"

void *usersAllocateAlignedZero32(size_t size)
{
    assert((size & 31U) == 0);

    /*
     * users_t-owned user_t objects rely on real 32-byte base alignment so their
     * SHA fields are actually 32-byte aligned at runtime. Keep this as aligned
     * zero allocation; do not replace it with memoryAllocateZero().
     */
    return memoryAllocateAlignedZero(size, 32);
}

user_t *usersStorageAtLocked(const users_t *users, size_t index)
{
    return &users->blocks[index / kUsersBlockSize][index % kUsersBlockSize];
}

user_t *usersGetAtLocked(const users_t *users, size_t index)
{
    return users->items[index];
}

const char *usersUserNameForLog(const user_t *user)
{
    if (UNLIKELY(user == NULL || user->name == NULL || user->name[0] == '\0'))
    {
        return "<unnamed>";
    }
    return user->name;
}

void usersStringDuplicate(char **dest, const char *value)
{
    *dest = stringDuplicate(value != NULL ? value : "");
}

void usersReplaceStringOwned(char **dest, char **owned_value)
{
    memoryFree(*dest);
    *dest        = *owned_value;
    *owned_value = NULL;
}

user_t *usersFindWireGuardAllowedIpsOverlapLocked(const users_t *users, bool valid, const ip_addr_t *network,
                                                  const ip_addr_t *mask, uint8_t family, const user_t *ignore,
                                                  bool *range_ok)
{
    uint8_t start16[16];
    uint8_t end16[16];

    if (range_ok != NULL)
    {
        *range_ok = true;
    }
    if (! valid)
    {
        return NULL;
    }
    if (UNLIKELY(! usersAllowedIpRangeFromFields(network, mask, family, start16, end16)))
    {
        if (range_ok != NULL)
        {
            *range_ok = false;
        }
        return NULL;
    }

    return usersAllowedIpTableFindOverlapLocked(users, family, start16, end16, ignore);
}

users_uuid_key_t usersUUIDKeyFromBytes(const uint8_t bytes[kWwUuidBytesLen])
{
    users_uuid_key_t key = {0};

    memoryCopy(key.bytes, bytes, kWwUuidBytesLen);
    return key;
}

users_wireguard_publickey_key_t usersWireGuardPublicKeyFromBytes(const uint8_t bytes[USER_WIREGUARD_PUBLICKEY_SIZE])
{
    users_wireguard_publickey_key_t key = {0};

    memoryCopy(key.bytes, bytes, USER_WIREGUARD_PUBLICKEY_SIZE);
    return key;
}

/*
 * Derives only the SHA-256 lookup key for a plaintext password. The hot
 * plaintext-lookup path indexes exclusively by SHA-256, so it must not pay for
 * the SHA-224/UUID/WireGuard-public-key material that userPreparePassword()
 * derives for the cold password-change path. Callers securely zero *sha256 once
 * they are done with it.
 */
bool usersPasswordLookupKeyCreate(sha256_hash_t *sha256, const char *password)
{
    if (UNLIKELY(sha256 == NULL || password == NULL || password[0] == '\0'))
    {
        return false;
    }

    if (UNLIKELY(wCryptoSHA256(sha256, (const unsigned char *) password, stringLength(password)) != kWCryptoOk))
    {
        memorySecureZero(sha256, sizeof(*sha256));
        return false;
    }

    return true;
}

bool usersReserveItemsLocked(users_t *users, size_t capacity)
{
    if (LIKELY(capacity <= users->capacity))
    {
        return true;
    }

    size_t new_capacity = users->capacity == 0 ? kUsersBlockSize : users->capacity;
    while (new_capacity < capacity)
    {
        if (UNLIKELY(new_capacity > SIZE_MAX / 2U))
        {
            LOGE("Users: active user pointer capacity overflow");
            return false;
        }
        new_capacity *= 2U;
    }
    if (UNLIKELY(new_capacity > SIZE_MAX / sizeof(*users->items)))
    {
        LOGE("Users: active user pointer capacity overflow");
        return false;
    }

    /* This array is aligned-allocated, so grow it manually; memoryReAllocate() cannot preserve that contract. */
    const size_t bytes = new_capacity * sizeof(*users->items);
    if (UNLIKELY(! memoryAlignedAllocationSizeIsRepresentable(bytes, 32)))
    {
        LOGE("Users: active user pointer capacity overflow");
        return false;
    }
    user_t **new_items = usersAllocateAlignedZero32(bytes);
    if (LIKELY(users->items != NULL))
    {
        memoryCopy(new_items, users->items, users->capacity * sizeof(*new_items));
        memoryFreeAligned(users->items);
    }

    users->items    = new_items;
    users->capacity = new_capacity;
    return true;
}

bool usersReserveStorageLocked(users_t *users, size_t slot_capacity)
{
    if (LIKELY(slot_capacity <= users->slot_capacity))
    {
        return true;
    }

    while (users->slot_capacity < slot_capacity)
    {
        user_t *block = NULL;

        if (UNLIKELY(users->block_count == users->block_capacity))
        {
            size_t new_block_capacity = users->block_capacity == 0
                                            ? (32U + sizeof(*users->blocks) - 1U) / sizeof(*users->blocks)
                                            : users->block_capacity * 2U;
            if (UNLIKELY(new_block_capacity < users->block_capacity ||
                         new_block_capacity > SIZE_MAX / sizeof(*users->blocks)))
            {
                LOGE("Users: user block pointer capacity overflow");
                return false;
            }

            /* Keep this manual grow in sync with memoryFreeAligned() in usersDestroy(). */
            const size_t bytes = new_block_capacity * sizeof(*users->blocks);
            if (UNLIKELY(! memoryAlignedAllocationSizeIsRepresentable(bytes, 32)))
            {
                LOGE("Users: user block pointer capacity overflow");
                return false;
            }
            user_t **new_blocks = usersAllocateAlignedZero32(bytes);
            if (LIKELY(users->blocks != NULL))
            {
                memoryCopy(new_blocks, users->blocks, users->block_capacity * sizeof(*new_blocks));
                memoryFreeAligned(users->blocks);
            }

            users->blocks         = new_blocks;
            users->block_capacity = new_block_capacity;
        }

        block = usersAllocateAlignedZero32(kUsersBlockSize * sizeof(*block));

        users->blocks[users->block_count] = block;
        users->block_count += 1U;
        users->slot_capacity += kUsersBlockSize;
    }

    return true;
}

bool usersReserveLocked(users_t *users, size_t capacity)
{
    size_t new_slots_needed;

    if (UNLIKELY(! usersReserveItemsLocked(users, capacity)))
    {
        return false;
    }

    new_slots_needed = capacity > users->count ? capacity - users->count : 0;
    if (UNLIKELY(users->slot_count > SIZE_MAX - new_slots_needed))
    {
        LOGE("Users: user storage capacity overflow");
        return false;
    }

    return usersReserveStorageLocked(users, users->slot_count + new_slots_needed);
}

bool usersIndexOfLocked(const users_t *users, const user_t *user, size_t *index_out)
{
    /* Average-O(1): the pointer table maps each stored user to its items[] index. */
    return usersPointerTableLookupLocked(users, user, index_out);
}

users_add_result_t usersAddUserChecked(users_t *users, const user_t *user)
{
    user_t            *slot;
    user_t             user_copy;
    users_add_result_t result;

    if (UNLIKELY(users == NULL || user == NULL))
    {
        return kUsersAddResultInvalidArgument;
    }
    if (UNLIKELY(! user->initialized))
    {
        return kUsersAddResultInvalidUser;
    }
    memoryZero(&user_copy, sizeof(user_copy));
    if (UNLIKELY(! userCopy(&user_copy, user)))
    {
        return kUsersAddResultStorageUnavailable;
    }

    rwlockWriteLock(&users->lock);

    result = usersValidateNewUserNoFatalLocked(users, &user_copy);
    if (UNLIKELY(result != kUsersAddResultOk))
    {
        rwlockWriteUnlock(&users->lock);
        userDestroy(&user_copy);
        return result;
    }
    if (UNLIKELY(! usersReserveLocked(users, users->count + 1U)))
    {
        rwlockWriteUnlock(&users->lock);
        userDestroy(&user_copy);
        return kUsersAddResultStorageUnavailable;
    }

    slot = usersStorageAtLocked(users, users->slot_count);
    if (UNLIKELY(! userMoveOwnedValue(slot, &user_copy)))
    {
        rwlockWriteUnlock(&users->lock);
        userDestroy(&user_copy);
        return kUsersAddResultStorageUnavailable;
    }
    /*
     * `slot` is an exact copy of the immutable, just-validated snapshot, so
     * commit skips the redundant revalidation. Capacity geometry refusal keeps
     * the public storage-unavailable result; heap exhaustion does not return.
     */
    if (UNLIKELY(! usersCommitNewUserLocked(users, slot, true)))
    {
        userDestroy(slot);
        rwlockWriteUnlock(&users->lock);
        userDestroy(&user_copy);
        return kUsersAddResultStorageUnavailable;
    }

    rwlockWriteUnlock(&users->lock);
    userDestroy(&user_copy);
    return kUsersAddResultOk;
}

user_t *usersLookupByPasswordLocked(users_t *users, const sha256_hash_t *sha256_key, const char *password)
{
    /*
     * Average-O(1) plaintext lookup. The SHA-256 table is the canonical password
     * index: every committed user has a valid SHA-256 key, is inserted into the
     * SHA-256 table, duplicates are rejected, password changes update the table,
     * and usersValidate() checks that each user maps back to itself. A miss is
     * therefore either a genuine miss or an invariant violation, so there is no
     * full-table fallback scan to hide a corrupted index. The exact plaintext
     * comparison in userPasswordMatches() is the authoritative collision-safe
     * check, so a hypothetical SHA-256 collision fails closed.
     */
    user_t *candidate = usersSHA256TableLookupLocked(users, sha256_key->bytes);
    if (candidate == NULL)
    {
        return NULL;
    }

    return userPasswordMatches(candidate, password) ? candidate : NULL;
}

bool usersRemoveUserLocked(users_t *users, user_t *user)
{
    size_t index;

    if (UNLIKELY(! usersIndexOfLocked(users, user, &index)))
    {
        return false;
    }

    user_t *victim = usersGetAtLocked(users, index);

    /*
     * Incremental removal: erase only the victim's own index entries (its fields
     * are still valid here), then swap the last active pointer into the freed
     * slot. No table is rebuilt on the success path. A false return means an
     * index resolved to a different user, i.e. it is already corrupt.
     */
    if (UNLIKELY(! usersEraseAllIndexEntriesLocked(users, victim)))
    {
        LOGF("Users: corrupted index during user removal");
        abortProgramNow(1);
    }

    size_t last = users->count - 1U;
    if (index != last)
    {
        user_t *moved       = users->items[last];
        users->items[index] = moved;
        /* Repoint the moved user at its new active index. This only rewrites an
         * existing entry's value, so it cannot allocate; a false return means the
         * moved user was missing from the pointer index, i.e. it is corrupt. */
        if (UNLIKELY(! usersPointerTableUpdateExistingLocked(users, moved, index)))
        {
            LOGF("Users: failed to update the pointer index after a swap-with-last removal");
            abortProgramNow(1);
        }
    }
    users->items[last] = NULL;
    users->count -= 1U;

    /*
     * The victim's stable storage slot is intentionally orphaned (not reused)
     * until usersClear()/usersDestroy(); slot_count stays monotonic.
     */
    userDestroy(victim);
    return true;
}

void usersClearLocked(users_t *users)
{
    for (size_t i = 0; i < users->count; ++i)
    {
        userDestroy(usersGetAtLocked(users, i));
        users->items[i] = NULL;
    }

    users->count      = 0;
    users->slot_count = 0;
    usersSHA224TableClear(users->sha224_table);
    usersSHA256TableClear(users->sha256_table);
    usersUUIDTableClear(users->uuid_table);
    usersWireGuardPublicKeyTableClear(users->wireguard_publickey_table);
    usersIDTableClear(users->id_table);
    usersNameTableClear(users->name_table);
    usersPointerTableClear(users->pointer_table);
    usersAllowedIpTableClear(users->allowed_ip_table);
}

void usersRollbackFeedLocked(users_t *users, size_t old_count, size_t old_slot_count)
{
    for (size_t i = old_count; i < users->count; ++i)
    {
        userDestroy(usersGetAtLocked(users, i));
        users->items[i] = NULL;
    }

    users->count      = old_count;
    users->slot_count = old_slot_count;

    if (UNLIKELY(! usersRebuildLookupTablesLocked(users)))
    {
        LOGF("Users: failed to rebuild lookup tables while rolling back a failed JSON load");
        abortProgramNow(1);
    }
}

void usersApplyNameHint(user_t *user, const char *name_hint)
{
    if (name_hint == NULL || name_hint[0] == '\0' || (user->name != NULL && user->name[0] != '\0'))
        return;
    char *name = stringDuplicate(name_hint);
    memoryFree(user->name);
    user->name = name;
}

static void usersLogNewUserRefusal(const user_t *user, users_add_result_t result)
{
    const char *reason;
    switch (result)
    {
    case kUsersAddResultDuplicateName:
        reason = "duplicate username";
        break;
    case kUsersAddResultDuplicateSHA224:
        reason = "duplicate SHA-224 lookup key";
        break;
    case kUsersAddResultDuplicateSHA256:
        reason = "duplicate SHA-256 lookup key";
        break;
    case kUsersAddResultDuplicateUUID:
        reason = "duplicate UUID credential";
        break;
    case kUsersAddResultDuplicateWireGuardPublicKey:
        reason = "duplicate WireGuard public key lookup key";
        break;
    case kUsersAddResultDuplicateWireGuardAllowedIps:
        reason = "overlapping WireGuard Allowed-IP range";
        break;
    case kUsersAddResultDuplicateId:
        reason = "duplicate durable id";
        break;
    default:
        reason = "invalid user or unavailable storage";
        break;
    }
    LOGE("Users: %s while loading user \"%s\"", reason, usersUserNameForLog(user));
}

bool usersAppendJsonUserLocked(users_t *users, const cJSON *user_json, const char *name_hint, bool required_ids)
{
    user_t *slot;

    if (UNLIKELY(! cJSON_IsObject(user_json)))
    {
        LOGE("Users: user entry must be a JSON object");
        return false;
    }
    if (required_ids)
    {
        const cJSON *id = cJSON_GetObjectItemCaseSensitive(user_json, "id");
        if (id == NULL)
            id = cJSON_GetObjectItemCaseSensitive(user_json, "user-id");
        uint64_t value = 0;
        if (id == NULL || cJSON_IsNull(id) ||
            (cJSON_IsString(id) && (id->valuestring == NULL || id->valuestring[0] == '\0')) ||
            ! getUint64FromJson(&value, id) || value == 0)
            return false;
    }
    if (UNLIKELY(! usersReserveLocked(users, users->count + 1U)))
    {
        return false;
    }

    slot = usersStorageAtLocked(users, users->slot_count);
    if (UNLIKELY(! userCreateFromJson(slot, user_json)))
    {
        LOGE("Users: failed to create user from JSON entry at index %zu", users->count);
        return false;
    }
    usersApplyNameHint(slot, name_hint);
    users_add_result_t result = usersValidateNewUserIndexesLocked(users, slot);
    if (result == kUsersAddResultOk && usersCommitNewUserLocked(users, slot, true))
        return true;
    usersLogNewUserRefusal(slot, result);
    userDestroy(slot);
    return false;
}

/*
 * Bound speculative storage before validating a container. Later entries grow
 * stable storage and indexes only as they are accepted; rollback restores counts.
 */
bool usersReserveForFeedLocked(users_t *users, const cJSON *container)
{
    int entry_count = cJSON_GetArraySize(container);
    if (entry_count <= 0)
    {
        return true;
    }

    size_t total = users->count + min((size_t) entry_count, (size_t) kUsersBlockSize);
    if (UNLIKELY(total < users->count))
    {
        LOGE("Users: JSON feed size overflow");
        return false;
    }

    return usersReserveLocked(users, total) && usersEnsureLookupCapacityLocked(users, total);
}

bool usersFeedJsonArrayLocked(users_t *users, const cJSON *array, bool required_ids)
{
    const cJSON *entry = NULL;

    if (UNLIKELY(! usersReserveForFeedLocked(users, array)))
    {
        return false;
    }

    cJSON_ArrayForEach(entry, array)
    {
        if (UNLIKELY(! usersAppendJsonUserLocked(users, entry, NULL, required_ids)))
        {
            return false;
        }
    }

    return true;
}

bool usersFeedJsonObjectMapLocked(users_t *users, const cJSON *object, bool required_ids)
{
    const cJSON *entry = NULL;

    if (UNLIKELY(! usersReserveForFeedLocked(users, object)))
    {
        return false;
    }

    cJSON_ArrayForEach(entry, object)
    {
        if (UNLIKELY(! usersAppendJsonUserLocked(users, entry, entry->string, required_ids)))
        {
            return false;
        }
    }

    return true;
}

bool usersJsonObjectLooksLikeSingleUser(const cJSON *json)
{
    return cJSON_IsString(cJSON_GetObjectItemCaseSensitive(json, "password")) ||
           cJSON_IsString(cJSON_GetObjectItemCaseSensitive(json, "pass"));
}

/*
 * Accepted layouts:
 * - null, an empty array, or an empty object: no-op success.
 * - [user, ...]
 * - {"users": [user, ...]}
 * - {"name": user, ...}, where the object key is used as a username hint.
 * - A single user object when "password" or "pass" has a string value.
 */
bool usersFeedJsonLocked(users_t *users, const cJSON *json, bool required_ids)
{
    if (UNLIKELY(json == NULL || cJSON_IsNull(json)))
    {
        return true;
    }
    if (cJSON_IsArray(json))
    {
        return usersFeedJsonArrayLocked(users, json, required_ids);
    }
    if (UNLIKELY(! cJSON_IsObject(json)))
    {
        LOGE("Users: JSON input must be an object, array, or null");
        return false;
    }
    if (json->child == NULL)
    {
        return true;
    }

    const cJSON *users_array = cJSON_GetObjectItemCaseSensitive(json, "users");
    if (users_array != NULL)
    {
        if (UNLIKELY(cJSON_IsNull(users_array)))
        {
            return true;
        }
        if (UNLIKELY(! cJSON_IsArray(users_array)))
        {
            LOGE("Users: JSON field \"users\" must be an array");
            return false;
        }
        return usersFeedJsonArrayLocked(users, users_array, required_ids);
    }
    if (usersJsonObjectLooksLikeSingleUser(json))
    {
        return usersAppendJsonUserLocked(users, json, NULL, required_ids);
    }

    return usersFeedJsonObjectMapLocked(users, json, required_ids);
}

bool usersValidateUserLookupKeysLocked(const users_t *users, bool credentials)
{
    for (size_t i = 0; i < users->count; ++i)
    {
        const user_t *a = usersGetAtLocked(users, i);
        if (UNLIKELY(! a->sha224_pass_valid))
        {
            LOGE("Users: user \"%s\" has no SHA-224 lookup key", usersUserNameForLog(a));
            return false;
        }
        if (UNLIKELY(! a->sha256_pass_valid))
        {
            LOGE("Users: user \"%s\" has no SHA-256 lookup key", usersUserNameForLog(a));
            return false;
        }
        if (UNLIKELY(! a->wireguard_publickey_valid))
        {
            LOGE("Users: user \"%s\" has no WireGuard public key lookup key", usersUserNameForLog(a));
            return false;
        }
        if (UNLIKELY(credentials && ! userPasswordDataValid((user_t *) a)))
        {
            LOGE("Users: user \"%s\" has inconsistent password lookup data", usersUserNameForLog(a));
            return false;
        }
        if (UNLIKELY(a->wireguard_allowed_ips_valid &&
                     (a->wireguard_allowed_ips == NULL || a->wireguard_allowed_ips[0] == '\0' ||
                      (a->wireguard_allowed_ip_family != 4U && a->wireguard_allowed_ip_family != 6U) ||
                      a->wireguard_allowed_ip_count == 0U ||
                      ! usersWireGuardAllowedIpContainsUser(a, &a->wireguard_allowed_ip))))
        {
            LOGE("Users: user \"%s\" has inconsistent WireGuard allowed IPs data", usersUserNameForLog(a));
            return false;
        }
        if (UNLIKELY(! a->wireguard_allowed_ips_valid && a->wireguard_allowed_ips != NULL &&
                     a->wireguard_allowed_ips[0] != '\0'))
        {
            LOGE("Users: user \"%s\" has WireGuard allowed IPs text without parsed data", usersUserNameForLog(a));
            return false;
        }
        if (UNLIKELY(usersSHA224TableLookupLocked(users, a->sha224_pass.bytes) != a))
        {
            LOGE("Users: SHA-224 lookup table does not point back to user \"%s\"", usersUserNameForLog(a));
            return false;
        }
        if (UNLIKELY(usersSHA256TableLookupLocked(users, a->sha256_pass.bytes) != a))
        {
            LOGE("Users: SHA-256 lookup table does not point back to user \"%s\"", usersUserNameForLog(a));
            return false;
        }
        if (UNLIKELY(a->uuid_pass_valid && usersUUIDTableLookupLocked(users, a->uuid_pass) != a))
        {
            LOGE("Users: UUID lookup table does not point back to user \"%s\"", usersUserNameForLog(a));
            return false;
        }
        if (UNLIKELY(usersWireGuardPublicKeyTableLookupLocked(users, a->wireguard_publickey) != a))
        {
            LOGE("Users: WireGuard public key lookup table does not point back to user \"%s\"", usersUserNameForLog(a));
            return false;
        }
        if (UNLIKELY(a->id != 0 && usersIDTableLookupLocked(users, a->id) != a))
        {
            LOGE("Users: id lookup table does not point back to user \"%s\"", usersUserNameForLog(a));
            return false;
        }
        if (UNLIKELY(a->name != NULL && a->name[0] != '\0' && usersNameTableLookupLocked(users, a->name) != a))
        {
            LOGE("Users: name lookup table does not point back to user \"%s\"", usersUserNameForLog(a));
            return false;
        }
        size_t pointer_index = 0;
        if (UNLIKELY(! usersPointerTableLookupLocked(users, a, &pointer_index) || pointer_index != i))
        {
            LOGE("Users: pointer lookup table does not resolve user \"%s\" to its active index",
                 usersUserNameForLog(a));
            return false;
        }
        if (a->wireguard_allowed_ips_valid)
        {
            users_allowed_ip_key_t   range_key;
            users_allowed_ip_value_t range_value;
            if (UNLIKELY(! usersAllowedIpEntryFromUser(a, &range_key, &range_value) || users->allowed_ip_table == NULL))
            {
                LOGE("Users: user \"%s\" has an unindexable Allowed-IP range", usersUserNameForLog(a));
                return false;
            }
            users_allowed_ip_map_t_iter it = users_allowed_ip_map_t_find(&users->allowed_ip_table->map, range_key);
            if (UNLIKELY(it.ref == NULL || it.ref->second.user != a))
            {
                LOGE("Users: Allowed-IP lookup table does not point back to user \"%s\"", usersUserNameForLog(a));
                return false;
            }
            /*
             * Overlap detection (not just exact-key duplication): two distinct
             * ranges that nest have different end keys, so the size check below
             * cannot see them. Query the ordered index for any other user whose
             * range overlaps this one, in O(log M).
             */
            const user_t *overlap = usersAllowedIpTableFindOverlapLocked(
                users, a->wireguard_allowed_ip_family, range_value.start, range_key.end, a);
            if (UNLIKELY(overlap != NULL))
            {
                LOGE("Users: overlapping WireGuard allowed IPs \"%s\" and \"%s\" between users \"%s\" and \"%s\"",
                     a->wireguard_allowed_ips,
                     overlap->wireguard_allowed_ips,
                     usersUserNameForLog(a),
                     usersUserNameForLog(overlap));
                return false;
            }
        }
    }

    /*
     * With every user proven above to map back to itself in each of its indexes,
     * comparing table sizes to the expected populations rules out duplicates
     * without any pairwise user comparison: two users sharing a key would leave
     * the map one entry short of the number of users requiring that key. This
     * turns full validation from O(N^2) into O(N) (plus O(N log M) for the
     * Allowed-IP overlap probes above).
     */
    size_t named_count  = 0;
    size_t ranged_count = 0;
    size_t uuid_count   = 0;
    size_t id_count     = 0;
    for (size_t i = 0; i < users->count; ++i)
    {
        const user_t *a = usersGetAtLocked(users, i);
        if (a->name != NULL && a->name[0] != '\0')
        {
            named_count += 1U;
        }
        if (a->wireguard_allowed_ips_valid)
        {
            ranged_count += 1U;
        }
        if (a->uuid_pass_valid)
        {
            uuid_count += 1U;
        }
        if (a->id != 0)
        {
            id_count += 1U;
        }
    }
    if (UNLIKELY(users->sha224_table == NULL ||
                 (size_t) users_sha224_map_t_size(&users->sha224_table->map) != users->count))
    {
        LOGE("Users: SHA-224 lookup table size does not match the active user count");
        return false;
    }
    if (UNLIKELY(users->sha256_table == NULL ||
                 (size_t) users_sha256_map_t_size(&users->sha256_table->map) != users->count))
    {
        LOGE("Users: SHA-256 lookup table size does not match the active user count");
        return false;
    }
    if (UNLIKELY(users->wireguard_publickey_table == NULL ||
                 (size_t) users_wireguard_publickey_map_t_size(&users->wireguard_publickey_table->map) != users->count))
    {
        LOGE("Users: WireGuard public key lookup table size does not match the active user count");
        return false;
    }
    if (UNLIKELY(users->pointer_table == NULL ||
                 (size_t) users_pointer_map_t_size(&users->pointer_table->map) != users->count))
    {
        LOGE("Users: pointer lookup table size does not match the active user count");
        return false;
    }
    if (UNLIKELY(users->uuid_table == NULL || (size_t) users_uuid_map_t_size(&users->uuid_table->map) != uuid_count))
    {
        LOGE("Users: UUID lookup table size does not match the number of UUID users");
        return false;
    }
    if (UNLIKELY(users->id_table == NULL || (size_t) users_id_map_t_size(&users->id_table->map) != id_count))
    {
        LOGE("Users: id lookup table size does not match the number of identified users");
        return false;
    }
    /*
     * Check the name and Allowed-IP table sizes unconditionally, including the
     * zero case: a stale final entry left behind by a botched erase would make
     * the size exceed the expected count, and gating on a nonzero expected count
     * would let that corruption pass. A borrowed name key that outlives its user
     * is especially dangerous, so it must be caught here.
     */
    if (UNLIKELY(users->name_table == NULL || (size_t) users_name_map_t_size(&users->name_table->map) != named_count))
    {
        LOGE("Users: name lookup table size does not match the number of named users");
        return false;
    }
    if (UNLIKELY(users->allowed_ip_table == NULL ||
                 (size_t) users_allowed_ip_map_t_size(&users->allowed_ip_table->map) != ranged_count))
    {
        LOGE("Users: Allowed-IP lookup table size does not match the number of ranged users");
        return false;
    }

    return true;
}

bool usersCreate(users_t *users)
{
    if (UNLIKELY(users == NULL))
    {
        return false;
    }

    memoryZero(users, sizeof(*users));
    if (UNLIKELY(! rwlockTryInit(&users->lock)))
    {
        return false;
    }
    usersLookupTablesCreateIfNeededLocked(users);

    return true;
}

void usersDestroy(users_t *users)
{
    if (UNLIKELY(users == NULL))
    {
        return;
    }

    usersClearLocked(users);
    for (size_t i = 0; i < users->block_count; ++i)
    {
        memoryFreeAligned(users->blocks[i]);
    }

    memoryFreeAligned(users->blocks);
    memoryFreeAligned(users->items);
    usersLookupTablesDestroy(users);

    rwlockDestroy(&users->lock);
    memoryZero(users, sizeof(*users));
}

bool usersAddUser(users_t *users, const user_t *user)
{
    user_t *slot;
    user_t  user_copy;
    bool    result = false;

    if (UNLIKELY(users == NULL || user == NULL))
    {
        return false;
    }

    memoryZero(&user_copy, sizeof(user_copy));
    if (UNLIKELY(! userCopy(&user_copy, user)))
    {
        return false;
    }

    rwlockWriteLock(&users->lock);
    if (LIKELY(usersReserveLocked(users, users->count + 1U)))
    {
        slot = usersStorageAtLocked(users, users->slot_count);
        if (LIKELY(userCopy(slot, &user_copy)))
        {
            result = usersCommitNewUserLocked(users, slot, false);
            if (UNLIKELY(! result))
            {
                userDestroy(slot);
            }
        }
    }
    rwlockWriteUnlock(&users->lock);
    userDestroy(&user_copy);
    return result;
}

/* Only fresh JSON construction enters this path. Arbitrary checked-add
 * callers retain the complete credential consistency diagnostic above. */
static users_add_result_t usersAddFreshUser(users_t *users, user_t *user)
{
    rwlockWriteLock(&users->lock);
    users_add_result_t result = usersValidateNewUserIndexesLocked(users, user);
    if (result == kUsersAddResultOk)
    {
        if (users->count == SIZE_MAX || ! usersReserveLocked(users, users->count + 1U))
            result = kUsersAddResultStorageUnavailable;
        else
        {
            user_t *slot = usersStorageAtLocked(users, users->slot_count);
            if (! userMoveOwnedValue(slot, user))
                result = kUsersAddResultStorageUnavailable;
            else if (! usersCommitNewUserLocked(users, slot, true))
            {
                userDestroy(slot);
                result = kUsersAddResultStorageUnavailable;
            }
        }
    }
    rwlockWriteUnlock(&users->lock);
    return result;
}

bool usersAddUserFromJson(users_t *users, const cJSON *json)
{
    if (users == NULL || ! cJSON_IsObject(json))
        return false;
    user_t user = {0};
    if (! userCreateFromJson(&user, json))
        return false;
    users_add_result_t result = usersAddFreshUser(users, &user);
    if (result != kUsersAddResultOk)
        usersLogNewUserRefusal(&user, result);
    userDestroy(&user);
    return result == kUsersAddResultOk;
}

users_add_result_t usersAddUserFromJsonChecked(users_t *users, const cJSON *json)
{
    if (users == NULL)
        return kUsersAddResultInvalidArgument;
    if (! cJSON_IsObject(json))
        return kUsersAddResultInvalidJson;
    user_allowed_ip_preparation_t allowed;
    if (! userPrepareJsonAllowedIps(json, &allowed))
        return kUsersAddResultInvalidWireGuardAllowedIps;
    user_t user    = {0};
    bool   created = userCreateFromJsonPreparedAllowedIps(&user, json, &allowed);
    memoryFree(allowed.text);
    if (! created)
        return kUsersAddResultInvalidUser;
    users_add_result_t result = usersAddFreshUser(users, &user);
    userDestroy(&user);
    return result;
}

static bool usersFeedJsonPolicy(users_t *users, const cJSON *json, bool required_ids)
{
    size_t old_count;
    size_t old_slot_count;
    bool   result;

    if (UNLIKELY(users == NULL))
    {
        return false;
    }

    rwlockWriteLock(&users->lock);
    old_count      = users->count;
    old_slot_count = users->slot_count;

    result = usersFeedJsonLocked(users, json, required_ids);
    if (UNLIKELY(! result))
    {
        usersRollbackFeedLocked(users, old_count, old_slot_count);
    }

    rwlockWriteUnlock(&users->lock);
    return result;
}

bool usersClear(users_t *users)
{
    if (UNLIKELY(users == NULL))
    {
        return false;
    }

    rwlockWriteLock(&users->lock);
    usersClearLocked(users);
    rwlockWriteUnlock(&users->lock);
    return true;
}

cJSON *usersToJson(const users_t *users)
{
    cJSON   *root  = NULL;
    cJSON   *array = NULL;
    users_t *self  = (users_t *) users;

    if (UNLIKELY(users == NULL))
    {
        return NULL;
    }

    root = cJSON_CreateObject();
    if (UNLIKELY(root == NULL))
    {
        return NULL;
    }
    array = cJSON_CreateArray();
    if (UNLIKELY(array == NULL))
    {
        cJSON_Delete(root);
        return NULL;
    }
    if (UNLIKELY(! cJSON_AddItemToObject(root, "users", array)))
    {
        cJSON_Delete(array);
        cJSON_Delete(root);
        return NULL;
    }

    rwlockReadLock(&self->lock);
    for (size_t i = 0; i < users->count; ++i)
    {
        cJSON *user_json = userToJson(usersGetAtLocked(users, i));
        if (UNLIKELY(user_json == NULL))
        {
            rwlockReadUnlock(&self->lock);
            cJSON_Delete(root);
            return NULL;
        }
        if (UNLIKELY(! cJSON_AddItemToArray(array, user_json)))
        {
            rwlockReadUnlock(&self->lock);
            cJSON_Delete(user_json);
            cJSON_Delete(root);
            return NULL;
        }
    }
    rwlockReadUnlock(&self->lock);

    return root;
}

user_t *usersLookupBySHA224(users_t *users, const uint8_t sha224[SHA224_DIGEST_SIZE])
{
    user_t *result;

    if (UNLIKELY(users == NULL || sha224 == NULL))
    {
        return NULL;
    }

    rwlockReadLock(&users->lock);
    result = usersSHA224TableLookupLocked(users, sha224);
    rwlockReadUnlock(&users->lock);
    return result;
}

const user_t *usersLookupBySHA224Const(const users_t *users, const uint8_t sha224[SHA224_DIGEST_SIZE])
{
    return usersLookupBySHA224((users_t *) users, sha224);
}

user_t *usersLookupBySHA256(users_t *users, const uint8_t sha256[SHA256_DIGEST_SIZE])
{
    user_t *result;

    if (UNLIKELY(users == NULL || sha256 == NULL))
    {
        return NULL;
    }

    rwlockReadLock(&users->lock);
    result = usersSHA256TableLookupLocked(users, sha256);
    rwlockReadUnlock(&users->lock);
    return result;
}

const user_t *usersLookupBySHA256Const(const users_t *users, const uint8_t sha256[SHA256_DIGEST_SIZE])
{
    return usersLookupBySHA256((users_t *) users, sha256);
}

user_t *usersLookupByUUID(users_t *users, const uint8_t uuid[kWwUuidBytesLen])
{
    user_t *result;

    if (UNLIKELY(users == NULL || uuid == NULL))
    {
        return NULL;
    }

    rwlockReadLock(&users->lock);
    result = usersUUIDTableLookupLocked(users, uuid);
    rwlockReadUnlock(&users->lock);
    return result;
}

const user_t *usersLookupByUUIDConst(const users_t *users, const uint8_t uuid[kWwUuidBytesLen])
{
    return usersLookupByUUID((users_t *) users, uuid);
}

user_t *usersLookupByWireGuardPublicKey(users_t *users, const uint8_t publickey[USER_WIREGUARD_PUBLICKEY_SIZE])
{
    user_t *result;

    if (UNLIKELY(users == NULL || publickey == NULL))
    {
        return NULL;
    }

    rwlockReadLock(&users->lock);
    result = usersWireGuardPublicKeyTableLookupLocked(users, publickey);
    rwlockReadUnlock(&users->lock);
    return result;
}

const user_t *usersLookupByWireGuardPublicKeyConst(const users_t *users,
                                                   const uint8_t  publickey[USER_WIREGUARD_PUBLICKEY_SIZE])
{
    return usersLookupByWireGuardPublicKey((users_t *) users, publickey);
}

user_t *usersLookupByWireGuardAllowedIp(users_t *users, const ip_addr_t *ip)
{
    user_t *result = NULL;

    if (UNLIKELY(users == NULL || ip == NULL))
    {
        return NULL;
    }

    uint8_t family = 0;
    uint8_t addr16[16];
    if (ip->type == IPADDR_TYPE_V4)
    {
        family = 4U;
    }
    else if (ip->type == IPADDR_TYPE_V6)
    {
        family = 6U;
    }
    else
    {
        return NULL;
    }
    if (UNLIKELY(! usersAllowedIpExtractBytes(ip, family, addr16)))
    {
        return NULL;
    }

    rwlockReadLock(&users->lock);
    result = usersAllowedIpTableFindContainingLocked(users, family, addr16);
    rwlockReadUnlock(&users->lock);
    return result;
}

const user_t *usersLookupByWireGuardAllowedIpConst(const users_t *users, const ip_addr_t *ip)
{
    return usersLookupByWireGuardAllowedIp((users_t *) users, ip);
}

user_t *usersLookupByIdentifier(users_t *users, uint64_t id)
{
    user_t *result;

    if (UNLIKELY(users == NULL || id == 0))
    {
        return NULL;
    }

    rwlockReadLock(&users->lock);
    result = usersIDTableLookupLocked(users, id);
    rwlockReadUnlock(&users->lock);
    return result;
}

const user_t *usersLookupByIdentifierConst(const users_t *users, uint64_t id)
{
    return usersLookupByIdentifier((users_t *) users, id);
}

cJSON *usersUserToJsonBySHA224(const users_t *users, const uint8_t sha224[SHA224_DIGEST_SIZE])
{
    users_t *self = (users_t *) users;
    user_t  *user = NULL;
    cJSON   *json = NULL;

    if (UNLIKELY(users == NULL || sha224 == NULL))
    {
        return NULL;
    }

    rwlockReadLock(&self->lock);
    user = usersSHA224TableLookupLocked(self, sha224);
    if (LIKELY(user != NULL))
    {
        json = userToJson(user);
    }
    rwlockReadUnlock(&self->lock);
    return json;
}

cJSON *usersUserToJsonBySHA256(const users_t *users, const uint8_t sha256[SHA256_DIGEST_SIZE])
{
    users_t *self = (users_t *) users;
    user_t  *user = NULL;
    cJSON   *json = NULL;

    if (UNLIKELY(users == NULL || sha256 == NULL))
    {
        return NULL;
    }

    rwlockReadLock(&self->lock);
    user = usersSHA256TableLookupLocked(self, sha256);
    if (LIKELY(user != NULL))
    {
        json = userToJson(user);
    }
    rwlockReadUnlock(&self->lock);
    return json;
}

cJSON *usersUserToJsonByIdentifier(const users_t *users, uint64_t id)
{
    users_t *self = (users_t *) users;
    user_t  *user = NULL;
    cJSON   *json = NULL;

    if (UNLIKELY(users == NULL || id == 0))
    {
        return NULL;
    }

    rwlockReadLock(&self->lock);
    user = usersIDTableLookupLocked(self, id);
    if (LIKELY(user != NULL))
    {
        json = userToJson(user);
    }
    rwlockReadUnlock(&self->lock);
    return json;
}

cJSON *usersUserToJsonByPassword(const users_t *users, const char *password)
{
    sha256_hash_t sha256_key;
    users_t      *self = (users_t *) users;
    user_t       *user = NULL;
    cJSON        *json = NULL;

    if (UNLIKELY(users == NULL || password == NULL))
    {
        return NULL;
    }

    if (UNLIKELY(! usersPasswordLookupKeyCreate(&sha256_key, password)))
    {
        return NULL;
    }

    /*
     * Keep the table read lock held across serialization so a concurrent removal
     * cannot invalidate the selected user pointer between lookup and conversion.
     */
    rwlockReadLock(&self->lock);
    user = usersLookupByPasswordLocked(self, &sha256_key, password);
    if (LIKELY(user != NULL))
    {
        json = userToJson(user);
    }
    rwlockReadUnlock(&self->lock);

    memorySecureZero(&sha256_key, sizeof(sha256_key));
    return json;
}

user_t *usersLookupByPassword(users_t *users, const char *password)
{
    sha256_hash_t sha256_key;
    user_t       *result;

    if (UNLIKELY(users == NULL || password == NULL))
    {
        return NULL;
    }

    if (UNLIKELY(! usersPasswordLookupKeyCreate(&sha256_key, password)))
    {
        return NULL;
    }

    rwlockReadLock(&users->lock);
    result = usersLookupByPasswordLocked(users, &sha256_key, password);
    rwlockReadUnlock(&users->lock);

    memorySecureZero(&sha256_key, sizeof(sha256_key));
    return result;
}

const user_t *usersLookupByPasswordConst(const users_t *users, const char *password)
{
    return usersLookupByPassword((users_t *) users, password);
}

bool usersRemoveUser(users_t *users, user_t *user)
{
    bool result;

    if (UNLIKELY(users == NULL || user == NULL))
    {
        return false;
    }

    rwlockWriteLock(&users->lock);
    result = usersRemoveUserLocked(users, user);
    rwlockWriteUnlock(&users->lock);
    return result;
}

bool usersRemoveUserBySHA256(users_t *users, const uint8_t sha256[SHA256_DIGEST_SIZE])
{
    user_t *user;
    bool    result = false;

    if (UNLIKELY(users == NULL || sha256 == NULL))
    {
        return false;
    }

    rwlockWriteLock(&users->lock);
    user = usersSHA256TableLookupLocked(users, sha256);
    if (LIKELY(user != NULL))
    {
        result = usersRemoveUserLocked(users, user);
    }
    rwlockWriteUnlock(&users->lock);
    return result;
}

bool usersRemoveUserByIdentifier(users_t *users, uint64_t id)
{
    user_t *user;
    bool    result = false;

    if (UNLIKELY(users == NULL || id == 0))
    {
        return false;
    }

    rwlockWriteLock(&users->lock);
    user = usersIDTableLookupLocked(users, id);
    if (LIKELY(user != NULL))
    {
        result = usersRemoveUserLocked(users, user);
    }
    rwlockWriteUnlock(&users->lock);
    return result;
}

bool usersChangePassword(users_t *users, user_t *user, const char *password)
{
    users_update_result_t result;

    if (UNLIKELY(users == NULL || user == NULL))
    {
        return false;
    }

    rwlockWriteLock(&users->lock);
    result = usersChangePasswordLocked(users, user, password);
    rwlockWriteUnlock(&users->lock);
    return result == kUsersUpdateResultOk;
}

size_t usersCount(const users_t *users)
{
    size_t result;

    if (UNLIKELY(users == NULL))
    {
        return 0;
    }

    rwlockReadLock(&((users_t *) users)->lock);
    result = users->count;
    rwlockReadUnlock(&((users_t *) users)->lock);
    return result;
}

bool usersIsEmpty(const users_t *users)
{
    return usersCount(users) == 0;
}

bool usersReserve(users_t *users, size_t capacity)
{
    bool result;

    if (UNLIKELY(users == NULL))
    {
        return false;
    }

    rwlockWriteLock(&users->lock);
    result = usersReserveLocked(users, capacity);
    rwlockWriteUnlock(&users->lock);
    return result;
}

user_t *usersGetAt(users_t *users, size_t index)
{
    user_t *result = NULL;

    if (UNLIKELY(users == NULL))
    {
        return NULL;
    }

    rwlockReadLock(&users->lock);
    if (LIKELY(index < users->count))
    {
        result = usersGetAtLocked(users, index);
    }
    rwlockReadUnlock(&users->lock);
    return result;
}

const user_t *usersGetAtConst(const users_t *users, size_t index)
{
    return usersGetAt((users_t *) users, index);
}

bool usersContainsUser(const users_t *users, const user_t *user)
{
    bool result;

    if (UNLIKELY(users == NULL))
    {
        return false;
    }

    rwlockReadLock(&((users_t *) users)->lock);
    result = usersIndexOfLocked(users, user, NULL);
    rwlockReadUnlock(&((users_t *) users)->lock);
    return result;
}

bool usersRebuildLookups(users_t *users)
{
    bool result;

    if (UNLIKELY(users == NULL))
    {
        return false;
    }

    rwlockWriteLock(&users->lock);
    result = usersRebuildLookupTablesLocked(users);
    rwlockWriteUnlock(&users->lock);
    return result;
}

bool usersValidate(const users_t *users)
{
    bool     result;
    users_t *self = (users_t *) users;

    if (UNLIKELY(users == NULL))
    {
        return false;
    }

    rwlockReadLock(&self->lock);
    result = usersValidateUserLookupKeysLocked(users, true);
    rwlockReadUnlock(&self->lock);
    return result;
}

/*
 * Moves every data and index field between two tables, deliberately excluding
 * the wrwlock_t lock in each (a lock must never be memcpy'd or swapped). Update
 * this whenever a new stored field or index is added.
 */
void usersSwapContentsLocked(users_t *a, users_t *b)
{
#define USERS_SWAP_PTR(field)                                                                                          \
    do                                                                                                                 \
    {                                                                                                                  \
        void *swap_tmp = a->field;                                                                                     \
        a->field       = b->field;                                                                                     \
        b->field       = swap_tmp;                                                                                     \
    } while (0)
#define USERS_SWAP_SIZE(field)                                                                                         \
    do                                                                                                                 \
    {                                                                                                                  \
        size_t swap_tmp = a->field;                                                                                    \
        a->field        = b->field;                                                                                    \
        b->field        = swap_tmp;                                                                                    \
    } while (0)

    USERS_SWAP_PTR(blocks);
    USERS_SWAP_PTR(items);
    USERS_SWAP_SIZE(count);
    USERS_SWAP_SIZE(capacity);
    USERS_SWAP_SIZE(slot_count);
    USERS_SWAP_SIZE(slot_capacity);
    USERS_SWAP_SIZE(block_count);
    USERS_SWAP_SIZE(block_capacity);
    usersLookupTablesSwapLocked(a, b);

#undef USERS_SWAP_SIZE
#undef USERS_SWAP_PTR
}

/*
 * Inserts an already-copied user into every index of a freshly built table and
 * appends it. No duplicate pre-scan and no credential rederivation: the source
 * table was already valid and userCopy() carried the derived material over. The
 * per-index insert helpers still fail closed on an unexpected duplicate.
 */
bool usersCommitCopiedUserLocked(users_t *dest, user_t *slot)
{
    if (UNLIKELY(! usersSHA224TableInsertLocked(dest, slot) || ! usersSHA256TableInsertLocked(dest, slot) ||
                 ! usersUUIDTableInsertLocked(dest, slot) || ! usersWireGuardPublicKeyTableInsertLocked(dest, slot) ||
                 ! usersIDTableInsertLocked(dest, slot) || ! usersNameTableInsertLocked(dest, slot) ||
                 ! usersPointerTableSetLocked(dest, slot, dest->count) ||
                 ! usersAllowedIpTableInsertLocked(dest, slot)))
    {
        return false;
    }

    dest->items[dest->count] = slot;
    dest->count += 1U;
    dest->slot_count += 1U;
    return true;
}

bool usersCopy(users_t *dest, const users_t *src)
{
    users_t  temp;
    users_t *src_mut = (users_t *) src;
    bool     ok      = true;

    if (UNLIKELY(dest == NULL || src == NULL))
    {
        return false;
    }
    if (dest == src)
    {
        return true;
    }

    /*
     * Build a complete copy in an isolated temporary table first, then swap it
     * into the destination under the destination lock. The source and
     * destination locks are never held at the same time, so no cross-copy
     * deadlock or address-ordered locking protocol is needed, and the
     * destination is untouched until the copy has fully succeeded.
     */
    if (UNLIKELY(! usersCreate(&temp)))
    {
        return false;
    }

    rwlockReadLock(&src_mut->lock);
    size_t src_count        = src->count;
    size_t src_ranged_count = 0;
    for (size_t i = 0; i < src_count; ++i)
    {
        if (usersGetAtLocked(src_mut, i)->wireguard_allowed_ips_valid)
        {
            src_ranged_count += 1U;
        }
    }
    if (UNLIKELY(! usersReserveLocked(&temp, src_count) || ! usersEnsureLookupCapacityLocked(&temp, src_count)))
    {
        ok = false;
    }
    if (ok && UNLIKELY(! usersAllowedIpTableEnsureCapacity(&temp, src_ranged_count)))
    {
        ok = false;
    }
    for (size_t i = 0; ok && i < src_count; ++i)
    {
        user_t *src_user = usersGetAtLocked(src_mut, i);
        user_t *slot     = usersStorageAtLocked(&temp, temp.slot_count);

        if (UNLIKELY(! userCopy(slot, src_user)))
        {
            ok = false;
            break;
        }
        if (UNLIKELY(! usersCommitCopiedUserLocked(&temp, slot)))
        {
            userDestroy(slot);
            ok = false;
            break;
        }
    }
    rwlockReadUnlock(&src_mut->lock);

#ifndef NDEBUG
    if (ok && UNLIKELY(! usersValidateUserLookupKeysLocked(&temp, false)))
    {
        LOGF("Users: internal copy produced an inconsistent table");
        ok = false;
    }
#endif

    if (UNLIKELY(! ok))
    {
        usersDestroy(&temp);
        return false;
    }

    rwlockWriteLock(&dest->lock);
    usersSwapContentsLocked(dest, &temp);
    rwlockWriteUnlock(&dest->lock);

    /* temp now owns the destination's previous contents; destroy frees them. */
    usersDestroy(&temp);
    return true;
}

/*
 * Intentionally an O(N) scan. Effective expiry changes when first usage is
 * recorded or when a client-view expiry is projected, so a maintained expiry
 * heap would add work to the hot accounting/sync paths for a diagnostic query.
 * Add an index only if a production caller polls this frequently and a benchmark
 * shows the scan matters.
 */
user_t *usersFindFirstExpired(users_t *users, uint64_t now_ms)
{
    user_t *result = NULL;

    if (UNLIKELY(users == NULL))
    {
        return NULL;
    }

    rwlockReadLock(&users->lock);
    for (size_t i = 0; i < users->count; ++i)
    {
        user_t *user = usersGetAtLocked(users, i);
        if (userIsExpired(user, now_ms))
        {
            result = user;
            break;
        }
    }
    rwlockReadUnlock(&users->lock);
    return result;
}

const user_t *usersFindFirstExpiredConst(const users_t *users, uint64_t now_ms)
{
    return usersFindFirstExpired((users_t *) users, now_ms);
}

/*
 * Intentionally an O(N) scan. No AuthenticationClient/Server hot path polls this
 * today; a maintained "disabled" set would add work to configuration updates to
 * speed up an unused query. Add an index only when a real caller and a benchmark
 * justify it.
 */
user_t *usersFindFirstDisabled(users_t *users)
{
    user_t *result = NULL;

    if (UNLIKELY(users == NULL))
    {
        return NULL;
    }

    rwlockReadLock(&users->lock);
    for (size_t i = 0; i < users->count; ++i)
    {
        user_t *user = usersGetAtLocked(users, i);
        if (userIsDisabled(user))
        {
            result = user;
            break;
        }
    }
    rwlockReadUnlock(&users->lock);
    return result;
}

const user_t *usersFindFirstDisabledConst(const users_t *users)
{
    return usersFindFirstDisabled((users_t *) users);
}

/*
 * Intentionally an O(N) scan. Limit state depends on frequently changing traffic
 * statistics and runtime counters, so a maintained "limited" set would add
 * contention to traffic accounting, which is more performance-critical than this
 * diagnostic scan.
 */
user_t *usersFindFirstLimited(users_t *users)
{
    user_t *result = NULL;

    if (UNLIKELY(users == NULL))
    {
        return NULL;
    }

    rwlockReadLock(&users->lock);
    for (size_t i = 0; i < users->count; ++i)
    {
        user_t *user = usersGetAtLocked(users, i);
        if (userHasReachedLimit(user))
        {
            result = user;
            break;
        }
    }
    rwlockReadUnlock(&users->lock);
    return result;
}

const user_t *usersFindFirstLimitedConst(const users_t *users)
{
    return usersFindFirstLimited((users_t *) users);
}

bool usersFeedJson(users_t *users, const cJSON *json)
{
    return usersFeedJsonPolicy(users, json, false);
}

bool usersFeedJsonRequiredIds(users_t *users, const cJSON *json)
{
    return usersFeedJsonPolicy(users, json, true);
}

bool usersValidateStructure(const users_t *users)
{
    if (users == NULL)
        return false;
    rwlockReadLock(&((users_t *) users)->lock);
    bool valid = usersValidateUserLookupKeysLocked(users, false);
    rwlockReadUnlock(&((users_t *) users)->lock);
    return valid;
}

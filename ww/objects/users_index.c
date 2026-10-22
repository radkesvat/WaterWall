#include "users_internal.h"

/* Only the fixed-byte credential indexes share this typed implementation.
 * Name/ID/pointer/interval indexes retain their distinct ownership semantics. */
#define USERS_FIXED_FN(op)         usersSHA224Table##op
#define USERS_FIXED_FIELD          sha224_table
#define USERS_FIXED_TABLE          users_sha224_table_t
#define USERS_FIXED_MAP(op)        users_sha224_map_t##op
#define USERS_FIXED_KEY            users_sha224_key_t
#define USERS_FIXED_BYTES          SHA224_DIGEST_SIZE
#define USERS_FIXED_KEY_FROM_BYTES usersSHA224KeyFromBytes
#define USERS_FIXED_LABEL          "SHA-224"
#include "users_fixed_index.inc"

#define USERS_FIXED_FN(op)         usersSHA256Table##op
#define USERS_FIXED_FIELD          sha256_table
#define USERS_FIXED_TABLE          users_sha256_table_t
#define USERS_FIXED_MAP(op)        users_sha256_map_t##op
#define USERS_FIXED_KEY            users_sha256_key_t
#define USERS_FIXED_BYTES          SHA256_DIGEST_SIZE
#define USERS_FIXED_KEY_FROM_BYTES usersSHA256KeyFromBytes
#define USERS_FIXED_LABEL          "SHA-256"
#include "users_fixed_index.inc"

#define USERS_FIXED_FN(op)         usersUUIDTable##op
#define USERS_FIXED_FIELD          uuid_table
#define USERS_FIXED_TABLE          users_uuid_table_t
#define USERS_FIXED_MAP(op)        users_uuid_map_t##op
#define USERS_FIXED_KEY            users_uuid_key_t
#define USERS_FIXED_BYTES          kWwUuidBytesLen
#define USERS_FIXED_KEY_FROM_BYTES usersUUIDKeyFromBytes
#define USERS_FIXED_LABEL          "UUID"
#include "users_fixed_index.inc"

#define USERS_FIXED_FN(op)         usersWireGuardPublicKeyTable##op
#define USERS_FIXED_FIELD          wireguard_publickey_table
#define USERS_FIXED_TABLE          users_wireguard_publickey_table_t
#define USERS_FIXED_MAP(op)        users_wireguard_publickey_map_t##op
#define USERS_FIXED_KEY            users_wireguard_publickey_key_t
#define USERS_FIXED_BYTES          USER_WIREGUARD_PUBLICKEY_SIZE
#define USERS_FIXED_KEY_FROM_BYTES usersWireGuardPublicKeyFromBytes
#define USERS_FIXED_LABEL          "WireGuard public key"
#include "users_fixed_index.inc"

#define USERS_INSERT_RESERVED(table_field, map_type, key_value, mapped_value)                                          \
    do                                                                                                                 \
    {                                                                                                                  \
        map_type *map = &users->table_field->map;                                                                      \
        if (map->size >= map_type##_capacity(map))                                                                     \
        {                                                                                                              \
            LOGF("Users: missing reserved insertion capacity");                                                        \
            abortProgramNow(1);                                                                                        \
        }                                                                                                              \
        map_type##_key    key    = (key_value);                                                                        \
        map_type##_result result = map_type##_bucket_insert_(map, &key);                                               \
        if (! result.inserted)                                                                                         \
        {                                                                                                              \
            LOGF("Users: duplicate key during reserved insertion");                                                    \
            abortProgramNow(1);                                                                                        \
        }                                                                                                              \
        ++map->size;                                                                                                   \
        result.ref->first  = key;                                                                                      \
        result.ref->second = (mapped_value);                                                                           \
        memorySecureZero(&key, sizeof(key));                                                                           \
    } while (0)

users_sha224_key_t usersSHA224KeyFromBytes(const uint8_t bytes[SHA224_DIGEST_SIZE])
{
    users_sha224_key_t key = {0};

    memoryCopy(key.bytes, bytes, SHA224_DIGEST_SIZE);
    return key;
}

users_sha256_key_t usersSHA256KeyFromBytes(const uint8_t bytes[SHA256_DIGEST_SIZE])
{
    users_sha256_key_t key = {0};

    memoryCopy(key.bytes, bytes, SHA256_DIGEST_SIZE);
    return key;
}

bool usersIDTableReserve(users_id_table_t *table, size_t count)
{
    size_t capacity = count < kUsersInitialTableCapacity ? kUsersInitialTableCapacity : count;

    if (UNLIKELY(! userIndexHashCapacityIsRepresentable(capacity, sizeof(*table->map.table), sizeof(*table->map.meta))))
    {
        LOGE("Users: id lookup table capacity overflow");
        return false;
    }
    discard users_id_map_t_reserve(&table->map, (isize) capacity);

    return true;
}

void usersIDTableCreateIfNeeded(users_t *users)
{
    if (users->id_table != NULL)
        return;
    users_id_table_t *table = memoryAllocateZero(sizeof(*table));
    discard           users_id_map_t_reserve(&table->map, kUsersInitialTableCapacity);
    users->id_table = table;
}

bool usersIDTableEnsureCapacity(users_t *users, size_t count)
{
    usersIDTableCreateIfNeeded(users);
    return usersIDTableReserve(users->id_table, count);
}

void usersIDTableClear(users_id_table_t *table)
{
    if (UNLIKELY(table == NULL))
    {
        return;
    }

    users_id_map_t_clear(&table->map);
}

void usersIDTableDestroy(users_id_table_t *table)
{
    if (UNLIKELY(table == NULL))
    {
        return;
    }

    users_id_map_t_drop(&table->map);
    memoryFree(table);
}

user_t *usersIDTableLookupLocked(const users_t *users, uint64_t id)
{
    users_id_table_t *table = users->id_table;

    if (UNLIKELY(table == NULL || id == 0))
    {
        return NULL;
    }

    users_id_map_t_iter it = users_id_map_t_find(&table->map, id);
    return it.ref != NULL ? it.ref->second : NULL;
}

/*
 * Capacity-free credential inserts. These never reserve, so a caller that has
 * already reserved headroom (see usersEnsureLookupCapacityLocked) can run them
 * after an irreversible mutation without growing their storage. Duplicate-key
 * and invalid-credential checks remain part of the transactional commit.
 */
bool usersSHA224TableInsertEntryLocked(users_t *users, user_t *user)
{
    users_sha224_key_t        key;
    users_sha224_map_t_result result;

    if (UNLIKELY(! user->sha224_pass_valid))
    {
        LOGE("Users: user \"%s\" does not have a usable SHA-224 password hash", usersUserNameForLog(user));
        return false;
    }

    key    = usersSHA224KeyFromBytes(user->sha224_pass.bytes);
    result = users_sha224_map_t_insert(&users->sha224_table->map, key, user);
    if (UNLIKELY(! result.inserted && result.ref->second != user))
    {
        LOGE("Users: duplicate SHA-224 lookup key between users \"%s\" and \"%s\"",
             usersUserNameForLog(result.ref->second),
             usersUserNameForLog(user));
        return false;
    }

    return true;
}

bool usersSHA224TableInsertLocked(users_t *users, user_t *user)
{
    if (UNLIKELY(! usersSHA224TableEnsureCapacity(users, users->count + 1U)))
    {
        return false;
    }
    return usersSHA224TableInsertEntryLocked(users, user);
}

bool usersSHA256TableInsertEntryLocked(users_t *users, user_t *user)
{
    users_sha256_key_t        key;
    users_sha256_map_t_result result;

    if (UNLIKELY(! user->sha256_pass_valid))
    {
        LOGE("Users: user \"%s\" does not have a usable SHA-256 password hash", usersUserNameForLog(user));
        return false;
    }

    key    = usersSHA256KeyFromBytes(user->sha256_pass.bytes);
    result = users_sha256_map_t_insert(&users->sha256_table->map, key, user);
    if (UNLIKELY(! result.inserted && result.ref->second != user))
    {
        LOGE("Users: duplicate SHA-256 lookup key between users \"%s\" and \"%s\"",
             usersUserNameForLog(result.ref->second),
             usersUserNameForLog(user));
        return false;
    }

    return true;
}

bool usersSHA256TableInsertLocked(users_t *users, user_t *user)
{
    if (UNLIKELY(! usersSHA256TableEnsureCapacity(users, users->count + 1U)))
    {
        return false;
    }
    return usersSHA256TableInsertEntryLocked(users, user);
}

bool usersUUIDTableInsertEntryLocked(users_t *users, user_t *user)
{
    users_uuid_key_t        key;
    users_uuid_map_t_result result;

    if (! user->uuid_pass_valid)
    {
        return true;
    }

    key    = usersUUIDKeyFromBytes(user->uuid_pass);
    result = users_uuid_map_t_insert(&users->uuid_table->map, key, user);
    if (UNLIKELY(! result.inserted && result.ref->second != user))
    {
        LOGE("Users: duplicate UUID credential between users \"%s\" and \"%s\"",
             usersUserNameForLog(result.ref->second),
             usersUserNameForLog(user));
        return false;
    }

    return true;
}

bool usersUUIDTableInsertLocked(users_t *users, user_t *user)
{
    if (! user->uuid_pass_valid)
    {
        return true;
    }
    if (UNLIKELY(! usersUUIDTableEnsureCapacity(users, users->count + 1U)))
    {
        return false;
    }
    return usersUUIDTableInsertEntryLocked(users, user);
}

bool usersWireGuardPublicKeyTableInsertEntryLocked(users_t *users, user_t *user)
{
    users_wireguard_publickey_key_t        key;
    users_wireguard_publickey_map_t_result result;

    if (UNLIKELY(! user->wireguard_publickey_valid))
    {
        LOGE("Users: user \"%s\" does not have a usable WireGuard public key", usersUserNameForLog(user));
        return false;
    }

    key    = usersWireGuardPublicKeyFromBytes(user->wireguard_publickey);
    result = users_wireguard_publickey_map_t_insert(&users->wireguard_publickey_table->map, key, user);
    if (UNLIKELY(! result.inserted && result.ref->second != user))
    {
        LOGE("Users: duplicate WireGuard public key between users \"%s\" and \"%s\"",
             usersUserNameForLog(result.ref->second),
             usersUserNameForLog(user));
        return false;
    }

    return true;
}

bool usersWireGuardPublicKeyTableInsertLocked(users_t *users, user_t *user)
{
    if (UNLIKELY(! user->wireguard_publickey_valid))
    {
        LOGE("Users: user \"%s\" does not have a usable WireGuard public key", usersUserNameForLog(user));
        return false;
    }
    if (UNLIKELY(! usersWireGuardPublicKeyTableEnsureCapacity(users, users->count + 1U)))
    {
        return false;
    }
    return usersWireGuardPublicKeyTableInsertEntryLocked(users, user);
}

bool usersIDTableInsertLocked(users_t *users, user_t *user)
{
    users_id_map_t_result result;
    uint64_t              id = user->id;

    if (id == 0)
    {
        return true;
    }
    if (UNLIKELY(! usersIDTableEnsureCapacity(users, users->count + 1U)))
    {
        return false;
    }

    result = users_id_map_t_insert(&users->id_table->map, id, user);
    if (UNLIKELY(! result.inserted && result.ref->second != user))
    {
        LOGE("Users: duplicate id %" PRIu64 " between users \"%s\" and \"%s\"",
             id,
             usersUserNameForLog(result.ref->second),
             usersUserNameForLog(user));
        return false;
    }

    return true;
}

/*
 * Exact-erase helpers. Each takes the key bytes explicitly so a caller can erase
 * a user's OLD credential entry (captured before a password change) or its live
 * entry (during removal). Each confirms the entry maps to the expected user
 * before erasing; refusing to erase another user's entry surfaces an invariant
 * violation instead of silently corrupting a second user's index.
 */
bool usersIDTableEraseLocked(users_t *users, const user_t *user, uint64_t id)
{
    if (id == 0)
    {
        return true;
    }
    if (users->id_table == NULL)
    {
        LOGE("Users: id entry to erase has no lookup table (corrupted index)");
        return false;
    }
    users_id_map_t_iter it = users_id_map_t_find(&users->id_table->map, id);
    if (UNLIKELY(it.ref == NULL))
    {
        /* A nonzero id is always indexed, so a miss here is a corrupted index;
         * fail closed so the caller can recover. */
        LOGE("Users: id entry to erase is missing (corrupted index)");
        return false;
    }
    if (UNLIKELY(it.ref->second != user))
    {
        LOGE("Users: refusing to erase an id entry owned by a different user");
        return false;
    }
    users_id_map_t_erase_at(&users->id_table->map, it);
    return true;
}

bool usersNameTableReserve(users_name_table_t *table, size_t count)
{
    size_t capacity = count < kUsersInitialTableCapacity ? kUsersInitialTableCapacity : count;

    if (UNLIKELY(! userIndexHashCapacityIsRepresentable(capacity, sizeof(*table->map.table), sizeof(*table->map.meta))))
    {
        LOGE("Users: name lookup table capacity overflow");
        return false;
    }
    discard users_name_map_t_reserve(&table->map, (isize) capacity);

    return true;
}

void usersNameTableCreateIfNeeded(users_t *users)
{
    if (users->name_table != NULL)
        return;
    users_name_table_t *table = memoryAllocateZero(sizeof(*table));
    discard             users_name_map_t_reserve(&table->map, kUsersInitialTableCapacity);
    users->name_table = table;
}

bool usersNameTableEnsureCapacity(users_t *users, size_t count)
{
    usersNameTableCreateIfNeeded(users);
    return usersNameTableReserve(users->name_table, count);
}

void usersNameTableClear(users_name_table_t *table)
{
    if (UNLIKELY(table == NULL))
    {
        return;
    }

    users_name_map_t_clear(&table->map);
}

void usersNameTableDestroy(users_name_table_t *table)
{
    if (UNLIKELY(table == NULL))
    {
        return;
    }

    users_name_map_t_drop(&table->map);
    memoryFree(table);
}

user_t *usersNameTableLookupLocked(const users_t *users, const char *name)
{
    users_name_table_t *table = users->name_table;

    if (UNLIKELY(table == NULL || name == NULL || name[0] == '\0'))
    {
        return NULL;
    }

    users_name_key_t      key = {.name = name};
    users_name_map_t_iter it  = users_name_map_t_find(&table->map, key);
    return it.ref != NULL ? it.ref->second : NULL;
}

/*
 * Inserts the user's non-empty name. Empty names are intentionally not indexed;
 * multiple unnamed users remain allowed. The stored key borrows user->name, so
 * the caller must not free or replace that string while the entry lives.
 */
bool usersNameTableInsertLocked(users_t *users, user_t *user)
{
    users_name_key_t        key;
    users_name_map_t_result result;

    if (user->name == NULL || user->name[0] == '\0')
    {
        return true;
    }
    if (UNLIKELY(! usersNameTableEnsureCapacity(users, users->count + 1U)))
    {
        return false;
    }

    key    = (users_name_key_t) {.name = user->name};
    result = users_name_map_t_insert(&users->name_table->map, key, user);
    if (UNLIKELY(! result.inserted && result.ref->second != user))
    {
        LOGE("Users: duplicate username \"%s\" between two users", user->name);
        return false;
    }

    return true;
}

/*
 * Erases the entry for `name` when it maps to `user`. `name` is passed
 * explicitly so the caller can erase the old string before it is replaced or
 * freed. Erasing an entry owned by a different user is an invariant violation.
 */
bool usersNameTableEraseLocked(users_t *users, const user_t *user, const char *name)
{
    users_name_table_t *table = users->name_table;

    if (name == NULL || name[0] == '\0')
    {
        return true;
    }
    if (table == NULL)
    {
        LOGE("Users: name to erase has no lookup table (corrupted index)");
        return false;
    }

    users_name_key_t      key = {.name = name};
    users_name_map_t_iter it  = users_name_map_t_find(&table->map, key);
    if (UNLIKELY(it.ref == NULL))
    {
        /* A non-empty name is always indexed, so a miss here is a corrupted index
         * (a borrowed name key that outlived its user); fail closed. */
        LOGE("Users: name to erase is missing (corrupted index)");
        return false;
    }
    if (UNLIKELY(it.ref->second != user))
    {
        LOGE("Users: refusing to erase name owned by a different user");
        return false;
    }

    users_name_map_t_erase_entry(&table->map, it.ref);
    return true;
}

/* Capacity and uniqueness are established before the commit point. This calls
 * STC's no-grow bucket primitive and updates only this insertion's occupancy. */
bool usersNameTableInsertReservedLocked(users_t *users, user_t *user)
{
    if (user->name == NULL || user->name[0] == '\0')
        return true;
    if (users->name_table == NULL || users->name_table->map.size >= users_name_map_t_capacity(&users->name_table->map))
    {
        LOGF("Users: missing reserved name insertion capacity");
        abortProgramNow(1);
    }
    users_name_map_t       *map    = &users->name_table->map;
    users_name_key_t        key    = {.name = user->name};
    users_name_map_t_result result = users_name_map_t_bucket_insert_(map, &key);
    if (! result.inserted)
        return result.ref->second == user;
    ++map->size;
    result.ref->first  = key;
    result.ref->second = user;
    return true;
}

bool usersPointerTableReserve(users_pointer_table_t *table, size_t count)
{
    size_t capacity = count < kUsersInitialTableCapacity ? kUsersInitialTableCapacity : count;

    if (UNLIKELY(! userIndexHashCapacityIsRepresentable(capacity, sizeof(*table->map.table), sizeof(*table->map.meta))))
    {
        LOGE("Users: pointer lookup table capacity overflow");
        return false;
    }
    discard users_pointer_map_t_reserve(&table->map, (isize) capacity);

    return true;
}

void usersPointerTableCreateIfNeeded(users_t *users)
{
    if (users->pointer_table != NULL)
        return;
    users_pointer_table_t *table = memoryAllocateZero(sizeof(*table));
    discard                users_pointer_map_t_reserve(&table->map, kUsersInitialTableCapacity);
    users->pointer_table = table;
}

bool usersPointerTableEnsureCapacity(users_t *users, size_t count)
{
    usersPointerTableCreateIfNeeded(users);
    return usersPointerTableReserve(users->pointer_table, count);
}

void usersPointerTableClear(users_pointer_table_t *table)
{
    if (UNLIKELY(table == NULL))
    {
        return;
    }

    users_pointer_map_t_clear(&table->map);
}

void usersPointerTableDestroy(users_pointer_table_t *table)
{
    if (UNLIKELY(table == NULL))
    {
        return;
    }

    users_pointer_map_t_drop(&table->map);
    memoryFree(table);
}

bool usersPointerTableLookupLocked(const users_t *users, const user_t *user, size_t *index_out)
{
    users_pointer_table_t *table = users->pointer_table;

    if (UNLIKELY(table == NULL || user == NULL))
    {
        return false;
    }

    users_pointer_map_t_iter it = users_pointer_map_t_find(&table->map, (uintptr_t) user);
    if (it.ref == NULL)
    {
        return false;
    }
    if (index_out != NULL)
    {
        *index_out = it.ref->second;
    }
    return true;
}

/* Records (or updates) the active items[] index for a stored user. */
bool usersPointerTableSetLocked(users_t *users, user_t *user, size_t index)
{
    if (UNLIKELY(! usersPointerTableEnsureCapacity(users, users->count + 1U)))
    {
        return false;
    }

    discard users_pointer_map_t_insert_or_assign(&users->pointer_table->map, (uintptr_t) user, index);

    return true;
}

/*
 * Repoints an already-indexed user at a new active items[] slot. It only rewrites
 * an existing entry's value, so unlike usersPointerTableSetLocked() it never
 * reserves and cannot allocate; the swap-with-last removal relies on this to stay
 * transactional after items[] has been mutated. A false return means the user was
 * not in the index, i.e. the pointer index is already corrupt.
 */
bool usersPointerTableUpdateExistingLocked(users_t *users, const user_t *user, size_t index)
{
    if (UNLIKELY(users->pointer_table == NULL || user == NULL))
    {
        return false;
    }

    users_pointer_map_t_iter it = users_pointer_map_t_find(&users->pointer_table->map, (uintptr_t) user);
    if (UNLIKELY(it.ref == NULL))
    {
        return false;
    }
    it.ref->second = index;
    return true;
}

void usersPointerTableEraseLocked(users_t *users, const user_t *user)
{
    if (UNLIKELY(users->pointer_table == NULL || user == NULL))
    {
        return;
    }

    users_pointer_map_t_erase(&users->pointer_table->map, (uintptr_t) user);
}

bool usersEnsureLookupCapacityLocked(users_t *users, size_t count)
{
    if (UNLIKELY(! usersSHA224TableEnsureCapacity(users, count)))
    {
        return false;
    }
    if (UNLIKELY(! usersSHA256TableEnsureCapacity(users, count)))
    {
        return false;
    }
    if (UNLIKELY(! usersUUIDTableEnsureCapacity(users, count)))
    {
        return false;
    }
    if (UNLIKELY(! usersWireGuardPublicKeyTableEnsureCapacity(users, count)))
    {
        return false;
    }
    if (UNLIKELY(! usersIDTableEnsureCapacity(users, count)))
    {
        return false;
    }
    if (UNLIKELY(! usersNameTableEnsureCapacity(users, count)))
    {
        return false;
    }
    if (UNLIKELY(! usersPointerTableEnsureCapacity(users, count)))
    {
        return false;
    }

    return true;
}

void usersLookupTablesCreateIfNeededLocked(users_t *users)
{
    usersSHA224TableCreateIfNeeded(users);
    usersSHA256TableCreateIfNeeded(users);
    usersUUIDTableCreateIfNeeded(users);
    usersWireGuardPublicKeyTableCreateIfNeeded(users);
    usersIDTableCreateIfNeeded(users);
    usersNameTableCreateIfNeeded(users);
    usersPointerTableCreateIfNeeded(users);
    usersAllowedIpTableCreateIfNeeded(users);
}

void usersLookupTablesDestroy(users_t *users)
{
    usersSHA224TableDestroy(users->sha224_table);
    usersSHA256TableDestroy(users->sha256_table);
    usersUUIDTableDestroy(users->uuid_table);
    usersWireGuardPublicKeyTableDestroy(users->wireguard_publickey_table);
    usersIDTableDestroy(users->id_table);
    usersNameTableDestroy(users->name_table);
    usersPointerTableDestroy(users->pointer_table);
    usersAllowedIpTableDestroy(users->allowed_ip_table);

    users->sha224_table              = NULL;
    users->sha256_table              = NULL;
    users->uuid_table                = NULL;
    users->wireguard_publickey_table = NULL;
    users->id_table                  = NULL;
    users->name_table                = NULL;
    users->pointer_table             = NULL;
    users->allowed_ip_table          = NULL;
}

void usersLookupTablesSwapLocked(users_t *a, users_t *b)
{
#define USERS_SWAP_TABLE_PTR(field)                                                                                    \
    do                                                                                                                 \
    {                                                                                                                  \
        void *swap_tmp = a->field;                                                                                     \
        a->field       = b->field;                                                                                     \
        b->field       = swap_tmp;                                                                                     \
    } while (0)

    USERS_SWAP_TABLE_PTR(sha224_table);
    USERS_SWAP_TABLE_PTR(sha256_table);
    USERS_SWAP_TABLE_PTR(uuid_table);
    USERS_SWAP_TABLE_PTR(wireguard_publickey_table);
    USERS_SWAP_TABLE_PTR(id_table);
    USERS_SWAP_TABLE_PTR(name_table);
    USERS_SWAP_TABLE_PTR(pointer_table);
    USERS_SWAP_TABLE_PTR(allowed_ip_table);

#undef USERS_SWAP_TABLE_PTR
}

bool usersBuildLookupTablesForItemsLocked(users_t *lookup_users, user_t **items, size_t count)
{
    size_t ranged_count    = 0;
    size_t lookup_capacity = count;

    lookup_users->count = count;
    for (size_t i = 0; i < count; ++i)
    {
        if (items[i]->wireguard_allowed_ips_valid)
        {
            ranged_count += 1U;
        }
    }

    if (UNLIKELY(lookup_capacity == SIZE_MAX))
    {
        LOGE("Users: lookup table capacity overflow");
        return false;
    }
    lookup_capacity += 1U;

    usersLookupTablesCreateIfNeededLocked(lookup_users);
    if (UNLIKELY(! usersEnsureLookupCapacityLocked(lookup_users, lookup_capacity) ||
                 ! usersAllowedIpTableReserve(lookup_users->allowed_ip_table, ranged_count)))
    {
        return false;
    }

    for (size_t i = 0; i < count; ++i)
    {
        user_t *user = items[i];
        if (UNLIKELY(! usersSHA224TableInsertLocked(lookup_users, user)))
        {
            return false;
        }
        if (UNLIKELY(! usersSHA256TableInsertLocked(lookup_users, user)))
        {
            return false;
        }
        if (UNLIKELY(! usersUUIDTableInsertLocked(lookup_users, user)))
        {
            return false;
        }
        if (UNLIKELY(! usersWireGuardPublicKeyTableInsertLocked(lookup_users, user)))
        {
            return false;
        }
        if (UNLIKELY(! usersIDTableInsertLocked(lookup_users, user)))
        {
            return false;
        }
        if (UNLIKELY(! usersNameTableInsertLocked(lookup_users, user)))
        {
            return false;
        }
        if (UNLIKELY(! usersPointerTableSetLocked(lookup_users, user, i)))
        {
            return false;
        }
        if (UNLIKELY(! usersAllowedIpTableInsertLocked(lookup_users, user)))
        {
            return false;
        }
    }

    return true;
}

bool usersRebuildLookupTablesLocked(users_t *users)
{
    users_t temp;
    bool    ok;

    memoryZero(&temp, sizeof(temp));
    ok = usersBuildLookupTablesForItemsLocked(&temp, users->items, users->count);
    if (LIKELY(ok))
    {
        usersLookupTablesSwapLocked(users, &temp);
    }
    usersLookupTablesDestroy(&temp);
    return ok;
}

/*
 * Erases every index entry a user owns, reading the user's live key fields. Used
 * by incremental removal before the user object is destroyed. Returns false if
 * any entry resolved to a different user (an invariant violation); it still
 * attempts every erase so the tables are left as consistent as possible.
 */
bool usersEraseAllIndexEntriesLocked(users_t *users, user_t *user)
{
    bool ok = true;

    if (! usersSHA224TableEraseLocked(users, user, user->sha224_pass.bytes))
    {
        ok = false;
    }
    if (! usersSHA256TableEraseLocked(users, user, user->sha256_pass.bytes))
    {
        ok = false;
    }
    if (user->uuid_pass_valid && ! usersUUIDTableEraseLocked(users, user, user->uuid_pass))
    {
        ok = false;
    }
    if (user->wireguard_publickey_valid &&
        ! usersWireGuardPublicKeyTableEraseLocked(users, user, user->wireguard_publickey))
    {
        ok = false;
    }
    if (! usersIDTableEraseLocked(users, user, user->id))
    {
        ok = false;
    }
    if (! usersNameTableEraseLocked(users, user, user->name))
    {
        ok = false;
    }
    if (! usersAllowedIpTableEraseLocked(users, user))
    {
        ok = false;
    }
    usersPointerTableEraseLocked(users, user);
    return ok;
}

user_t *usersFindByNameLocked(const users_t *users, const char *name, const user_t *exclude)
{
    /*
     * Average-O(1) via the name table. Non-empty names are unique, so a hit that
     * is not the excluded user is a genuine duplicate; a hit equal to `exclude`
     * (a no-op rename to the same name) is not a conflict.
     */
    user_t *found = usersNameTableLookupLocked(users, name);
    return (found != NULL && found != exclude) ? found : NULL;
}

/* No reserve or rehash is permitted once index publication starts. Callers
 * establish unique keys and complete capacity before entering this commit. */
void usersCommitReservedCredentialsLocked(users_t *users, user_t *slot)
{
    USERS_INSERT_RESERVED(sha224_table, users_sha224_map_t, usersSHA224KeyFromBytes(slot->sha224_pass.bytes), slot);
    USERS_INSERT_RESERVED(sha256_table, users_sha256_map_t, usersSHA256KeyFromBytes(slot->sha256_pass.bytes), slot);
    if (slot->uuid_pass_valid)
        USERS_INSERT_RESERVED(uuid_table, users_uuid_map_t, usersUUIDKeyFromBytes(slot->uuid_pass), slot);
    if (slot->wireguard_publickey_valid)
        USERS_INSERT_RESERVED(wireguard_publickey_table,
                              users_wireguard_publickey_map_t,
                              usersWireGuardPublicKeyFromBytes(slot->wireguard_publickey),
                              slot);
}

void usersCommitReservedUserLocked(users_t *users, user_t *slot)
{
    /* Initialize a newly installed finite policy before publication, so an
     * edit before first traffic still preserves/clamps its original credit. */
    rwlockWriteLock(&slot->lock);
    rwlockWriteLock(&slot->stats_lock);
    userBandwidthReconcileLocked(slot, getHRTimeUs() / 1000U);
    rwlockWriteUnlock(&slot->stats_lock);
    rwlockWriteUnlock(&slot->lock);
    usersCommitReservedCredentialsLocked(users, slot);
    if (slot->id != 0)
        USERS_INSERT_RESERVED(id_table, users_id_map_t, slot->id, slot);
    if (! usersNameTableInsertReservedLocked(users, slot))
    {
        LOGF("Users: duplicate name during reserved insertion");
        abortProgramNow(1);
    }
    USERS_INSERT_RESERVED(pointer_table, users_pointer_map_t, (uintptr_t) slot, users->count);
#undef USERS_INSERT_RESERVED
    if (slot->wireguard_allowed_ips_valid)
    {
        users_allowed_ip_map_t *map = &users->allowed_ip_table->map;
        if ((map->disp == 0 && map->head >= map->capacity) || ! usersAllowedIpTableInsertLocked(users, slot))
        {
            LOGF("Users: inconsistent reserved Allowed-IP insertion");
            abortProgramNow(1);
        }
    }
    users->items[users->count++] = slot;
    ++users->slot_count;
}

/*
 * Commits a fully-initialized slot into the active set and every lookup index.
 *
 * The caller has checked the identical source's indexes under the same held
 * write lock. Fresh JSON construction derives
 * credentials once; trusted copies preserve those validated values. Arbitrary
 * checked-add callers also run usersValidateNewUserNoFatalLocked(), including
 * the full derived-password diagnostic. Repeating those proofs here would
 * recompute credentials or repeat duplicate probes, so they are skipped. The
 * capacity reservation and the index inserts always run, so a false return
 * reflects rejected capacity geometry. Publication thereafter
 * uses the shared reserved primitive; impossible index inconsistencies are fatal.
 */
bool usersCommitNewUserLocked(users_t *users, user_t *slot)
{
    if (UNLIKELY(! usersEnsureLookupCapacityLocked(users, users->count + 1U)))
    {
        return false;
    }
    if (UNLIKELY(slot->wireguard_allowed_ips_valid && ! usersAllowedIpTableEnsureOneMoreRange(users)))
    {
        return false;
    }

    usersCommitReservedUserLocked(users, slot);
    return true;
}

void usersDuplicateResultConsider(const users_t *users, users_duplicate_result_t *best, user_t *owner,
                                  users_add_result_t result, uint8_t priority)
{
    size_t index = SIZE_MAX;

    if (owner == NULL)
    {
        return;
    }
    (void) usersIndexOfLocked(users, owner, &index);
    if (! best->found || index < best->index || (index == best->index && priority < best->priority))
    {
        best->result   = result;
        best->index    = index;
        best->priority = priority;
        best->found    = true;
    }
}

users_add_result_t usersValidateNewUserIndexesLocked(const users_t *users, const user_t *user)
{
    /*
     * Classify duplicates through the lookup indexes instead of scanning every
     * existing user. Each index already yields the owning user, so this is
     * average O(1) per key (O(log M) for the Allowed-IP overlap probe) rather
     * than O(N), which keeps a full feed average O(N) instead of O(N^2).
     */
    if (UNLIKELY(usersFindByNameLocked(users, user->name, NULL) != NULL))
    {
        return kUsersAddResultDuplicateName;
    }

    bool    range_ok = true;
    user_t *overlap  = usersFindWireGuardAllowedIpsOverlapLocked(users,
                                                                user->wireguard_allowed_ips_valid,
                                                                &user->wireguard_allowed_ip,
                                                                &user->wireguard_allowed_mask,
                                                                user->wireguard_allowed_ip_family,
                                                                NULL,
                                                                &range_ok);
    if (UNLIKELY(! range_ok))
    {
        return kUsersAddResultInvalidWireGuardAllowedIps;
    }

    /*
     * Preserve the old checked-add compatibility rule without restoring the old
     * O(N) scan: non-empty duplicate names win first, then the earliest existing
     * conflicting user wins. If the same existing user conflicts on multiple
     * keys, keep the former per-user key order.
     */
    users_duplicate_result_t duplicate = {0};
    usersDuplicateResultConsider(users,
                                 &duplicate,
                                 usersSHA224TableLookupLocked(users, user->sha224_pass.bytes),
                                 kUsersAddResultDuplicateSHA224,
                                 0U);
    usersDuplicateResultConsider(users,
                                 &duplicate,
                                 usersSHA256TableLookupLocked(users, user->sha256_pass.bytes),
                                 kUsersAddResultDuplicateSHA256,
                                 1U);
    if (user->uuid_pass_valid)
    {
        usersDuplicateResultConsider(
            users, &duplicate, usersUUIDTableLookupLocked(users, user->uuid_pass), kUsersAddResultDuplicateUUID, 2U);
    }
    if (user->wireguard_publickey_valid)
    {
        usersDuplicateResultConsider(users,
                                     &duplicate,
                                     usersWireGuardPublicKeyTableLookupLocked(users, user->wireguard_publickey),
                                     kUsersAddResultDuplicateWireGuardPublicKey,
                                     3U);
    }
    usersDuplicateResultConsider(users, &duplicate, overlap, kUsersAddResultDuplicateWireGuardAllowedIps, 4U);
    if (user->id != 0)
    {
        usersDuplicateResultConsider(
            users, &duplicate, usersIDTableLookupLocked(users, user->id), kUsersAddResultDuplicateId, 5U);
    }
    if (UNLIKELY(duplicate.found))
    {
        return duplicate.result;
    }

    return kUsersAddResultOk;
}

users_add_result_t usersValidateNewUserNoFatalLocked(const users_t *users, const user_t *user)
{
    if (UNLIKELY(user == NULL || ! user->initialized || ! user->sha224_pass_valid || ! user->sha256_pass_valid ||
                 ! userPasswordDataValid((user_t *) user)))
        return kUsersAddResultInvalidUser;
    if (UNLIKELY(! usersAllowedIpUserFieldsIndexable(user)))
        return kUsersAddResultInvalidWireGuardAllowedIps;
    return usersValidateNewUserIndexesLocked(users, user);
}

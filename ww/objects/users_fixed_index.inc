/* Private typed expansion for the four fixed-byte credential maps. */
bool USERS_FIXED_FN(Reserve)(USERS_FIXED_TABLE *table, size_t count)
{
    size_t capacity = max(count, (size_t) kUsersInitialTableCapacity);
    if (! userIndexHashCapacityIsRepresentable(capacity, sizeof(*table->map.table), sizeof(*table->map.meta)))
    {
        LOGE("Users: " USERS_FIXED_LABEL " lookup table capacity overflow");
        return false;
    }
    discard USERS_FIXED_MAP(_reserve)(&table->map, (isize) capacity);
    return true;
}

void USERS_FIXED_FN(CreateIfNeeded)(users_t *users)
{
    if (users->USERS_FIXED_FIELD != NULL)
        return;
    USERS_FIXED_TABLE *table = memoryAllocateZero(sizeof(*table));
    discard            USERS_FIXED_MAP(_reserve)(&table->map, kUsersInitialTableCapacity);
    users->USERS_FIXED_FIELD = table;
}

bool USERS_FIXED_FN(EnsureCapacity)(users_t *users, size_t count)
{
    USERS_FIXED_FN(CreateIfNeeded)(users);
    return USERS_FIXED_FN(Reserve)(users->USERS_FIXED_FIELD, count);
}

void USERS_FIXED_FN(Clear)(USERS_FIXED_TABLE *table)
{
    if (table != NULL)
    {
        USERS_FIXED_MAP(_clear)(&table->map);
        if (table->map.table != NULL)
            memorySecureZero(table->map.table, (size_t) table->map.bucket_count * sizeof(*table->map.table));
    }
}

void USERS_FIXED_FN(Destroy)(USERS_FIXED_TABLE *table)
{
    if (table == NULL)
        return;
    USERS_FIXED_MAP(_drop)(&table->map);
    memoryFree(table);
}

user_t *USERS_FIXED_FN(LookupLocked)(const users_t *users, const uint8_t bytes[USERS_FIXED_BYTES])
{
    USERS_FIXED_TABLE *table = users->USERS_FIXED_FIELD;
    if (table == NULL || bytes == NULL)
        return NULL;
    USERS_FIXED_KEY key       = USERS_FIXED_KEY_FROM_BYTES(bytes);
    USERS_FIXED_MAP(_iter) it = USERS_FIXED_MAP(_find)(&table->map, key);
    memorySecureZero(&key, sizeof(key));
    return it.ref != NULL ? it.ref->second : NULL;
}

bool USERS_FIXED_FN(EraseLocked)(users_t *users, const user_t *user, const uint8_t bytes[USERS_FIXED_BYTES])
{
    USERS_FIXED_TABLE *table = users->USERS_FIXED_FIELD;
    if (table == NULL)
    {
        LOGE("Users: " USERS_FIXED_LABEL " entry to erase has no lookup table (corrupted index)");
        return false;
    }
    USERS_FIXED_KEY key       = USERS_FIXED_KEY_FROM_BYTES(bytes);
    USERS_FIXED_MAP(_iter) it = USERS_FIXED_MAP(_find)(&table->map, key);
    memorySecureZero(&key, sizeof(key));
    if (it.ref == NULL || it.ref->second != user)
    {
        LOGE("Users: " USERS_FIXED_LABEL " entry to erase has invalid ownership (corrupted index)");
        return false;
    }
    size_t hole = (size_t) (it.ref - table->map.table);
    USERS_FIXED_MAP(_erase_entry)(&table->map, it.ref);
    /* Backward shifting leaves one inactive copy of the final credential. */
    const size_t mask = (size_t) table->map.bucket_count - 1U;
    while (table->map.meta[hole].dist != 0)
        hole = (hole + 1U) & mask;
    memorySecureZero(&table->map.table[hole], sizeof(*table->map.table));
    return true;
}

#undef USERS_FIXED_FN
#undef USERS_FIXED_FIELD
#undef USERS_FIXED_TABLE
#undef USERS_FIXED_MAP
#undef USERS_FIXED_KEY
#undef USERS_FIXED_BYTES
#undef USERS_FIXED_KEY_FROM_BYTES
#undef USERS_FIXED_LABEL

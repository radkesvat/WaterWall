#include "replay.h"

typedef struct replay_key_s
{
    uint8_t  bytes[48];
    uint64_t hash;
} replay_key_t;

typedef struct replay_entry_s
{
    replay_key_t key;
    uint64_t     expiry;
    size_t       position;
} replay_entry_t;

static uint64_t replayHash(const replay_key_t *key)
{
    return key->hash;
}
static bool replayEqual(const replay_key_t *a, const replay_key_t *b)
{
    return memoryCompare(a->bytes, b->bytes, sizeof(a->bytes)) == 0;
}

static void replayStorageFree(void *pointer, size_t size)
{
    if (pointer != NULL)
        memorySecureZero(pointer, size);
    memoryFree(pointer);
}

#define i_type                replay_map_t
#define i_key                 replay_key_t
#define i_val                 replay_entry_t *
#define i_hash                replayHash
#define i_eq                  replayEqual
#define i_malloc              c_malloc
#define i_calloc              c_calloc
#define i_realloc             c_realloc
#define i_free(pointer, size) replayStorageFree((pointer), (size_t) (size))
#include "stc/hmap.h"

typedef struct replay_table_s
{
    replay_map_t     map;
    replay_entry_t **heap;
    size_t           count, allocated;
} replay_table_t;

struct vmess_replay_s
{
    wmutex_t       mutex;
    replay_table_t auth, session;
    uint64_t       seed, wall_high_water;
    size_t         capacity;
};

static void heapSet(replay_table_t *table, size_t index, replay_entry_t *entry)
{
    table->heap[index] = entry;
    entry->position    = index;
}

static void removeEntry(replay_table_t *table, replay_entry_t *entry)
{
    size_t index = entry->position;
    replay_map_t_erase(&table->map, entry->key);
    replay_entry_t *last = table->heap[--table->count];
    if (index != table->count)
    {
        while (index != 0 && last->expiry < table->heap[(index - 1) / 2]->expiry)
        {
            heapSet(table, index, table->heap[(index - 1) / 2]);
            index = (index - 1) / 2;
        }
        while (2 * index + 1 < table->count)
        {
            size_t child = 2 * index + 1;
            if (child + 1 < table->count && table->heap[child + 1]->expiry < table->heap[child]->expiry)
                ++child;
            if (last->expiry <= table->heap[child]->expiry)
                break;
            heapSet(table, index, table->heap[child]);
            index = child;
        }
        heapSet(table, index, last);
    }
    memorySecureZero(entry, sizeof(*entry));
    memoryFree(entry);
}

static void expireEntries(replay_table_t *table, uint64_t now)
{
    /* Limit lock hold time during a large idle-to-busy transition. A saturated
     * table fails closed until later admissions finish reclaiming expired marks. */
    for (unsigned i = 0; i < 256 && table->count && table->heap[0]->expiry <= now; ++i)
        removeEntry(table, table->heap[0]);
}

static bool containsLive(replay_table_t *table, replay_key_t key, uint64_t now)
{
    replay_map_t_iter it = replay_map_t_find(&table->map, key);
    if (it.ref == NULL)
        return false;
    if (it.ref->second->expiry > now)
        return true;
    removeEntry(table, it.ref->second);
    return false;
}

static void insertEntry(replay_table_t *table, replay_key_t key, uint64_t expiry, size_t capacity)
{
    if (table->count == table->allocated)
    {
        size_t count     = min(capacity, table->allocated ? table->allocated * 2 : 16);
        table->heap      = memoryReAllocate(table->heap, count * sizeof(*table->heap));
        table->allocated = count;
    }
    replay_entry_t *entry = memoryAllocate(sizeof(*entry));
    *entry                = (replay_entry_t) {.key = key, .expiry = expiry};
    size_t index          = table->count++;
    while (index && expiry < table->heap[(index - 1) / 2]->expiry)
    {
        heapSet(table, index, table->heap[(index - 1) / 2]);
        index = (index - 1) / 2;
    }
    heapSet(table, index, entry);
    replay_map_t_insert(&table->map, key, entry);
}

vmess_replay_t *vmessReplayCreate(size_t capacity)
{
    assert(capacity && capacity <= SIZE_MAX / sizeof(replay_entry_t *));
    vmess_replay_t *replay = memoryAllocateZero(sizeof(*replay));
    mutexInit(&replay->mutex);
    replay->capacity = capacity;
    replay->seed     = fastRand64();
    return replay;
}

void vmessReplayDestroy(vmess_replay_t *replay)
{
    if (! replay)
        return;
    replay_table_t *tables[] = {&replay->auth, &replay->session};
    for (unsigned i = 0; i < 2; ++i)
    {
        while (tables[i]->count)
            removeEntry(tables[i], tables[i]->heap[0]);
        replay_map_t_drop(&tables[i]->map);
        memoryFree(tables[i]->heap);
    }
    mutexDestroy(&replay->mutex);
    memorySecureZero(replay, sizeof(*replay));
    memoryFree(replay);
}

bool vmessReplayAdmit(vmess_replay_t *replay, const uint8_t auth_id[16], const uint8_t uuid[16], const uint8_t key[16],
                      const uint8_t iv[16], uint64_t timestamp, uint64_t wall_seconds, uint64_t monotonic_ms)
{
    replay_key_t auth = {0}, session = {0};
    memoryCopy(auth.bytes, auth_id, 16);
    memoryCopy(session.bytes, uuid, 16);
    memoryCopy(session.bytes + 16, key, 16);
    memoryCopy(session.bytes + 32, iv, 16);
    auth.hash    = calcHashBytesSeed(auth.bytes, sizeof(auth.bytes), replay->seed);
    session.hash = calcHashBytesSeed(session.bytes, sizeof(session.bytes), replay->seed);
    mutexLock(&replay->mutex);
    replay->wall_high_water = max(replay->wall_high_water, wall_seconds);
    const uint64_t high     = replay->wall_high_water;
    expireEntries(&replay->auth, high);
    expireEntries(&replay->session, monotonic_ms);
    bool valid = timestamp <= UINT64_MAX - 121 && monotonic_ms <= UINT64_MAX - 180000 &&
                 ! (timestamp < high && high - timestamp > 120) &&
                 ! (timestamp > wall_seconds && timestamp - wall_seconds > 120);
    if (valid)
        valid = ! containsLive(&replay->auth, auth, high) && ! containsLive(&replay->session, session, monotonic_ms) &&
                replay->auth.count < replay->capacity && replay->session.count < replay->capacity;
    if (valid)
    {
        insertEntry(&replay->auth, auth, timestamp + 121, replay->capacity);
        insertEntry(&replay->session, session, monotonic_ms + 180000, replay->capacity);
    }
    mutexUnlock(&replay->mutex);
    memorySecureZero(&session, sizeof(session));
    return valid;
}

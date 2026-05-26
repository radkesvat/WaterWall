#include "objects/users.h"
#include "watomic.h"

#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum
{
    kSyncStressUsers       = 8,
    kSyncWriterThreads    = 4,
    kSyncPullerThreads    = 4,
    kSyncWriterIterations = 10000,
    kSyncPullerIterations = 5000,

    kDirtyMarkerThreads    = 4,
    kDirtyPullerThreads    = 2,
    kDirtyMarkerIterations = 20000,
    kDirtyPullerIterations = 8000,

    kLifetimeStableUsers      = 4,
    kLifetimeChurnIterations  = 8000,
    kLifetimeReaderThreads    = 3,
    kLifetimeReaderIterations = 4000,

    kPasswordBufSize = 64,
    kNameBufSize     = 64,
    kNotesBufSize    = 96
};

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "%s\n", message);
        abort();
    }
}

static void require_pthread(int result, const char *message)
{
    if (result != 0)
    {
        fprintf(stderr, "%s: %d\n", message, result);
        abort();
    }
}

static void wait_barrier_or_die(pthread_barrier_t *barrier, const char *message)
{
    int result = pthread_barrier_wait(barrier);
    if (result != 0 && result != PTHREAD_BARRIER_SERIAL_THREAD)
    {
        require_pthread(result, message);
    }
}

static void create_user_or_die(user_t *user, const char *password, const char *name)
{
    cJSON *json = cJSON_CreateObject();
    require(json != NULL, "failed to create user JSON object");
    require(cJSON_AddStringToObject(json, "password", password) != NULL, "failed to add user password");
    require(cJSON_AddStringToObject(json, "name", name) != NULL, "failed to add user name");

    memset(user, 0, sizeof(*user));
    require(userCreateFromJson(user, json), "failed to create user from JSON");
    cJSON_Delete(json);
}

static void add_user_or_die(users_t *users,
                            const char *password,
                            const char *name,
                            uint8_t sha256_out[SHA256_DIGEST_SIZE])
{
    user_t user;

    create_user_or_die(&user, password, name);
    if (sha256_out != NULL)
    {
        memcpy(sha256_out, user.sha256_pass.bytes, SHA256_DIGEST_SIZE);
    }
    require(usersAddUserChecked(users, &user) == kUsersAddResultOk, "failed to add user to database");
    userDestroy(&user);
}

static cJSON *make_client_sync_array(char passwords[][kPasswordBufSize],
                                     const uint32_t *sync_indexes,
                                     size_t count)
{
    cJSON *array = cJSON_CreateArray();
    require(array != NULL, "failed to create client sync array");

    for (size_t i = 0; i < count; ++i)
    {
        cJSON *entry = cJSON_CreateObject();
        require(entry != NULL, "failed to create client sync entry");
        require(cJSON_AddStringToObject(entry, "password", passwords[i]) != NULL, "failed to add client password");
        require(cJSON_AddNumberToObject(entry, "sync_index", (double) sync_indexes[i]) != NULL,
                "failed to add client sync index");
        require(cJSON_AddItemToArray(array, entry), "failed to append client sync entry");
    }

    return array;
}

static const cJSON *json_object_get(const cJSON *json, const char *key)
{
    const cJSON *item = cJSON_GetObjectItemCaseSensitive(json, key);
    require(item != NULL, "missing expected JSON field");
    return item;
}

static const char *json_string_field(const cJSON *json, const char *key)
{
    const cJSON *item = json_object_get(json, key);
    require(cJSON_IsString(item) && item->valuestring != NULL, "expected JSON string field");
    return item->valuestring;
}

static uint32_t json_sync_index_field(const cJSON *json)
{
    const cJSON *item = json_object_get(json, "sync_index");
    require(cJSON_IsNumber(item), "expected numeric sync_index");
    require(item->valuedouble >= 0.0 && item->valuedouble <= (double) UINT32_MAX, "sync_index out of range");

    uint32_t sync_index = (uint32_t) item->valuedouble;
    require((double) sync_index == item->valuedouble, "sync_index must be an integer");
    return sync_index;
}

static const cJSON *find_user_json_by_password(const cJSON *array, const char *password)
{
    const cJSON *entry = NULL;

    cJSON_ArrayForEach(entry, array)
    {
        require(cJSON_IsObject(entry), "pull result entry is not an object");
        const char *entry_password = json_string_field(entry, "password");
        if (strcmp(entry_password, password) == 0)
        {
            return entry;
        }
    }

    return NULL;
}

static size_t password_index_or_die(char passwords[][kPasswordBufSize], size_t count, const char *password)
{
    for (size_t i = 0; i < count; ++i)
    {
        if (strcmp(passwords[i], password) == 0)
        {
            return i;
        }
    }

    require(false, "pull result contained an unknown password");
    return 0;
}

static void test_pull_semantics_and_private_sync_lifecycle(void)
{
    users_t users;
    require(usersCreate(&users), "failed to create users database");

    char     passwords[1][kPasswordBufSize] = {"alpha-password"};
    uint8_t  sha256[SHA256_DIGEST_SIZE];
    uint32_t sync_indexes[1] = {1};

    add_user_or_die(&users, passwords[0], "alpha", sha256);

    cJSON *client = make_client_sync_array(passwords, sync_indexes, 1);
    cJSON *pull   = usersPullChangesJson(&users, client);
    require(pull != NULL, "initial pull failed");
    require(cJSON_GetArraySize(pull) == 0, "fresh client sync should not return unchanged users");
    cJSON_Delete(pull);
    cJSON_Delete(client);

    const char    notes[] = "first update";
    user_update_t update  = {.mask = kUserUpdateNotes, .notes = notes};
    uint32_t      new_sync_index = 0;
    require(usersUpdateUserBySHA256AndIncrementSync(&users, sha256, &update, &new_sync_index) == kUsersUpdateResultOk,
            "update plus sync increment failed");
    require(new_sync_index == 2, "first update should move sync_index from 1 to 2");

    sync_indexes[0] = 1;
    client          = make_client_sync_array(passwords, sync_indexes, 1);
    pull            = usersPullChangesJson(&users, client);
    require(pull != NULL, "dirty pull failed");
    require(cJSON_GetArraySize(pull) == 1, "stale client sync should return the changed user");

    const cJSON *user_json = find_user_json_by_password(pull, passwords[0]);
    require(user_json != NULL, "changed user was not returned");
    require(json_sync_index_field(user_json) == 2, "changed user returned the wrong sync_index");
    require(strcmp(json_string_field(user_json, "notes"), notes) == 0, "changed user returned stale notes");
    cJSON_Delete(pull);
    cJSON_Delete(client);

    sync_indexes[0] = 2;
    client          = make_client_sync_array(passwords, sync_indexes, 1);
    pull            = usersPullChangesJson(&users, client);
    require(pull != NULL, "current pull failed");
    require(cJSON_GetArraySize(pull) == 0, "current client sync should not return unchanged users");
    cJSON_Delete(pull);
    cJSON_Delete(client);

    sync_indexes[0] = 999;
    client          = make_client_sync_array(passwords, sync_indexes, 1);
    pull            = usersPullChangesJson(&users, client);
    require(pull != NULL, "ahead-of-server pull failed");
    require(cJSON_GetArraySize(pull) == 1, "client sync newer than server should be treated as dirty");
    user_json = find_user_json_by_password(pull, passwords[0]);
    require(user_json != NULL, "ahead-of-server dirty user was not returned");
    require(json_sync_index_field(user_json) == 2, "ahead-of-server pull returned the wrong sync_index");
    cJSON_Delete(pull);
    cJSON_Delete(client);

    usersDestroy(&users);
}

static void test_pull_rejects_malformed_client_sync_arrays(void)
{
    users_t users;
    require(usersCreate(&users), "failed to create users database");

    uint8_t sha256[SHA256_DIGEST_SIZE];
    (void) sha256;
    add_user_or_die(&users, "malformed-password", "malformed-user", sha256);

    require(usersPullChangesJson(&users, NULL) == NULL, "NULL client sync array should be rejected");

    cJSON *not_array = cJSON_CreateObject();
    require(not_array != NULL, "failed to create malformed object");
    require(usersPullChangesJson(&users, not_array) == NULL, "non-array client sync payload should be rejected");
    cJSON_Delete(not_array);

    cJSON *missing_password_array = cJSON_CreateArray();
    cJSON *missing_password_entry = cJSON_CreateObject();
    require(missing_password_array != NULL && missing_password_entry != NULL, "failed to create missing-password case");
    require(cJSON_AddNumberToObject(missing_password_entry, "sync_index", 1) != NULL,
            "failed to add sync_index to missing-password case");
    require(cJSON_AddItemToArray(missing_password_array, missing_password_entry),
            "failed to append missing-password case");
    require(usersPullChangesJson(&users, missing_password_array) == NULL,
            "client sync entry without password should be rejected");
    cJSON_Delete(missing_password_array);

    cJSON *fractional_sync_array = cJSON_CreateArray();
    cJSON *fractional_sync_entry = cJSON_CreateObject();
    require(fractional_sync_array != NULL && fractional_sync_entry != NULL, "failed to create fractional-sync case");
    require(cJSON_AddStringToObject(fractional_sync_entry, "password", "malformed-password") != NULL,
            "failed to add password to fractional-sync case");
    require(cJSON_AddNumberToObject(fractional_sync_entry, "sync_index", 1.5) != NULL,
            "failed to add fractional sync_index");
    require(cJSON_AddItemToArray(fractional_sync_array, fractional_sync_entry),
            "failed to append fractional-sync case");
    require(usersPullChangesJson(&users, fractional_sync_array) == NULL,
            "fractional client sync_index should be rejected");
    cJSON_Delete(fractional_sync_array);

    cJSON *bad_string_sync_array = cJSON_CreateArray();
    cJSON *bad_string_sync_entry = cJSON_CreateObject();
    require(bad_string_sync_array != NULL && bad_string_sync_entry != NULL, "failed to create bad-string-sync case");
    require(cJSON_AddStringToObject(bad_string_sync_entry, "password", "malformed-password") != NULL,
            "failed to add password to bad-string-sync case");
    require(cJSON_AddStringToObject(bad_string_sync_entry, "sync_index", "not-a-number") != NULL,
            "failed to add bad sync_index string");
    require(cJSON_AddItemToArray(bad_string_sync_array, bad_string_sync_entry),
            "failed to append bad-string-sync case");
    require(usersPullChangesJson(&users, bad_string_sync_array) == NULL,
            "non-numeric client sync_index string should be rejected");
    cJSON_Delete(bad_string_sync_array);

    usersDestroy(&users);
}

typedef struct sync_stress_context_s
{
    users_t          users;
    uint8_t          sha256[kSyncStressUsers][SHA256_DIGEST_SIZE];
    char             passwords[kSyncStressUsers][kPasswordBufSize];
    atomic_uint      expected_sync[kSyncStressUsers];
    pthread_barrier_t start_barrier;
} sync_stress_context_t;

typedef struct sync_thread_arg_s
{
    sync_stress_context_t *ctx;
    size_t                 thread_index;
} sync_thread_arg_t;

static void *sync_writer_thread(void *arg)
{
    sync_thread_arg_t    *thread_arg = (sync_thread_arg_t *) arg;
    sync_stress_context_t *ctx        = thread_arg->ctx;

    wait_barrier_or_die(&ctx->start_barrier, "sync writer barrier failed");

    for (size_t i = 0; i < kSyncWriterIterations; ++i)
    {
        size_t user_index = (thread_arg->thread_index + i) % kSyncStressUsers;
        char   notes[kNotesBufSize];
        snprintf(notes, sizeof(notes), "writer-%zu-iteration-%zu", thread_arg->thread_index, i);

        user_update_t update = {.mask = kUserUpdateNotes, .notes = notes};
        uint32_t      new_sync_index = 0;
        users_update_result_t result =
            usersUpdateUserBySHA256AndIncrementSync(&ctx->users, ctx->sha256[user_index], &update, &new_sync_index);
        require(result == kUsersUpdateResultOk, "concurrent update plus sync increment failed");
        require(new_sync_index > 1, "concurrent update returned an invalid sync_index");
        atomicAdd(&ctx->expected_sync[user_index], 1U);
    }

    return NULL;
}

static void *sync_puller_thread(void *arg)
{
    sync_thread_arg_t    *thread_arg = (sync_thread_arg_t *) arg;
    sync_stress_context_t *ctx        = thread_arg->ctx;
    uint32_t              local_sync[kSyncStressUsers];

    for (size_t i = 0; i < kSyncStressUsers; ++i)
    {
        local_sync[i] = 1;
    }

    wait_barrier_or_die(&ctx->start_barrier, "sync puller barrier failed");

    for (size_t i = 0; i < kSyncPullerIterations; ++i)
    {
        cJSON *client = make_client_sync_array(ctx->passwords, local_sync, kSyncStressUsers);
        cJSON *pull   = usersPullChangesJson(&ctx->users, client);
        require(pull != NULL, "concurrent pull failed");

        const cJSON *entry = NULL;
        cJSON_ArrayForEach(entry, pull)
        {
            const char *password = json_string_field(entry, "password");
            size_t      user_index = password_index_or_die(ctx->passwords, kSyncStressUsers, password);
            uint32_t    server_sync = json_sync_index_field(entry);

            require(server_sync > local_sync[user_index], "pull returned a user that was not dirty for this client");
            local_sync[user_index] = server_sync;
        }

        cJSON_Delete(pull);
        cJSON_Delete(client);
    }

    return NULL;
}

static void sync_stress_context_init(sync_stress_context_t *ctx)
{
    memset(ctx, 0, sizeof(*ctx));
    require(usersCreate(&ctx->users), "failed to create sync stress users database");

    for (size_t i = 0; i < kSyncStressUsers; ++i)
    {
        char name[kNameBufSize];
        snprintf(ctx->passwords[i], sizeof(ctx->passwords[i]), "sync-user-%zu-password", i);
        snprintf(name, sizeof(name), "sync-user-%zu", i);
        add_user_or_die(&ctx->users, ctx->passwords[i], name, ctx->sha256[i]);
        atomicStoreRelaxed(&ctx->expected_sync[i], 1U);
    }

    require_pthread(pthread_barrier_init(&ctx->start_barrier,
                                         NULL,
                                         kSyncWriterThreads + kSyncPullerThreads),
                    "failed to initialize sync stress barrier");
}

static void sync_stress_context_destroy(sync_stress_context_t *ctx)
{
    require_pthread(pthread_barrier_destroy(&ctx->start_barrier), "failed to destroy sync stress barrier");
    usersDestroy(&ctx->users);
}

static void assert_final_sync_indexes(sync_stress_context_t *ctx)
{
    uint32_t zero_sync[kSyncStressUsers] = {0};
    cJSON   *client = make_client_sync_array(ctx->passwords, zero_sync, kSyncStressUsers);
    cJSON   *pull   = usersPullChangesJson(&ctx->users, client);
    require(pull != NULL, "final sync pull failed");
    require(cJSON_GetArraySize(pull) == kSyncStressUsers, "final sync pull should return every user");

    for (size_t i = 0; i < kSyncStressUsers; ++i)
    {
        const cJSON *user_json = find_user_json_by_password(pull, ctx->passwords[i]);
        require(user_json != NULL, "final pull missed a stress user");

        uint32_t expected = (uint32_t) atomicLoadRelaxed(&ctx->expected_sync[i]);
        uint32_t actual   = json_sync_index_field(user_json);
        require(actual == expected, "final sync_index did not match the number of committed updates");
    }

    cJSON_Delete(pull);
    cJSON_Delete(client);
}

static void test_concurrent_update_and_pull_stress(void)
{
    sync_stress_context_t ctx;
    pthread_t             writers[kSyncWriterThreads];
    pthread_t             pullers[kSyncPullerThreads];
    sync_thread_arg_t      writer_args[kSyncWriterThreads];
    sync_thread_arg_t      puller_args[kSyncPullerThreads];

    sync_stress_context_init(&ctx);

    for (size_t i = 0; i < kSyncWriterThreads; ++i)
    {
        writer_args[i] = (sync_thread_arg_t){.ctx = &ctx, .thread_index = i};
        require_pthread(pthread_create(&writers[i], NULL, sync_writer_thread, &writer_args[i]),
                        "failed to create sync writer thread");
    }
    for (size_t i = 0; i < kSyncPullerThreads; ++i)
    {
        puller_args[i] = (sync_thread_arg_t){.ctx = &ctx, .thread_index = i};
        require_pthread(pthread_create(&pullers[i], NULL, sync_puller_thread, &puller_args[i]),
                        "failed to create sync puller thread");
    }

    for (size_t i = 0; i < kSyncWriterThreads; ++i)
    {
        require_pthread(pthread_join(writers[i], NULL), "failed to join sync writer thread");
    }
    for (size_t i = 0; i < kSyncPullerThreads; ++i)
    {
        require_pthread(pthread_join(pullers[i], NULL), "failed to join sync puller thread");
    }

    assert_final_sync_indexes(&ctx);
    sync_stress_context_destroy(&ctx);
}

typedef struct dirty_mark_context_s
{
    users_t          users;
    uint8_t          sha256[SHA256_DIGEST_SIZE];
    char             passwords[1][kPasswordBufSize];
    atomic_uint      expected_sync;
    pthread_barrier_t start_barrier;
} dirty_mark_context_t;

typedef struct dirty_mark_thread_arg_s
{
    dirty_mark_context_t *ctx;
    size_t                thread_index;
} dirty_mark_thread_arg_t;

static void *dirty_marker_thread(void *arg)
{
    dirty_mark_thread_arg_t *thread_arg = (dirty_mark_thread_arg_t *) arg;
    dirty_mark_context_t    *ctx        = thread_arg->ctx;

    (void) thread_arg->thread_index;
    wait_barrier_or_die(&ctx->start_barrier, "dirty marker barrier failed");

    for (size_t i = 0; i < kDirtyMarkerIterations; ++i)
    {
        uint32_t new_sync_index = 0;
        users_update_result_t result = usersIncrementSyncIndexBySHA256(&ctx->users, ctx->sha256, &new_sync_index);
        require(result == kUsersUpdateResultOk, "dirty marker sync increment failed");
        require(new_sync_index > 1, "dirty marker returned an invalid sync_index");
        atomicAdd(&ctx->expected_sync, 1U);
    }

    return NULL;
}

static void *dirty_pull_thread(void *arg)
{
    dirty_mark_thread_arg_t *thread_arg = (dirty_mark_thread_arg_t *) arg;
    dirty_mark_context_t    *ctx        = thread_arg->ctx;
    uint32_t                 local_sync[1] = {1};

    (void) thread_arg->thread_index;
    wait_barrier_or_die(&ctx->start_barrier, "dirty pull barrier failed");

    for (size_t i = 0; i < kDirtyPullerIterations; ++i)
    {
        cJSON *client = make_client_sync_array(ctx->passwords, local_sync, 1);
        cJSON *pull   = usersPullChangesJson(&ctx->users, client);
        require(pull != NULL, "dirty marker concurrent pull failed");

        int pull_count = cJSON_GetArraySize(pull);
        require(pull_count == 0 || pull_count == 1, "single-user dirty pull returned an impossible count");
        if (pull_count == 1)
        {
            const cJSON *user_json = find_user_json_by_password(pull, ctx->passwords[0]);
            require(user_json != NULL, "dirty marker pull missed the only user");
            uint32_t server_sync = json_sync_index_field(user_json);
            require(server_sync > local_sync[0], "dirty marker pull returned a non-dirty user");
            local_sync[0] = server_sync;
        }

        cJSON_Delete(pull);
        cJSON_Delete(client);
    }

    return NULL;
}

static void dirty_mark_context_init(dirty_mark_context_t *ctx)
{
    memset(ctx, 0, sizeof(*ctx));
    require(usersCreate(&ctx->users), "failed to create dirty marker users database");

    snprintf(ctx->passwords[0], sizeof(ctx->passwords[0]), "dirty-marker-password");
    add_user_or_die(&ctx->users, ctx->passwords[0], "dirty-marker-user", ctx->sha256);
    atomicStoreRelaxed(&ctx->expected_sync, 1U);

    require_pthread(pthread_barrier_init(&ctx->start_barrier,
                                         NULL,
                                         kDirtyMarkerThreads + kDirtyPullerThreads),
                    "failed to initialize dirty marker barrier");
}

static void dirty_mark_context_destroy(dirty_mark_context_t *ctx)
{
    require_pthread(pthread_barrier_destroy(&ctx->start_barrier), "failed to destroy dirty marker barrier");
    usersDestroy(&ctx->users);
}

static void assert_dirty_marker_final_sync(dirty_mark_context_t *ctx)
{
    uint32_t zero_sync[1] = {0};
    cJSON   *client = make_client_sync_array(ctx->passwords, zero_sync, 1);
    cJSON   *pull   = usersPullChangesJson(&ctx->users, client);
    require(pull != NULL, "dirty marker final pull failed");
    require(cJSON_GetArraySize(pull) == 1, "dirty marker final pull should return the only user");

    const cJSON *user_json = find_user_json_by_password(pull, ctx->passwords[0]);
    require(user_json != NULL, "dirty marker final pull missed the only user");

    uint32_t expected = (uint32_t) atomicLoadRelaxed(&ctx->expected_sync);
    uint32_t actual   = json_sync_index_field(user_json);
    require(actual == expected, "dirty marker final sync_index did not match committed increments");

    cJSON_Delete(pull);
    cJSON_Delete(client);
}

static void test_concurrent_dirty_mark_and_pull_stress(void)
{
    dirty_mark_context_t    ctx;
    pthread_t               marker_threads[kDirtyMarkerThreads];
    pthread_t               puller_threads[kDirtyPullerThreads];
    dirty_mark_thread_arg_t marker_args[kDirtyMarkerThreads];
    dirty_mark_thread_arg_t puller_args[kDirtyPullerThreads];

    dirty_mark_context_init(&ctx);

    for (size_t i = 0; i < kDirtyMarkerThreads; ++i)
    {
        marker_args[i] = (dirty_mark_thread_arg_t){.ctx = &ctx, .thread_index = i};
        require_pthread(pthread_create(&marker_threads[i], NULL, dirty_marker_thread, &marker_args[i]),
                        "failed to create dirty marker thread");
    }
    for (size_t i = 0; i < kDirtyPullerThreads; ++i)
    {
        puller_args[i] = (dirty_mark_thread_arg_t){.ctx = &ctx, .thread_index = i};
        require_pthread(pthread_create(&puller_threads[i], NULL, dirty_pull_thread, &puller_args[i]),
                        "failed to create dirty puller thread");
    }

    for (size_t i = 0; i < kDirtyMarkerThreads; ++i)
    {
        require_pthread(pthread_join(marker_threads[i], NULL), "failed to join dirty marker thread");
    }
    for (size_t i = 0; i < kDirtyPullerThreads; ++i)
    {
        require_pthread(pthread_join(puller_threads[i], NULL), "failed to join dirty puller thread");
    }

    assert_dirty_marker_final_sync(&ctx);
    dirty_mark_context_destroy(&ctx);
}

typedef struct lifetime_context_s
{
    users_t          users;
    char             stable_passwords[kLifetimeStableUsers][kPasswordBufSize];
    pthread_barrier_t start_barrier;
} lifetime_context_t;

typedef struct lifetime_reader_arg_s
{
    lifetime_context_t *ctx;
    size_t              reader_index;
} lifetime_reader_arg_t;

static void *lifetime_churn_thread(void *arg)
{
    lifetime_context_t *ctx = (lifetime_context_t *) arg;

    wait_barrier_or_die(&ctx->start_barrier, "lifetime churn barrier failed");

    for (size_t i = 0; i < kLifetimeChurnIterations; ++i)
    {
        char    password[kPasswordBufSize];
        char    name[kNameBufSize];
        uint8_t sha256[SHA256_DIGEST_SIZE];
        user_t  user;

        snprintf(password, sizeof(password), "transient-password-%zu", i);
        snprintf(name, sizeof(name), "transient-user-%zu", i);

        create_user_or_die(&user, password, name);
        memcpy(sha256, user.sha256_pass.bytes, SHA256_DIGEST_SIZE);
        require(usersAddUserChecked(&ctx->users, &user) == kUsersAddResultOk, "failed to add transient user");
        userDestroy(&user);

        require(usersRemoveUserBySHA256(&ctx->users, sha256), "failed to remove transient user");
    }

    return NULL;
}

static void validate_exported_users_json(cJSON *root)
{
    require(root != NULL, "usersToJson returned NULL");
    const cJSON *array = json_object_get(root, "users");
    require(cJSON_IsArray(array), "usersToJson did not return a users array");
    require(cJSON_GetArraySize(array) >= kLifetimeStableUsers, "usersToJson lost stable users");

    const cJSON *entry = NULL;
    cJSON_ArrayForEach(entry, array)
    {
        require(cJSON_IsObject(entry), "usersToJson returned a non-object user entry");
        (void) json_string_field(entry, "password");
    }
}

static void *lifetime_reader_thread(void *arg)
{
    lifetime_reader_arg_t *reader_arg = (lifetime_reader_arg_t *) arg;
    lifetime_context_t    *ctx        = reader_arg->ctx;
    uint32_t               zero_sync[kLifetimeStableUsers] = {0};

    wait_barrier_or_die(&ctx->start_barrier, "lifetime reader barrier failed");

    for (size_t i = 0; i < kLifetimeReaderIterations; ++i)
    {
        cJSON *export_json = usersToJson(&ctx->users);
        validate_exported_users_json(export_json);
        cJSON_Delete(export_json);

        cJSON *client = make_client_sync_array(ctx->stable_passwords, zero_sync, kLifetimeStableUsers);
        cJSON *pull   = usersPullChangesJson(&ctx->users, client);
        require(pull != NULL, "lifetime pull failed");

        const cJSON *entry = NULL;
        cJSON_ArrayForEach(entry, pull)
        {
            require(cJSON_IsObject(entry), "lifetime pull returned a non-object entry");
            (void) json_string_field(entry, "password");
            require(json_sync_index_field(entry) >= 1, "lifetime pull returned an invalid sync_index");
        }

        cJSON_Delete(pull);
        cJSON_Delete(client);

        size_t stable_index = (reader_arg->reader_index + i) % kLifetimeStableUsers;
        const user_t *user = usersLookupByPasswordConst(&ctx->users, ctx->stable_passwords[stable_index]);
        require(user != NULL, "stable user lookup failed during add/remove churn");
    }

    return NULL;
}

static void lifetime_context_init(lifetime_context_t *ctx)
{
    memset(ctx, 0, sizeof(*ctx));
    require(usersCreate(&ctx->users), "failed to create lifetime users database");

    for (size_t i = 0; i < kLifetimeStableUsers; ++i)
    {
        char name[kNameBufSize];
        snprintf(ctx->stable_passwords[i], sizeof(ctx->stable_passwords[i]), "stable-password-%zu", i);
        snprintf(name, sizeof(name), "stable-user-%zu", i);
        add_user_or_die(&ctx->users, ctx->stable_passwords[i], name, NULL);
    }

    require_pthread(pthread_barrier_init(&ctx->start_barrier,
                                         NULL,
                                         kLifetimeReaderThreads + 1),
                    "failed to initialize lifetime barrier");
}

static void lifetime_context_destroy(lifetime_context_t *ctx)
{
    require_pthread(pthread_barrier_destroy(&ctx->start_barrier), "failed to destroy lifetime barrier");
    usersDestroy(&ctx->users);
}

static void test_concurrent_add_remove_export_and_pull_stress(void)
{
    lifetime_context_t     ctx;
    pthread_t              churn_thread;
    pthread_t              readers[kLifetimeReaderThreads];
    lifetime_reader_arg_t  reader_args[kLifetimeReaderThreads];

    lifetime_context_init(&ctx);

    require_pthread(pthread_create(&churn_thread, NULL, lifetime_churn_thread, &ctx),
                    "failed to create lifetime churn thread");
    for (size_t i = 0; i < kLifetimeReaderThreads; ++i)
    {
        reader_args[i] = (lifetime_reader_arg_t){.ctx = &ctx, .reader_index = i};
        require_pthread(pthread_create(&readers[i], NULL, lifetime_reader_thread, &reader_args[i]),
                        "failed to create lifetime reader thread");
    }

    require_pthread(pthread_join(churn_thread, NULL), "failed to join lifetime churn thread");
    for (size_t i = 0; i < kLifetimeReaderThreads; ++i)
    {
        require_pthread(pthread_join(readers[i], NULL), "failed to join lifetime reader thread");
    }

    require(usersCount(&ctx.users) == kLifetimeStableUsers, "transient churn leaked users");
    lifetime_context_destroy(&ctx);
}

int main(void)
{
    test_pull_semantics_and_private_sync_lifecycle();
    test_pull_rejects_malformed_client_sync_arrays();
    test_concurrent_update_and_pull_stress();
    test_concurrent_dirty_mark_and_pull_stress();
    test_concurrent_add_remove_export_and_pull_stress();
    return 0;
}

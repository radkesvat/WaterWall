/* CTest: waterwall.authenticationserver_storage_unit
 * Fault actual file operations, execute AddNewUser and reload primary/recovery. */
#include "AuthenticationServer/structure.h"
#include "common/private_file.h"
#include "fixtures/failure/tunnel_line_failure_harness.h"
#include "loggers/network_logger.h"

#include <pthread.h>

typedef enum fault_e
{
    kNone,
    kOpen,
    kWrite,
    kFlush,
    kSync,
    kClose,
    kBackupRename,
    kPrimaryRename,
    kBackupStage,
    kHistory,
    kDirectorySync,
    kReadOpen,
    kRead,
    kReadClose,
    kMissingPrimary,
    kMissingNoBackup,
    kMissingPublication,
    kPermissions,
    kProbeClose
} fault_t;
static fault_t  fault;
static unsigned rwlock_failure_after;
static unsigned credential_failure_after;
static unsigned producer_log_count;
static int      producer_log_level;
static char     producer_log[1024];
static bool     collide_archive, fail_history_remove, fail_backup_read;
static bool     fail_backup_permissions, require_nonblocking_backup;
static int      backup_fd = -1;
static unsigned backup_data_reads;
static char     collision_path[1024];
static char     primary[512];
static unsigned private_writes;
static unsigned stage_writes, directory_syncs;
static bool     use_test_clock;
static uint64_t test_clock_us;
static time_t   test_wall_time;
static unsigned wall_time_reads;
static bool     inspect_owned_credentials;
static char    *read_watch, *password_watch, *serialized_watch;
static size_t   read_watch_length, password_watch_length, serialized_watch_length;
static unsigned owned_credentials_wiped;

int __real_pthread_rwlock_init(pthread_rwlock_t *lock, const pthread_rwlockattr_t *attr);
int __wrap_pthread_rwlock_init(pthread_rwlock_t *lock, const pthread_rwlockattr_t *attr);
int __wrap_pthread_rwlock_init(pthread_rwlock_t *lock, const pthread_rwlockattr_t *attr)
{
    if (rwlock_failure_after != 0 && --rwlock_failure_after == 0)
        return EAGAIN;
    return __real_pthread_rwlock_init(lock, attr);
}

wcrypto_status_t __real_wCryptoSHA224(sha224_hash_t *out, const unsigned char *input, size_t length);
wcrypto_status_t __wrap_wCryptoSHA224(sha224_hash_t *out, const unsigned char *input, size_t length);
wcrypto_status_t __wrap_wCryptoSHA224(sha224_hash_t *out, const unsigned char *input, size_t length)
{
    if (credential_failure_after != 0 && --credential_failure_after == 0)
        return kWCryptoBackendFailed;
    return __real_wCryptoSHA224(out, input, length);
}

static void captureProducerLog(int level, const char *bytes, int length)
{
    twfRequire(length >= 0 && (size_t) length < sizeof(producer_log), "producer diagnostic exceeded fixture buffer");
    ++producer_log_count;
    producer_log_level = level;
    memoryCopy(producer_log, bytes, (size_t) length);
    producer_log[length] = '\0';
}

int __real_remove(const char *path);
int __wrap_remove(const char *path);
int __wrap_remove(const char *path)
{
    if (fail_history_remove && strstr(path, "/authenticationserver-") != NULL)
    {
        fail_history_remove = false;
        errno               = EIO;
        return -1;
    }
    return __real_remove(path);
}

void __real_memoryFree(void *pointer);
void __wrap_memoryFree(void *pointer);
void __wrap_memoryFree(void *pointer)
{
    if (pointer != NULL && (pointer == read_watch || pointer == password_watch || pointer == serialized_watch))
    {
        const size_t length = pointer == read_watch       ? read_watch_length
                              : pointer == password_watch ? password_watch_length
                                                          : serialized_watch_length;
        for (size_t i = 0; i < length; ++i)
            twfRequire(((const uint8_t *) pointer)[i] == 0, "database credential copy reached free unwiped");
        if (pointer == read_watch)
            read_watch = NULL;
        else if (pointer == password_watch)
            password_watch = NULL;
        else
            serialized_watch = NULL;
        ++owned_credentials_wiped;
    }
    __real_memoryFree(pointer);
}

static void watchDatabasePassword(cJSON *json)
{
    cJSON *row      = cJSON_GetArrayItem(cJSON_GetObjectItemCaseSensitive(json, "users"), 0);
    cJSON *password = cJSON_GetObjectItemCaseSensitive(row != NULL ? row : json, "password");
    if (password == NULL)
        password = cJSON_GetObjectItemCaseSensitive(row != NULL ? row : json, "pass");
    if (cJSON_IsString(password))
    {
        twfRequire(password_watch == NULL, "prior database JSON password not released");
        password_watch        = password->valuestring;
        password_watch_length = strlen(password_watch);
    }
}

cJSON *__real_cJSON_ParseWithLengthOpts(const char *text, size_t length, const char **end, cJSON_bool terminated);
cJSON *__wrap_cJSON_ParseWithLengthOpts(const char *text, size_t length, const char **end, cJSON_bool terminated);
cJSON *__wrap_cJSON_ParseWithLengthOpts(const char *text, size_t length, const char **end, cJSON_bool terminated)
{
    cJSON *json = __real_cJSON_ParseWithLengthOpts(text, length, end, terminated);
    if (inspect_owned_credentials)
        watchDatabasePassword(json);
    return json;
}

char *__real_cJSON_PrintBuffered(const cJSON *json, int size, cJSON_bool format);
char *__wrap_cJSON_PrintBuffered(const cJSON *json, int size, cJSON_bool format);
char *__wrap_cJSON_PrintBuffered(const cJSON *json, int size, cJSON_bool format)
{
    char *text = __real_cJSON_PrintBuffered(json, size, format);
    if (inspect_owned_credentials)
    {
        watchDatabasePassword((cJSON *) json);
        twfRequire(serialized_watch == NULL, "prior database serialization not released");
        serialized_watch        = text;
        serialized_watch_length = text == NULL ? 0 : strlen(text);
    }
    return text;
}

unsigned long long __real_getHRTimeUs(void);
unsigned long long __wrap_getHRTimeUs(void);
unsigned long long __wrap_getHRTimeUs(void)
{
    return use_test_clock ? test_clock_us : __real_getHRTimeUs();
}

time_t __real_time(time_t *result);
time_t __wrap_time(time_t *result);
time_t __wrap_time(time_t *result)
{
    if (! use_test_clock)
        return __real_time(result);
    ++wall_time_reads;
    if (result != NULL)
        *result = test_wall_time;
    return test_wall_time;
}

int __real_open(const char *path, int flags, ...);
int __wrap_open(const char *path, int flags, ...);
int __wrap_open(const char *path, int flags, ...)
{
    const bool is_backup = stringEndsWith(path, ".backup");
    if (is_backup && require_nonblocking_backup)
        twfRequire((flags & O_NONBLOCK) != 0, "backup permission probe could block on a FIFO");
    mode_t mode = 0;
    if ((flags & O_CREAT) != 0)
    {
        va_list args;
        va_start(args, flags);
        mode = (mode_t) va_arg(args, int);
        va_end(args);
        twfRequire(mode == 0600 && (flags & O_EXCL) != 0, "secret creation was not private and exclusive");
        if (use_test_clock && strstr(path, "/authenticationserver-") != NULL)
            test_clock_us += 30000U; /* Optional work follows the primary outcome. */
        if (collide_archive && strstr(path, ".corrupt-") != NULL)
        {
            collide_archive = false;
            snprintf(collision_path, sizeof(collision_path), "%s", path);
            int existing = __real_open(path, flags, mode);
            twfRequire(existing >= 0 && write(existing, "collision", 9) == 9 && close(existing) == 0,
                       "archive collision fixture failed");
            errno = EEXIST;
            return -1;
        }
        if (fault == kOpen)
        {
            fault = kNone;
            errno = EIO;
            return -1;
        }
    }
    if (fail_backup_read && stringEndsWith(path, ".backup") && (flags & O_ACCMODE) == O_RDONLY)
    {
        fail_backup_read = false;
        errno            = EACCES;
        return -1;
    }
    if (fault == kReadOpen && strcmp(path, primary) == 0 && (flags & O_ACCMODE) == O_RDONLY)
    {
        fault = kNone;
        errno = EIO;
        return -1;
    }
    const int fd = __real_open(path, flags, mode);
    if (is_backup && fd >= 0)
        backup_fd = fd;
    return fd;
}
int __real_close(int fd);
int __wrap_close(int fd);
int __wrap_close(int fd)
{
    if (fd == backup_fd)
        backup_fd = -1;
    const int result = __real_close(fd);
    if (fault == kProbeClose)
    {
        fault = kNone;
        errno = EIO;
        return -1;
    }
    return result;
}
size_t __real_fread(void *ptr, size_t size, size_t count, FILE *stream);
size_t __wrap_fread(void *ptr, size_t size, size_t count, FILE *stream);
size_t __wrap_fread(void *ptr, size_t size, size_t count, FILE *stream)
{
    if (fileno(stream) == backup_fd)
        ++backup_data_reads;
    if (inspect_owned_credentials)
    {
        twfRequire(read_watch == NULL, "prior database read not released");
        read_watch        = ptr;
        read_watch_length = size * count;
    }
    if (fault == kRead)
    {
        fault = kNone;
        errno = EIO;
        return __real_fread(ptr, size, count - 1, stream);
    }
    return __real_fread(ptr, size, count, stream);
}
size_t __real_fwrite(const void *ptr, size_t size, size_t count, FILE *stream);
size_t __wrap_fwrite(const void *ptr, size_t size, size_t count, FILE *stream);
size_t __wrap_fwrite(const void *ptr, size_t size, size_t count, FILE *stream)
{
    struct stat info;
    twfRequire(fstat(fileno(stream), &info) == 0 && (info.st_mode & 0777) == 0600,
               "a secret byte was written before permissions were private");
    ++private_writes;
    if (fault == kBackupStage && ++stage_writes == 2)
    {
        fault = kNone;
        return __real_fwrite(ptr, size, count - 1, stream);
    }
    if (fault == kWrite)
    {
        fault = kNone;
        return __real_fwrite(ptr, size, count - 1, stream);
    }
    return __real_fwrite(ptr, size, count, stream);
}
int __real_fflush(FILE *stream);
int __wrap_fflush(FILE *stream);
int __wrap_fflush(FILE *stream)
{
    int result = __real_fflush(stream);
    if (fault == kFlush)
    {
        fault = kNone;
        return EOF;
    }
    return result;
}
int __real_fclose(FILE *stream);
int __wrap_fclose(FILE *stream);
int __wrap_fclose(FILE *stream)
{
    if (fileno(stream) == backup_fd)
        backup_fd = -1;
    bool read_close = fault == kReadClose && (fcntl(fileno(stream), F_GETFL) & O_ACCMODE) == O_RDONLY;
    int  result     = __real_fclose(stream);
    if (fault == kClose || read_close)
    {
        fault = kNone;
        return EOF;
    }
    return result;
}
int __real_fsync(int fd);
int __wrap_fsync(int fd);
int __wrap_fsync(int fd)
{
    struct stat info;
    twfRequire(fstat(fd, &info) == 0, "sync received invalid descriptor");
    if (S_ISDIR(info.st_mode))
    {
        ++directory_syncs;
        if (use_test_clock && directory_syncs == 2)
            test_clock_us += 20000U; /* Primary replacement is already committed. */
    }
    if (fault == kSync || (fault == kDirectorySync && S_ISDIR(info.st_mode) && directory_syncs == 2))
    {
        fault = kNone;
        errno = EIO;
        return -1;
    }
    return __real_fsync(fd);
}
int __real_fchmod(int fd, mode_t mode);
int __wrap_fchmod(int fd, mode_t mode);
int __wrap_fchmod(int fd, mode_t mode)
{
    if (fail_backup_permissions && fd == backup_fd)
    {
        fail_backup_permissions = false;
        errno                   = EPERM;
        return -1;
    }
    if (fault == kPermissions)
    {
        fault = kNone;
        errno = EPERM;
        return -1;
    }
    return __real_fchmod(fd, mode);
}
int __real_rename(const char *from, const char *to);
int __wrap_rename(const char *from, const char *to);
int __wrap_rename(const char *from, const char *to)
{
    if ((fault == kBackupRename && stringEndsWith(to, ".backup")) ||
        (fault == kPrimaryRename && stringCompare(to, primary) == 0))
    {
        fault = kNone;
        errno = EIO;
        return -1;
    }
    return __real_rename(from, to);
}

static void reload(authenticationserver_tstate_t *ts)
{
    usersClear(&ts->store.users);
    memoryFree(ts->backup_path);
    ts->backup_path = NULL;
    twfRequire(authenticationserverLoadDatabase(ts), "committed database could not restart");
}

typedef struct status_lock_holder_s
{
    wrwlock_t  *lock;
    wsem_t      acquired;
    wsem_t      release;
    atomic_bool released;
} status_lock_holder_t;

static void *holdStatusWriteLock(void *argument)
{
    status_lock_holder_t *holder = argument;
    rwlockWriteLock(holder->lock);
    semaphorePost(&holder->acquired);
    semaphoreWait(&holder->release);
    atomicStore(&holder->released, true);
    rwlockWriteUnlock(holder->lock);
    return NULL;
}

static void requireStatusBusy(tunnel_t *server, wrwlock_t *lock)
{
    status_lock_holder_t holder = {.lock = lock};
    semaphoreInit(&holder.acquired, 0);
    semaphoreInit(&holder.release, 0);
    atomic_init(&holder.released, false);
    pthread_t thread;
    twfRequire(pthread_create(&thread, NULL, holdStatusWriteLock, &holder) == 0, "status lock holder creation failed");
    semaphoreWait(&holder.acquired);
    authenticationserver_status_t snapshot;
    twfRequire(authenticationserverStatusSnapshot(server, 0, &snapshot) == kAuthenticationServerStatusBusy,
               "contended status snapshot did not report busy");
    twfRequire(! atomicLoad(&holder.released), "status query waited for lock holder release");
    twfRequire(snapshot.user_count == 0 && snapshot.config_revision == 0 && ! snapshot.database_loaded,
               "busy status snapshot exposed partial state");
    semaphorePost(&holder.release);
    twfRequire(pthread_join(thread, NULL) == 0, "status lock holder join failed");
    semaphoreDestroy(&holder.release);
    semaphoreDestroy(&holder.acquired);
}

static authenticationserver_status_t statusSnapshot(tunnel_t *server)
{
    authenticationserver_status_t snapshot;
    twfRequire(authenticationserverStatusSnapshot(server, 0, &snapshot) == kAuthenticationServerStatusOk,
               "status snapshot failed");
    return snapshot;
}

static void testCommit(mode_t mask, fault_t selected, bool was_dirty)
{
    char directory[] = "/tmp/ww-auth-storage-XXXXXX";
    twfRequire(mkdtemp(directory) != NULL, "temporary directory failed");
    snprintf(primary, sizeof(primary), "%s/users.json", directory);
    mode_t previous_mask        = umask(mask);
    fault                       = kNone;
    static const char initial[] = "{\"users\":[{\"id\":42,\"password\":\"committed\"}]}";
    twfRequire(authenticationserverPrivateWrite(primary, initial, sizeof(initial) - 1), "seed save failed");
    twfRequire(chmod(primary, 0666) == 0, "could not prepare permissive existing primary");

    twf_worker_env_t env;
    twfWorkerEnvSetup(&env, 8192, 32);
    tunnel_t *server = tunnelCreate(NULL, sizeof(authenticationserver_tstate_t), 0);
    twfRequire(server != NULL, "server construction failed");
    authenticationserver_tstate_t *ts = tunnelGetState(server);
    authenticationserverInitializeExportLimit(ts);
    rwlockinit(&ts->state_lock);
    twfRequire(usersCreate(&ts->store.users), "users construction failed");
    ts->db_path = primary;
    twfRequire(authenticationserverLoadDatabase(ts), "initial database load failed");
    ts->database_loaded                  = true;
    ts->database_dirty                   = was_dirty;
    static const char protected_backup[] = "{\"users\":[{\"id\":42,\"password\":\"previous-backup\"}]}";
    if (selected == kMissingPrimary || selected == kMissingNoBackup || selected == kMissingPublication)
    {
        if (selected != kMissingNoBackup)
            twfRequire(
                authenticationserverPrivateWrite(ts->backup_path, protected_backup, sizeof(protected_backup) - 1),
                "missing-primary backup seed failed");
        twfRequire(remove(primary) == 0, "primary removal failed");
    }
    ts->normal_backups_mode = kAuthenticationServerNormalBackupsDaily;
    ts->normal_backups_path = directory;
    if (selected == kHistory)
        ts->normal_backups_path = stringDuplicate("/nonexistent-waterwall-test-directory");
    ts->normal_backups_count_limit               = 10;
    ts->auth_clients_count                       = 4;
    ts->sessions_count                           = 5; /* Retained records, not live connections. */
    ts->store.config_revision                    = 84;
    ts->store.stats_revision                     = 1902;
    authenticationserver_status_t initial_status = statusSnapshot(server);
    twfRequire(initial_status.database_loaded && initial_status.user_count == 1 &&
                   initial_status.configured_producer_count == 4 && initial_status.session_record_count == 5 &&
                   initial_status.config_revision == 84 && initial_status.stats_revision == 1902,
               "status scalars did not describe the protected server state");
    twfRequire(initial_status.primary_save_last_result == kAuthenticationServerSaveNotAttempted &&
                   ! initial_status.primary_save_last_attempt_valid && ! initial_status.primary_save_last_success_valid,
               "database load fabricated process-local save history");
    requireStatusBusy(server, &ts->state_lock);
    /* A fixture may access the collection lock solely to hold it from a distinct
     * thread. Production status still obtains the count through usersTryCount. */
    requireStatusBusy(server, &ts->store.users.lock);
    twf_line_pool_t lines;
    twfLinePoolSetup(&lines, 0, 2);
    line_t                        *line           = twfLinePoolCreateLine(&lines);
    authenticationserver_session_t session        = {.allow_user_write = true};
    const uint8_t                  correlation[4] = {0};
    static const char              addition[]     = "{\"id\":43,\"password\":\"proposed\"}";
    fault                                         = selected == kMissingPrimary || selected == kMissingNoBackup ? kNone
                                                    : selected == kMissingPublication ? kPrimaryRename
                                                                                      : selected;
    stage_writes = directory_syncs = 0;
    use_test_clock                 = true;
    test_clock_us                  = 0; /* A valid outcome timestamp, never an unavailable sentinel. */
    test_wall_time                 = 1800000000;
    rwlockWriteLock(&ts->state_lock);
    sbuf_t *response = authenticationserverDispatchRequest(kAuthenticationServerRequestTypeAddNewUser,
                                                           correlation,
                                                           server,
                                                           line,
                                                           &session,
                                                           (const uint8_t *) addition,
                                                           sizeof(addition) - 1);
    rwlockWriteUnlock(&ts->state_lock);
    const bool committed = selected == kNone || selected == kHistory || selected == kDirectorySync ||
                           selected == kMissingPrimary || selected == kMissingNoBackup;
    twfRequire(response != NULL &&
                   (((const uint8_t *) sbufGetRawPtr(response))[0] == kAuthenticationServerResponseTypeOk) == committed,
               "save result disagreed with commit boundary");
    lineReuseBuffer(line, response);
    twfRequire((usersLookupByIdentifier(&ts->store.users, 43) != NULL) == committed,
               "in-memory rollback disagreed with disk");
    authenticationserver_status_t saved_status = statusSnapshot(server);
    twfRequire(ts->database_dirty == (! committed && was_dirty) && ts->primary_checkpoint_valid == committed,
               "producer create did not preserve dirty/checkpoint facts across commit or rollback");
    twfRequire(saved_status.primary_save_last_result ==
                       (committed ? kAuthenticationServerSaveSuccess : kAuthenticationServerSaveFailure) &&
                   saved_status.primary_save_last_attempt_valid &&
                   saved_status.primary_save_last_success_valid == committed && ts->primary_save_last_attempt_ms == 0 &&
                   ts->primary_save_last_success_ms == 0,
               "primary save telemetry disagreed with the outcome at monotonic zero");
    twfRequire(saved_status.primary_save_last_attempt_age_ms == test_clock_us / 1000U &&
                   (! committed || saved_status.primary_save_last_success_age_ms == test_clock_us / 1000U),
               "postcommit directory/history work moved the primary outcome timestamp");
    twfRequire(saved_status.config_revision == (committed ? 85U : 84U) && saved_status.stats_revision == 1902 &&
                   saved_status.user_count == (committed ? 2U : 1U),
               "status did not preserve the existing save/revision ordering");
    if (selected == kMissingPrimary || selected == kMissingPublication)
    {
        char *retained = readFile(ts->backup_path);
        twfRequire(retained != NULL && strcmp(retained, protected_backup) == 0,
                   "missing primary rotated recovery backup");
        memoryFree(retained);
    }
    if (selected == kMissingNoBackup)
        twfRequire(! isFile(ts->backup_path), "missing primary fabricated a recovery backup");
    unsigned reads_before                         = wall_time_reads;
    unsigned writes_before                        = private_writes;
    test_wall_time                                = 100;
    authenticationserver_status_t after_wall_jump = statusSnapshot(server);
    twfRequire(after_wall_jump.primary_save_last_attempt_age_ms == saved_status.primary_save_last_attempt_age_ms &&
                   after_wall_jump.primary_save_last_success_age_ms == saved_status.primary_save_last_success_age_ms &&
                   wall_time_reads == reads_before && private_writes == writes_before,
               "status read used wall time or triggered persistence");
    test_clock_us = 100000;
    authenticationserver_status_t expired;
    twfRequire(authenticationserverStatusSnapshot(server, 100, &expired) == kAuthenticationServerStatusTimeout &&
                   ! expired.database_loaded && expired.user_count == 0,
               "expired status request returned sampled state");
    if (committed)
    {
        fault = kWrite;
        twfRequire(! authenticationserverSaveDatabase(ts), "second primary-save failure was not exercised");
        test_clock_us                               = 125000;
        authenticationserver_status_t failed_status = statusSnapshot(server);
        twfRequire(failed_status.primary_save_last_result == kAuthenticationServerSaveFailure &&
                       failed_status.primary_save_last_attempt_valid && failed_status.primary_save_last_success_valid &&
                       failed_status.primary_save_last_attempt_age_ms == 25 &&
                       failed_status.primary_save_last_success_age_ms == 125 && ts->primary_save_last_success_ms == 0,
                   "later failure lost the earlier successful replacement time");
    }
    if (selected == kMissingPrimary || selected == kMissingNoBackup)
    {
        char *restored = readFile(primary);
        fault          = kNone;
        twfRequire(authenticationserverSaveDatabase(ts), "normal rotation did not resume after missing primary");
        char *rotated = readFile(ts->backup_path);
        twfRequire(restored != NULL && rotated != NULL && strcmp(restored, rotated) == 0,
                   "next normal save did not rotate the restored primary");
        memoryFree(restored);
        memoryFree(rotated);
    }
    use_test_clock                                        = false;
    fault                                                 = kNone;
    const authenticationserver_save_result_t last_result  = ts->primary_save_last_result;
    const uint64_t                           last_attempt = ts->primary_save_last_attempt_ms;
    reload(ts);
    twfRequire(ts->primary_save_last_result == last_result && ts->primary_save_last_attempt_ms == last_attempt,
               "database reload changed runtime save telemetry");
    twfRequire((usersLookupByIdentifier(&ts->store.users, 43) != NULL) == committed,
               "restart resurrected a rejected addition");
    if (! committed && isFile(ts->backup_path))
    {
        twfRequire(remove(primary) == 0, "could not exercise recovery");
        reload(ts);
        twfRequire(ts->primary_save_last_result == last_result && ts->primary_save_last_attempt_ms == last_attempt,
                   "startup recovery fabricated a primary-save attempt");
        twfRequire(usersLookupByIdentifier(&ts->store.users, 42) != NULL &&
                       usersLookupByIdentifier(&ts->store.users, 43) == NULL,
                   "recovery published an uncommitted addition");
    }
    fault = kPermissions;
    twfRequire(! authenticationserverPrivateRestrict(primary), "permission refusal was ignored");
    fault = kNone;
    lineDestroy(line);
    twfLinePoolTeardown(&lines);
    usersDestroy(&ts->store.users);
    rwlockDestroy(&ts->state_lock);
    memoryFree(ts->backup_path);
    if (selected == kHistory)
        memoryFree(ts->normal_backups_path);
    tunnelDestroy(server);
    twfWorkerEnvTeardown(&env);
    umask(previous_mask);

    DIR           *dir = opendir(directory);
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL)
    {
        if (entry->d_name[0] == '.')
            continue;
        twfRequire(strstr(entry->d_name, ".tmp-") == NULL, "operation abandoned a staging file");
        char path[1024];
        snprintf(path, sizeof(path), "%s/%s", directory, entry->d_name);
        struct stat info;
        twfRequire(stat(path, &info) == 0 && (info.st_mode & 0777) == 0600, "output file remained exposed");
        twfRequire(remove(path) == 0, "fixture cleanup failed");
    }
    closedir(dir);
    twfRequire(rmdir(directory) == 0, "temporary directory remained populated");
}

static void testCalendarWeeksAndLayouts(void)
{
    char directory[] = "/tmp/ww-auth-calendar-XXXXXX";
    twfRequire(mkdtemp(directory) != NULL, "calendar directory failed");
    snprintf(primary, sizeof(primary), "%s/users.json", directory);
    char  *read_bytes  = NULL;
    size_t read_length = 0;
    twfRequire(authenticationserverPrivateRead(primary, &read_bytes, &read_length) ==
                       kAuthenticationServerPrivateReadAbsent &&
                   read_bytes == NULL && read_length == 0 &&
                   authenticationserverPrivateProbe(primary) == kAuthenticationServerPrivateReadAbsent,
               "missing private primary was not classified at open");
    int empty_fd = open(primary, O_WRONLY | O_CREAT | O_EXCL, 0600);
    twfRequire(empty_fd >= 0 && close(empty_fd) == 0 &&
                   authenticationserverPrivateRead(primary, &read_bytes, &read_length) ==
                       kAuthenticationServerPrivateReadError &&
                   authenticationserverPrivateProbe(primary) == kAuthenticationServerPrivateReadError,
               "empty primary was misclassified as missing");
    twfRequire(remove(primary) == 0 && symlink("missing-target", primary) == 0 &&
                   authenticationserverPrivateRead(primary, &read_bytes, &read_length) ==
                       kAuthenticationServerPrivateReadError &&
                   authenticationserverPrivateProbe(primary) == kAuthenticationServerPrivateReadError,
               "dangling primary symlink was misclassified as missing");
    twfRequire(remove(primary) == 0 &&
                   authenticationserverPrivateRead(directory, &read_bytes, &read_length) ==
                       kAuthenticationServerPrivateReadError &&
                   authenticationserverPrivateProbe(directory) == kAuthenticationServerPrivateReadError,
               "nonregular primary was accepted");
    authenticationserver_tstate_t ts = {0};
    authenticationserverInitializeExportLimit(&ts);
    rwlockinit(&ts.state_lock);
    twfRequire(usersCreate(&ts.store.users), "calendar users creation failed");
    ts.db_path                   = primary;
    static const char *layouts[] = {
        "{\"password\":{\"id\":1,\"password\":\"one\"}}",
        "{\"pass\":{\"id\":1,\"pass\":\"one\"}}",
        "{\"password\":{\"id\":1,\"password\":\"one\"},\"pass\":{\"id\":2,\"password\":\"two\"}}",
        "{\"users\":[{\"id\":1,\"password\":\"one\"}],\"pass\":{}}",
        "[{\"id\":1,\"pass\":\"one\"}]",
        "{\"id\":1,\"password\":\"one\"}",
        "{\"alice\":{\"id\":1,\"pass\":\"one\"}}\r\n\t "};
    for (size_t i = 0; i < sizeof(layouts) / sizeof(layouts[0]); ++i)
    {
        twfRequire(authenticationserverPrivateWrite(primary, layouts[i], strlen(layouts[i])), "layout seed failed");
        if (ts.backup_path != NULL)
        {
            memoryFree(ts.backup_path);
            ts.backup_path = NULL;
        }
        usersClear(&ts.store.users);
        twfRequire(authenticationserverLoadDatabase(&ts) && usersCount(&ts.store.users) == (i == 2 ? 2U : 1U),
                   "server required-ID validation misclassified name map");
    }
    const char *old_tz   = getenv("TZ");
    char       *saved_tz = old_tz == NULL ? NULL : stringDuplicate(old_tz);
    twfRequire(setenv("TZ", "STD0DST,M3.3.3/0,M11.1.3/0", 1) == 0, "calendar timezone setup failed");
    tzset();
    ts.database_loaded            = true;
    ts.normal_backups_mode        = kAuthenticationServerNormalBackupsWeekly;
    ts.normal_backups_path        = directory;
    ts.normal_backups_count_limit = 10;
    static const struct
    {
        int      year, month, day;
        uint64_t slot;
    } dates[]      = {{2026, 3, 16, 20260316},
                      {2026, 3, 18, 20260316},
                      {2026, 3, 22, 20260316},
                      {2026, 11, 2, 20261102},
                      {2026, 11, 4, 20261102},
                      {2026, 11, 8, 20261102},
                      {2026, 12, 28, 20261228},
                      {2027, 1, 1, 20261228},
                      {2027, 1, 3, 20261228}};
    use_test_clock = true;
    for (size_t i = 0; i < sizeof(dates) / sizeof(dates[0]); ++i)
    {
        struct tm local = {.tm_year  = dates[i].year - 1900,
                           .tm_mon   = dates[i].month - 1,
                           .tm_mday  = dates[i].day,
                           .tm_hour  = 12,
                           .tm_isdst = -1};
        test_wall_time  = mktime(&local);
        twfRequire(test_wall_time != (time_t) -1 && authenticationserverSaveDatabase(&ts) &&
                       ts.normal_backups_last_slot == dates[i].slot,
                   "weekly backup used elapsed days instead of local calendar week");
    }
    use_test_clock = false;
    if (saved_tz != NULL)
        twfRequire(setenv("TZ", saved_tz, 1) == 0, "calendar timezone restore failed");
    else
        twfRequire(unsetenv("TZ") == 0, "calendar timezone removal failed");
    tzset();
    memoryFree(saved_tz);
    memoryFree(ts.backup_path);
    usersDestroy(&ts.store.users);
    rwlockDestroy(&ts.state_lock);
    DIR           *dir = opendir(directory);
    struct dirent *entry;
    unsigned       snapshots = 0;
    while ((entry = readdir(dir)) != NULL)
    {
        if (entry->d_name[0] == '.')
            continue;
        if (stringStartsWith(entry->d_name, "authenticationserver-"))
            ++snapshots;
        char path[1024];
        snprintf(path, sizeof(path), "%s/%s", directory, entry->d_name);
        twfRequire(remove(path) == 0, "calendar cleanup failed");
    }
    twfRequire(snapshots == 3, "one local week produced multiple history snapshots");
    twfRequire(closedir(dir) == 0 && rmdir(directory) == 0, "calendar directory cleanup failed");
}

static void requirePrivateFileEquals(const char *path, const char *expected, size_t expected_length)
{
    char  *actual = NULL;
    size_t length = 0;
    twfRequire(authenticationserverPrivateReadForLoad(path, &actual, &length) ==
                       kAuthenticationServerPrivateReadSuccess &&
                   length == expected_length && memcmp(actual, expected, length) == 0,
               "rejected input changed persisted bytes");
    memorySecureZero(actual, length);
    memoryFree(actual);
}

static void testExistingBackupPermissions(void)
{
    char directory[] = "/tmp/ww-backup-permissions-XXXXXX";
    twfRequire(mkdtemp(directory) != NULL, "backup permissions directory failed");
    snprintf(primary, sizeof(primary), "%s/users.json", directory);
    char backup[520], target[520];
    snprintf(backup, sizeof(backup), "%s.backup", primary);
    snprintf(target, sizeof(target), "%s/target", directory);
    static const char             good[]      = "{\"users\":[{\"id\":42,\"password\":\"primary-secret\"}]}";
    static const char             malformed[] = "{invalid-backup";
    authenticationserver_tstate_t ts          = {.db_path = primary};
    authenticationserverInitializeExportLimit(&ts);
    twfRequire(usersCreate(&ts.store.users), "backup permissions users failed");
    twfRequire(authenticationserverPrivateWrite(primary, good, sizeof(good) - 1), "backup permissions primary failed");
    static const struct
    {
        const char *bytes;
        size_t      length;
        mode_t      mode;
    } cases[] = {{malformed, sizeof(malformed) - 1, 0644}, {"", 0, 0666}};
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i)
    {
        twfRequire(authenticationserverPrivateWrite(backup, cases[i].bytes, cases[i].length) &&
                       chmod(backup, cases[i].mode) == 0,
                   "permissive backup fixture failed");
        struct stat before, after;
        twfRequire(stat(backup, &before) == 0, "could not inspect permissive backup");
        const unsigned reads = backup_data_reads, writes = private_writes;
        reload(&ts);
        twfRequire(stat(backup, &after) == 0 && (after.st_mode & 0777) == 0600 && after.st_dev == before.st_dev &&
                       after.st_ino == before.st_ino,
                   "startup did not restrict the existing backup in place");
        twfRequire(backup_data_reads == reads && private_writes == writes && usersCount(&ts.store.users) == 1 &&
                       userPasswordMatches(usersLookupByIdentifier(&ts.store.users, 42), "primary-secret"),
                   "valid primary startup read or replaced the backup");
        requirePrivateFileEquals(backup, cases[i].bytes, cases[i].length);
        requirePrivateFileEquals(primary, good, sizeof(good) - 1);
    }
    twfRequire(remove(backup) == 0, "backup absence fixture failed");
    reload(&ts);
    struct stat info;
    twfRequire(lstat(backup, &info) != 0 && errno == ENOENT,
               "valid primary startup required or created a missing backup");

    twfRequire(authenticationserverPrivateWrite(backup, malformed, sizeof(malformed) - 1) && chmod(backup, 0644) == 0,
               "backup permission refusal fixture failed");
    struct stat primary_before, backup_before;
    twfRequire(stat(primary, &primary_before) == 0 && stat(backup, &backup_before) == 0,
               "could not inspect permission refusal files");
    memoryFree(ts.backup_path);
    ts.backup_path                = NULL;
    fail_backup_permissions       = true;
    const unsigned refused_writes = private_writes, refused_reads = backup_data_reads;
    twfRequire(! authenticationserverLoadDatabase(&ts) && ! fail_backup_permissions &&
                   private_writes == refused_writes && backup_data_reads == refused_reads &&
                   usersCount(&ts.store.users) == 1 &&
                   userPasswordMatches(usersLookupByIdentifier(&ts.store.users, 42), "primary-secret"),
               "backup permission refusal published users or wrote database files");
    twfRequire(stat(primary, &info) == 0 && info.st_dev == primary_before.st_dev &&
                   info.st_ino == primary_before.st_ino && stat(backup, &info) == 0 &&
                   info.st_dev == backup_before.st_dev && info.st_ino == backup_before.st_ino &&
                   (info.st_mode & 0777) == 0644,
               "backup permission refusal replaced a database file");
    requirePrivateFileEquals(primary, good, sizeof(good) - 1);
    requirePrivateFileEquals(backup, malformed, sizeof(malformed) - 1);

    twfRequire(remove(backup) == 0 && authenticationserverPrivateWrite(target, malformed, sizeof(malformed) - 1) &&
                   chmod(target, 0644) == 0 && symlink(target, backup) == 0,
               "backup symlink fixture failed");
    memoryFree(ts.backup_path);
    ts.backup_path = NULL;
    twfRequire(! authenticationserverLoadDatabase(&ts) && stat(target, &info) == 0 && (info.st_mode & 0777) == 0644 &&
                   lstat(backup, &info) == 0 && S_ISLNK(info.st_mode),
               "backup permission probe followed or replaced a symlink");
    requirePrivateFileEquals(target, malformed, sizeof(malformed) - 1);
    twfRequire(remove(backup) == 0 && remove(target) == 0 && mkdir(backup, 0755) == 0 && chmod(backup, 0755) == 0,
               "backup directory fixture failed");
    memoryFree(ts.backup_path);
    ts.backup_path = NULL;
    twfRequire(! authenticationserverLoadDatabase(&ts) && stat(backup, &info) == 0 && S_ISDIR(info.st_mode) &&
                   (info.st_mode & 0777) == 0755,
               "backup permission probe accepted or chmodded a directory");
    twfRequire(rmdir(backup) == 0 && mkfifo(backup, 0644) == 0 && chmod(backup, 0644) == 0,
               "backup FIFO fixture failed");
    memoryFree(ts.backup_path);
    ts.backup_path             = NULL;
    require_nonblocking_backup = true;
    twfRequire(! authenticationserverLoadDatabase(&ts) && stat(backup, &info) == 0 && S_ISFIFO(info.st_mode) &&
                   (info.st_mode & 0777) == 0644,
               "backup permission probe accepted or chmodded a FIFO");
    require_nonblocking_backup = false;
    requirePrivateFileEquals(primary, good, sizeof(good) - 1);
    memoryFree(ts.backup_path);
    usersDestroy(&ts.store.users);
    twfRequire(remove(backup) == 0 && remove(primary) == 0 && rmdir(directory) == 0,
               "backup permissions cleanup failed");
}

static void testRootDatabasePermissions(void)
{
    if (geteuid() != 0)
        return;
    char directory[] = "/tmp/ww-root-database-XXXXXX";
    twfRequire(mkdtemp(directory) != NULL, "root database directory failed");
    snprintf(primary, sizeof(primary), "%s/users.json", directory);
    char backup[520];
    snprintf(backup, sizeof(backup), "%s.backup", primary);
    static const char             good[]  = "{\"users\":[{\"id\":42,\"password\":\"root-secret\"}]}";
    static const char             older[] = "{\"users\":[{\"id\":42,\"password\":\"older-secret\"}]}";
    authenticationserver_tstate_t ts      = {.db_path = primary, .database_loaded = true};
    authenticationserverInitializeExportLimit(&ts);
    rwlockinit(&ts.state_lock);
    twfRequire(usersCreate(&ts.store.users), "root database users failed");
    const uid_t owners[] = {0, 65534};
    for (size_t i = 0; i < sizeof(owners) / sizeof(owners[0]); ++i)
    {
        twfRequire(authenticationserverPrivateWrite(primary, good, sizeof(good) - 1) &&
                       authenticationserverPrivateWrite(backup, older, sizeof(older) - 1) &&
                       chown(primary, owners[i], (gid_t) -1) == 0 && chown(backup, owners[i], (gid_t) -1) == 0 &&
                       chmod(primary, 0000) == 0 && chmod(backup, 0000) == 0,
                   "root-owned or foreign-owned database fixture failed");
        reload(&ts);
        struct stat info;
        twfRequire(stat(primary, &info) == 0 && info.st_uid == owners[i] && (info.st_mode & 0777) == 0600 &&
                       stat(backup, &info) == 0 && info.st_uid == owners[i] && (info.st_mode & 0777) == 0600,
                   "root startup rejected or changed database ownership");
        requirePrivateFileEquals(primary, good, sizeof(good) - 1);
        requirePrivateFileEquals(backup, older, sizeof(older) - 1);
        twfRequire(authenticationserverSaveDatabase(&ts), "root database save failed");
        reload(&ts);
        twfRequire(usersCount(&ts.store.users) == 1 &&
                       userPasswordMatches(usersLookupByIdentifier(&ts.store.users, 42), "root-secret") &&
                       stat(primary, &info) == 0 && (info.st_mode & 0777) == 0600 && stat(backup, &info) == 0 &&
                       (info.st_mode & 0777) == 0600,
                   "root database save and reload changed credentials or exposed files");
    }
    memoryFree(ts.backup_path);
    usersDestroy(&ts.store.users);
    rwlockDestroy(&ts.state_lock);
    twfRequire(remove(backup) == 0 && remove(primary) == 0 && rmdir(directory) == 0, "root database cleanup failed");
}

static void testMalformedDatabaseRecovery(void)
{
    static const char invalid_account[] = "{\"users\":[{\"id\":43,\"password\":42}]}";
    static const char trailing[]        = "{\"users\":[]}garbage";
    static const char concatenated[]    = "{\"users\":[]}{\"users\":[]}";
    static const char raw_nul[]         = "{\"users\":[]}\0garbage";
    static const char decoded_nul[]     = "{\"users\":[{\"id\":43,\"password\":\"abc\\u0000suffix\"}]}";
    static const char duplicate_key[]   = "{\"users\":[],\"us\\u0065rs\":[]}";
    static const char invalid_utf8[]    = "{\"users\":[{\"id\":43,\"password\":\"bad\xc0\xaf\"}]}";
    static const struct
    {
        const char *bytes;
        size_t      length;
    } invalid[]                   = {{"", 0},
                                     {"{", 1},
                                     {invalid_account, sizeof(invalid_account) - 1},
                                     {trailing, sizeof(trailing) - 1},
                                     {concatenated, sizeof(concatenated) - 1},
                                     {raw_nul, sizeof(raw_nul) - 1},
                                     {decoded_nul, sizeof(decoded_nul) - 1},
                                     {duplicate_key, sizeof(duplicate_key) - 1},
                                     {invalid_utf8, sizeof(invalid_utf8) - 1}};
    static const char seed[]      = "{\"users\":[{\"id\":42,\"password\":\"recovered-secret\"}]}";
    char              directory[] = "/tmp/waterwall-malformed-database-XXXXXX";
    twfRequire(mkdtemp(directory) != NULL, "malformed database directory failed");
    snprintf(primary, sizeof(primary), "%s/users.json", directory);
    char backup[520];
    snprintf(backup, sizeof(backup), "%s.backup", primary);
    authenticationserver_tstate_t ts = {.db_path = primary, .database_loaded = true};
    authenticationserverInitializeExportLimit(&ts);
    rwlockinit(&ts.state_lock);
    twfRequire(usersCreate(&ts.store.users), "malformed database users failed");
    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i)
    {
        twfRequire(authenticationserverPrivateWrite(primary, invalid[i].bytes, invalid[i].length) &&
                       authenticationserverPrivateWrite(backup, seed, sizeof(seed) - 1),
                   "malformed database seed failed");
        reload(&ts);
        DIR           *archives = opendir(directory);
        struct dirent *archive_entry;
        unsigned       archive_count = 0;
        bool           found_exact   = false;
        while ((archive_entry = readdir(archives)) != NULL)
            if (strstr(archive_entry->d_name, ".corrupt-") != NULL)
            {
                ++archive_count;
                char   path[1024], *bytes;
                size_t length;
                snprintf(path, sizeof(path), "%s/%s", directory, archive_entry->d_name);
                twfRequire(authenticationserverPrivateReadForLoad(path, &bytes, &length) ==
                               kAuthenticationServerPrivateReadSuccess,
                           "corruption archive unreadable");
                found_exact |= length == invalid[i].length && memcmp(bytes, invalid[i].bytes, length) == 0;
                struct stat info;
                twfRequire(stat(path, &info) == 0 && (info.st_mode & 0777) == 0600,
                           "corruption archive permissions are not private");
                memorySecureZero(bytes, length);
                memoryFree(bytes);
            }
        twfRequire(closedir(archives) == 0 && archive_count == i + 1 && found_exact,
                   "malformed bytes were not archived exactly once");
        user_t *user = usersLookupByIdentifier(&ts.store.users, 42);
        twfRequire(usersCount(&ts.store.users) == 1 && user != NULL && userPasswordMatches(user, "recovered-secret"),
                   "malformed primary bypassed recovery or changed the recovered credential");
        requirePrivateFileEquals(backup, seed, sizeof(seed) - 1);
        twfRequire(authenticationserverSaveDatabase(&ts), "save after malformed-primary recovery failed");
        twfRequire(remove(primary) == 0, "could not exercise recovery after another save");
        reload(&ts);
        user = usersLookupByIdentifier(&ts.store.users, 42);
        twfRequire(usersCount(&ts.store.users) == 1 && user != NULL && userPasswordMatches(user, "recovered-secret"),
                   "post-recovery save replaced good recovery data with malformed bytes");

        twfRequire(authenticationserverPrivateWrite(primary, invalid[i].bytes, invalid[i].length) &&
                       authenticationserverPrivateWrite(backup, invalid[i].bytes, invalid[i].length),
                   "invalid recovery seed failed");
        memoryFree(ts.backup_path);
        ts.backup_path = NULL;
        twfRequire(! authenticationserverLoadDatabase(&ts) && usersCount(&ts.store.users) == 1 &&
                       usersLookupByIdentifier(&ts.store.users, 42) != NULL,
                   "invalid primary and backup replaced previously installed users");
        requirePrivateFileEquals(primary, invalid[i].bytes, invalid[i].length);
        requirePrivateFileEquals(backup, invalid[i].bytes, invalid[i].length);
    }
    memoryFree(ts.backup_path);
    usersDestroy(&ts.store.users);
    rwlockDestroy(&ts.state_lock);
    DIR           *dir = opendir(directory);
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL)
        if (entry->d_name[0] != '.')
        {
            char path[1024];
            snprintf(path, sizeof(path), "%s/%s", directory, entry->d_name);
            twfRequire(remove(path) == 0, "malformed database file cleanup failed");
        }
    twfRequire(closedir(dir) == 0 && rmdir(directory) == 0, "malformed database cleanup failed");
}

static void testLoadFailurePreservation(void)
{
    char directory[] = "/tmp/ww-load-preservation-XXXXXX";
    twfRequire(mkdtemp(directory) != NULL, "load preservation directory failed");
    snprintf(primary, sizeof(primary), "%s/users.json", directory);
    char backup[520];
    snprintf(backup, sizeof(backup), "%s.backup", primary);
    static const char             good[]      = "{\"users\":[{\"id\":42,\"password\":\"good\"}]}";
    static const char             older[]     = "{\"users\":[{\"id\":42,\"password\":\"older\"}]}";
    static const char             malformed[] = "{truncated";
    authenticationserver_tstate_t ts          = {.db_path = primary};
    authenticationserverInitializeExportLimit(&ts);
    twfRequire(usersCreate(&ts.store.users), "load preservation users failed");
    const fault_t failures[] = {kReadOpen, kRead, kReadClose};
    for (unsigned i = 0; i < 6; ++i)
    {
        twfRequire(authenticationserverPrivateWrite(primary, good, sizeof(good) - 1) &&
                       authenticationserverPrivateWrite(backup, older, sizeof(older) - 1),
                   "load failure seed failed");
        fault                = i < 3 ? failures[i] : kNone;
        rwlock_failure_after = i < 3 ? 0 : i - 2; /* candidate, user config, user stats locks */
        twfRequire(! authenticationserverLoadDatabase(&ts) && fault == kNone && rwlock_failure_after == 0 &&
                       usersCount(&ts.store.users) == 0,
                   "native failure triggered database fallback or publication");
        requirePrivateFileEquals(primary, good, sizeof(good) - 1);
        requirePrivateFileEquals(backup, older, sizeof(older) - 1);
        memoryFree(ts.backup_path);
        ts.backup_path = NULL;
    }
    /* Valid primary is authoritative, even when backup cannot be parsed. */
    twfRequire(authenticationserverPrivateWrite(backup, malformed, sizeof(malformed) - 1) &&
                   authenticationserverLoadDatabase(&ts),
               "valid primary consulted invalid backup");
    twfRequire(userPasswordMatches(usersLookupByIdentifier(&ts.store.users, 42), "good"), "valid primary did not win");
    memoryFree(ts.backup_path);
    ts.backup_path = NULL;
    /* Policy failures preserve both files, including when backup is usable. */
    size_t allowance;
    twfRequire(userMeasureExportUpperBound(usersLookupByIdentifier(&ts.store.users, 42), &allowance) == kUserPublicOk,
               "could not measure policy fixture");
    ts.max_user_export_bytes = allowance - 1;
    twfRequire(authenticationserverPrivateWrite(backup, older, sizeof(older) - 1) &&
                   ! authenticationserverLoadDatabase(&ts),
               "oversized primary fell back to backup");
    requirePrivateFileEquals(primary, good, sizeof(good) - 1);
    requirePrivateFileEquals(backup, older, sizeof(older) - 1);
    memoryFree(ts.backup_path);
    ts.backup_path = NULL;
    twfRequire(authenticationserverPrivateWrite(primary, malformed, sizeof(malformed) - 1) &&
                   ! authenticationserverLoadDatabase(&ts),
               "oversized backup became recovery source");
    requirePrivateFileEquals(primary, malformed, sizeof(malformed) - 1);
    requirePrivateFileEquals(backup, older, sizeof(older) - 1);
    memoryFree(ts.backup_path);
    ts.backup_path = NULL;
    authenticationserverInitializeExportLimit(&ts);
    /* Missing or unreadable backups do not authorize an archive or replacement. */
    twfRequire(remove(backup) == 0 && ! authenticationserverLoadDatabase(&ts),
               "missing backup replaced malformed primary");
    requirePrivateFileEquals(primary, malformed, sizeof(malformed) - 1);
    memoryFree(ts.backup_path);
    ts.backup_path = NULL;
    twfRequire(authenticationserverPrivateWrite(backup, older, sizeof(older) - 1), "backup reseed failed");
    fail_backup_read = true;
    twfRequire(! authenticationserverLoadDatabase(&ts) && ! fail_backup_read,
               "unreadable backup replaced malformed primary");
    requirePrivateFileEquals(primary, malformed, sizeof(malformed) - 1);
    requirePrivateFileEquals(backup, older, sizeof(older) - 1);
    memoryFree(ts.backup_path);
    ts.backup_path = NULL;
    /* Each archive-stage refusal leaves the primary and validated backup intact. */
    const fault_t archive_failures[] = {kOpen, kWrite, kFlush, kSync, kClose};
    for (size_t i = 0; i < sizeof(archive_failures) / sizeof(archive_failures[0]); ++i)
    {
        fault = archive_failures[i];
        twfRequire(! authenticationserverLoadDatabase(&ts) && fault == kNone,
                   "archive failure allowed database replacement");
        requirePrivateFileEquals(primary, malformed, sizeof(malformed) - 1);
        requirePrivateFileEquals(backup, older, sizeof(older) - 1);
        memoryFree(ts.backup_path);
        ts.backup_path = NULL;
    }
    /* Collision retry cannot clobber even an existing candidate name. A failed
     * restore keeps the successful archive and the old in-memory table. */
    collide_archive = true;
    fault           = kPrimaryRename;
    twfRequire(! authenticationserverLoadDatabase(&ts) && ! collide_archive && fault == kNone &&
                   userPasswordMatches(usersLookupByIdentifier(&ts.store.users, 42), "good"),
               "failed restore published candidate or lost archive");
    requirePrivateFileEquals(primary, malformed, sizeof(malformed) - 1);
    requirePrivateFileEquals(backup, older, sizeof(older) - 1);
    requirePrivateFileEquals(collision_path, "collision", 9);
    unsigned       archived = 0;
    DIR           *dir      = opendir(directory);
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL)
        if (strstr(entry->d_name, ".corrupt-") != NULL)
        {
            char path[1024];
            snprintf(path, sizeof(path), "%s/%s", directory, entry->d_name);
            if (strcmp(path, collision_path) != 0)
            {
                requirePrivateFileEquals(path, malformed, sizeof(malformed) - 1);
                ++archived;
            }
        }
    twfRequire(closedir(dir) == 0 && archived == 1, "restoration failure lost its exact corruption archive");
    memoryFree(ts.backup_path);
    usersDestroy(&ts.store.users);
    dir = opendir(directory);
    while ((entry = readdir(dir)) != NULL)
        if (entry->d_name[0] != '.')
        {
            char path[1024];
            snprintf(path, sizeof(path), "%s/%s", directory, entry->d_name);
            twfRequire(remove(path) == 0, "load preservation file cleanup failed");
        }
    twfRequire(closedir(dir) == 0 && rmdir(directory) == 0, "load preservation cleanup failed");
}

static void testBackwardHistoryRetention(void)
{
    char directory[] = "/tmp/ww-history-backward-XXXXXX";
    twfRequire(mkdtemp(directory) != NULL, "history backward directory failed");
    snprintf(primary, sizeof(primary), "%s/users.json", directory);
    static const char seed[] = "{\"users\":[{\"id\":1,\"password\":\"history\"}]}";
    twfRequire(authenticationserverPrivateWrite(primary, seed, sizeof(seed) - 1), "history seed failed");
    authenticationserver_tstate_t ts = {.db_path                    = primary,
                                        .database_loaded            = true,
                                        .normal_backups_mode        = kAuthenticationServerNormalBackupsDaily,
                                        .normal_backups_path        = directory,
                                        .normal_backups_count_limit = 2};
    authenticationserverInitializeExportLimit(&ts);
    rwlockinit(&ts.state_lock);
    twfRequire(usersCreate(&ts.store.users) && authenticationserverLoadDatabase(&ts), "history initial load failed");
    char unrelated[1024], corrupt[1024];
    snprintf(unrelated, sizeof(unrelated), "%s/unrelated.json", directory);
    snprintf(corrupt, sizeof(corrupt), "%s.corrupt-sentinel", primary);
    twfRequire(authenticationserverPrivateWrite(unrelated, "keep", 4) &&
                   authenticationserverPrivateWrite(corrupt, "preserved", 9),
               "history unrelated seed failed");
    use_test_clock = true;
    test_clock_us  = 1000000;
    /* Dates jump backward twice, then forward; limit one pins each new current. */
    const unsigned days[]    = {22, 23, 20, 19, 24, 24, 25};
    uint64_t       last_slot = 0;
    for (unsigned i = 0; i < sizeof(days) / sizeof(days[0]); ++i)
    {
        struct tm local = {.tm_year = 126, .tm_mon = 9, .tm_mday = (int) days[i], .tm_hour = 12, .tm_isdst = -1};
        test_wall_time  = mktime(&local);
        if (i == 3)
            ts.normal_backups_count_limit = 1;
        if (i == 6)
            fail_history_remove = true;
        const user_config_patch_t patch = {.mask  = kUserConfigNotes,
                                           .notes = i == 2   ? "backward-new"
                                                    : i == 3 ? "backward-again"
                                                             : "forward"};
        twfRequire(usersPatchConfigByIdentifier(&ts.store.users, 1, &patch) == kUsersUpdateResultOk,
                   "history notes setup failed");
        twfRequire(authenticationserverSaveDatabase(&ts) &&
                       ts.primary_save_last_result == kAuthenticationServerSaveSuccess,
                   "history work changed committed primary outcome");
        if (i == 6)
        {
            twfRequire(! fail_history_remove && ts.normal_backups_last_slot == last_slot,
                       "failed history deletion consumed successful-history marker");
            twfRequire(authenticationserverSaveDatabase(&ts), "history deletion retry failed");
        }
        char period[32];
        snprintf(period, sizeof(period), "%04d%02d%02d.json", 2026, 10, days[i]);
        unsigned       count        = 0;
        bool           current      = false;
        bool           latest_other = false;
        DIR           *dir          = opendir(directory);
        struct dirent *entry;
        while ((entry = readdir(dir)) != NULL)
            if (stringStartsWith(entry->d_name, "authenticationserver-"))
            {
                ++count;
                latest_other |= stringEndsWith(entry->d_name, "20261023.json");
                if (stringEndsWith(entry->d_name, period))
                {
                    current = true;
                    if (i == 2 || i == 3)
                    {
                        char path[1024];
                        snprintf(path, sizeof(path), "%s/%s", directory, entry->d_name);
                        char *text = readFile(path);
                        twfRequire(strstr(text, i == 2 ? "backward-new" : "backward-again") != NULL,
                                   "backward current history content was discarded");
                        memoryFree(text);
                    }
                }
            }
        twfRequire(closedir(dir) == 0 && current && count <= ts.normal_backups_count_limit,
                   "new backward snapshot was pruned or retention exceeded");
        if (i == 2)
            twfRequire(latest_other, "backward pruning removed the latest other period");
        last_slot = ts.normal_backups_last_slot;
        requirePrivateFileEquals(unrelated, "keep", 4);
        requirePrivateFileEquals(corrupt, "preserved", 9);
    }
    use_test_clock = false;
    usersDestroy(&ts.store.users);
    rwlockDestroy(&ts.state_lock);
    memoryFree(ts.backup_path);
    DIR           *dir = opendir(directory);
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL)
        if (entry->d_name[0] != '.')
        {
            char path[1024];
            snprintf(path, sizeof(path), "%s/%s", directory, entry->d_name);
            twfRequire(remove(path) == 0, "history file cleanup failed");
        }
    twfRequire(closedir(dir) == 0 && rmdir(directory) == 0, "history directory cleanup failed");
}

static void testProducerJsonValidation(void)
{
    static const char trailing[]      = "{\"id\":43,\"password\":\"proposed\"}garbage";
    static const char concatenated[]  = "{\"id\":43,\"password\":\"proposed\"}{}";
    static const char raw_nul[]       = "{\"id\":43,\"password\":\"proposed\"}\0garbage";
    static const char decoded_nul[]   = "{\"id\":43,\"password\":\"abc\\u0000suffix\"}";
    static const char duplicate_key[] = "{\"id\":43,\"\\u0069d\":44,\"password\":\"proposed\"}";
    static const char invalid_utf8[]  = "{\"id\":43,\"password\":\"bad\xc0\xaf\"}";
    static const struct
    {
        const char *bytes;
        size_t      length;
    } invalid[]                     = {{trailing, sizeof(trailing) - 1},
                                       {concatenated, sizeof(concatenated) - 1},
                                       {raw_nul, sizeof(raw_nul) - 1},
                                       {decoded_nul, sizeof(decoded_nul) - 1},
                                       {duplicate_key, sizeof(duplicate_key) - 1},
                                       {invalid_utf8, sizeof(invalid_utf8) - 1}};
    static const char seed[]        = "{\"users\":[{\"id\":42,\"password\":\"committed\"}]}";
    static const char backup_seed[] = "{\"users\":[{\"id\":42,\"password\":\"prior\"}]}";
    char              directory[]   = "/tmp/waterwall-producer-json-XXXXXX";
    twfRequire(mkdtemp(directory) != NULL, "producer JSON directory failed");
    snprintf(primary, sizeof(primary), "%s/users.json", directory);
    twfRequire(authenticationserverPrivateWrite(primary, seed, sizeof(seed) - 1), "producer JSON seed failed");
    twf_worker_env_t env;
    twfWorkerEnvSetup(&env, 8192, 32);
    tunnel_t *server = tunnelCreate(NULL, sizeof(authenticationserver_tstate_t), 0);
    twfRequire(server != NULL, "producer JSON server failed");
    authenticationserver_tstate_t *ts = tunnelGetState(server);
    ts->db_path                       = primary;
    authenticationserverInitializeExportLimit(ts);
    rwlockinit(&ts->state_lock);
    twfRequire(usersCreate(&ts->store.users) && authenticationserverLoadDatabase(ts), "producer JSON load failed");
    ts->database_loaded       = true;
    ts->store.config_revision = 84;
    twfRequire(authenticationserverPrivateWrite(ts->backup_path, backup_seed, sizeof(backup_seed) - 1),
               "producer JSON backup seed failed");
    twf_line_pool_t lines;
    twfLinePoolSetup(&lines, 0, 2);
    line_t                        *line           = twfLinePoolCreateLine(&lines);
    authenticationserver_session_t session        = {.allow_user_write = true};
    const uint8_t                  correlation[4] = {0};
    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i)
    {
        const unsigned writes     = private_writes;
        const unsigned wiped      = owned_credentials_wiped;
        inspect_owned_credentials = true;
        rwlockWriteLock(&ts->state_lock);
        sbuf_t *response = authenticationserverDispatchRequest(kAuthenticationServerRequestTypeAddNewUser,
                                                               correlation,
                                                               server,
                                                               line,
                                                               &session,
                                                               (const uint8_t *) invalid[i].bytes,
                                                               (uint32_t) invalid[i].length);
        rwlockWriteUnlock(&ts->state_lock);
        inspect_owned_credentials = false;
        twfRequire(password_watch == NULL && owned_credentials_wiped == wiped + (i == 0 || i == 1 || i == 4 ? 1U : 0U),
                   "producer lexical refusal released parsed credential unwiped");
        twfRequire(response != NULL &&
                       ((const uint8_t *) sbufGetRawPtr(response))[0] == kAuthenticationServerResponseTypeError,
                   "producer accepted malformed JSON");
        lineReuseBuffer(line, response);
        twfRequire(usersCount(&ts->store.users) == 1 && usersLookupByIdentifier(&ts->store.users, 43) == NULL &&
                       usersLookupByIdentifier(&ts->store.users, 44) == NULL && ts->store.config_revision == 84 &&
                       private_writes == writes &&
                       ts->primary_save_last_result == kAuthenticationServerSaveNotAttempted,
                   "invalid producer JSON mutated users, revisions or save state");
        requirePrivateFileEquals(primary, seed, sizeof(seed) - 1);
        requirePrivateFileEquals(ts->backup_path, backup_seed, sizeof(backup_seed) - 1);
    }
    static const char proposed[] =
        "{\"id\":43,\"password\":\"diagnostic-private-password\",\"name\":\"diagnostic-private-name\","
        "\"email\":\"diagnostic-private-email\",\"notes\":\"diagnostic-private-notes\"}";
    static const struct
    {
        const char *json;
        const char *error;
        unsigned    fail_lock;
        unsigned    fail_crypto;
    } refused[] = {
        {proposed, "storage-unavailable", 1, 0},
        {proposed, "storage-unavailable", 2, 0},
        {proposed, "storage-unavailable", 3, 0},
        {proposed, "storage-unavailable", 4, 0},
        {proposed, "storage-unavailable", 5, 0},
        {proposed, "storage-unavailable", 6, 0},
        {proposed, "storage-unavailable", 0, 1},
        {proposed, "invalid-user", 0, 2},
        {"{\"password\":\"diagnostic-private-password\"}trailing", "invalid-user-json", 0, 0},
        {"{\"id\":43,\"password\":42}", "invalid-user", 0, 0},
        {"{\"id\":43,\"password\":\"diagnostic-private-password\",\"enabled\":42}", "invalid-user", 0, 0},
        {"{\"id\":42,\"password\":\"diagnostic-private-password\"}", "user-id-exists", 0, 0},
    };
    logger_handler previous_handler = loggerGetHandle(getNetworkLogger());
    loggerSetHandler(getNetworkLogger(), captureProducerLog);
    loggerSetLevel(getNetworkLogger(), LOG_LEVEL_DEBUG);
    ts->verbose = false;
    for (size_t i = 0; i < sizeof(refused) / sizeof(refused[0]); ++i)
    {
        const unsigned writes           = private_writes;
        const bool     resource_failure = refused[i].fail_lock != 0 || refused[i].fail_crypto;
        rwlock_failure_after            = refused[i].fail_lock;
        credential_failure_after        = refused[i].fail_crypto;
        producer_log_count              = 0;
        producer_log[0]                 = '\0';
        rwlockWriteLock(&ts->state_lock);
        sbuf_t *response = authenticationserverDispatchRequest(kAuthenticationServerRequestTypeAddNewUser,
                                                               correlation,
                                                               server,
                                                               line,
                                                               &session,
                                                               (const uint8_t *) refused[i].json,
                                                               (uint32_t) strlen(refused[i].json));
        rwlockWriteUnlock(&ts->state_lock);
        twfRequire(rwlock_failure_after == 0 && credential_failure_after == 0, "producer fault was not exercised");
        const size_t error_length = strlen(refused[i].error);
        twfRequire(response != NULL &&
                       sbufGetLength(response) == kAuthenticationServerResponseHeaderSize + error_length &&
                       ((const uint8_t *) sbufGetRawPtr(response))[0] == kAuthenticationServerResponseTypeError &&
                       memcmp((const uint8_t *) sbufGetRawPtr(response) + kAuthenticationServerResponseHeaderSize,
                              refused[i].error,
                              error_length) == 0,
                   "producer did not distinguish resource failure from invalid input");
        lineReuseBuffer(line, response);
        twfRequire(producer_log_count == (resource_failure ? 1U : 0U) &&
                       (! resource_failure || (producer_log_level == LOG_LEVEL_WARN &&
                                               strstr(producer_log, "AddNewUser could not") != NULL)) &&
                       strstr(producer_log, "diagnostic-private-") == NULL,
                   "producer diagnostic was missing, duplicated, unredacted or emitted for invalid input");
        twfRequire(
            usersCount(&ts->store.users) == 1 && usersLookupByIdentifier(&ts->store.users, 43) == NULL &&
                usersLookupByPassword(&ts->store.users, "committed") == usersLookupByIdentifier(&ts->store.users, 42) &&
                usersValidate(&ts->store.users) && ts->store.config_revision == 84 && ! ts->database_dirty &&
                private_writes == writes && ts->primary_save_last_result == kAuthenticationServerSaveNotAttempted,
            "producer resource or input refusal mutated accounts, indexes, revision or save state");
        requirePrivateFileEquals(primary, seed, sizeof(seed) - 1);
        requirePrivateFileEquals(ts->backup_path, backup_seed, sizeof(backup_seed) - 1);
    }
    loggerSetHandler(getNetworkLogger(), previous_handler);
    loggerSetLevel(getNetworkLogger(), DEFAULT_LOG_LEVEL);
    static const char *valid[]     = {"{\"id\":43,\"password\":\"caf\\u00e9-\\ud83d\\udd10\"}\r\n",
                                      "{\"id\":44,\"pass\":\"\xe9\x9b\xaa-\xf0\x9f\x94\x91\"}"};
    static const char *passwords[] = {"caf\xc3\xa9-\xf0\x9f\x94\x90", "\xe9\x9b\xaa-\xf0\x9f\x94\x91"};
    for (size_t i = 0; i < sizeof(valid) / sizeof(valid[0]); ++i)
    {
        rwlockWriteLock(&ts->state_lock);
        sbuf_t *response = authenticationserverDispatchRequest(kAuthenticationServerRequestTypeAddNewUser,
                                                               correlation,
                                                               server,
                                                               line,
                                                               &session,
                                                               (const uint8_t *) valid[i],
                                                               (uint32_t) strlen(valid[i]));
        rwlockWriteUnlock(&ts->state_lock);
        twfRequire(response != NULL &&
                       ((const uint8_t *) sbufGetRawPtr(response))[0] == kAuthenticationServerResponseTypeOk,
                   "producer rejected valid Unicode password or alias");
        lineReuseBuffer(line, response);
        reload(ts);
        user_t *user = usersLookupByIdentifier(&ts->store.users, 43 + i);
        twfRequire(user != NULL && userPasswordMatches(user, passwords[i]) && ts->store.config_revision == 85 + i,
                   "producer changed exact Unicode password bytes or revision");
    }
    lineDestroy(line);
    twfLinePoolTeardown(&lines);
    usersDestroy(&ts->store.users);
    rwlockDestroy(&ts->state_lock);
    twfRequire(remove(ts->backup_path) == 0 && remove(primary) == 0 && rmdir(directory) == 0,
               "producer JSON cleanup failed");
    memoryFree(ts->backup_path);
    tunnelDestroy(server);
    twfWorkerEnvTeardown(&env);
}

static void testCleanPeriodicSaving(void)
{
    char directory[] = "/tmp/waterwall-clean-save-XXXXXX";
    twfRequire(mkdtemp(directory) != NULL, "clean-save directory failed");
    snprintf(primary, sizeof(primary), "%s/users.json", directory);
    static const char seed[] = "{\"users\":[{\"id\":1,\"password\":\"one\"}]}";
    twfRequire(authenticationserverPrivateWrite(primary, seed, sizeof(seed) - 1), "clean-save seed failed");
    authenticationserver_tstate_t ts = {0};
    authenticationserverInitializeExportLimit(&ts);
    rwlockinit(&ts.state_lock);
    twfRequire(usersCreate(&ts.store.users), "clean-save users failed");
    ts.db_path = primary;
    twfRequire(authenticationserverLoadDatabase(&ts), "clean-save load failed");
    ts.database_loaded = true;
    twfRequire(authenticationserverSaveDatabase(&ts) && ts.primary_checkpoint_valid && ! ts.periodic_save_seen,
               "forced save consumed the first periodic tick");
    unsigned writes = private_writes;
    twfRequire(authenticationserverSaveDatabaseForReason(&ts, kAuthenticationServerSavePeriodic) &&
                   private_writes > writes && ts.primary_checkpoint_valid && ! ts.database_dirty,
               "first periodic save was skipped");
    const uint64_t attempt = ts.primary_save_last_attempt_ms;
    writes                 = private_writes;
    char *backup           = readFile(ts.backup_path);
    for (unsigned i = 0; i < 5; ++i)
        twfRequire(authenticationserverSaveDatabaseForReason(&ts, kAuthenticationServerSavePeriodic),
                   "clean periodic skip failed");
    char *after = readFile(ts.backup_path);
    twfRequire(private_writes == writes && ts.primary_save_last_attempt_ms == attempt && strcmp(backup, after) == 0,
               "clean skip rewrote files or save telemetry");
    memoryFree(backup);
    memoryFree(after);
    ts.database_dirty = true;
    twfRequire(authenticationserverSaveDatabaseForReason(&ts, kAuthenticationServerSavePeriodic) &&
                   private_writes > writes && ! ts.database_dirty,
               "dirty periodic save was skipped");
    writes                        = private_writes;
    ts.normal_backups_mode        = kAuthenticationServerNormalBackupsHourly;
    ts.normal_backups_path        = directory;
    ts.normal_backups_count_limit = 10;
    use_test_clock                = true;
    test_clock_us                 = 1000000;
    test_wall_time                = 1792454400;
    twfRequire(authenticationserverSaveDatabaseForReason(&ts, kAuthenticationServerSavePeriodic) &&
                   private_writes > writes && ts.normal_backups_last_slot != 0,
               "due history did not force clean save");
    writes = private_writes;
    twfRequire(authenticationserverSaveDatabaseForReason(&ts, kAuthenticationServerSavePeriodic) &&
                   private_writes == writes,
               "same history slot rewrote clean primary");
    test_wall_time += 3600;
    static char missing_directory[] = "/nonexistent-waterwall-test-directory";
    ts.normal_backups_path          = missing_directory;
    const uint64_t slot             = ts.normal_backups_last_slot;
    twfRequire(authenticationserverSaveDatabaseForReason(&ts, kAuthenticationServerSavePeriodic) &&
                   ! ts.database_dirty && ts.normal_backups_last_slot == slot && private_writes > writes,
               "history failure dirtied committed primary or consumed due slot");
    writes                 = private_writes;
    ts.normal_backups_path = directory;
    twfRequire(authenticationserverSaveDatabaseForReason(&ts, kAuthenticationServerSavePeriodic) &&
                   private_writes > writes && ts.normal_backups_last_slot != slot,
               "due history was not retried");
    ts.normal_backups_mode = kAuthenticationServerNormalBackupsDisabled;
    twfRequire(remove(primary) == 0, "clean primary removal failed");
    backup = readFile(ts.backup_path);
    twfRequire(authenticationserverSaveDatabaseForReason(&ts, kAuthenticationServerSavePeriodic),
               "clean periodic save failed to repair missing primary");
    after = readFile(ts.backup_path);
    twfRequire(strcmp(backup, after) == 0, "missing-primary clean repair changed recovery copy");
    memoryFree(backup);
    memoryFree(after);
    twfRequire(authenticationserverPrivateWrite(primary, "", 0), "empty primary fixture failed");
    backup = readFile(ts.backup_path);
    twfRequire(! authenticationserverSaveDatabaseForReason(&ts, kAuthenticationServerSavePeriodic) &&
                   ts.primary_save_last_result == kAuthenticationServerSaveFailure,
               "empty primary was a successful clean skip");
    after = readFile(ts.backup_path);
    twfRequire(strcmp(backup, after) == 0, "truncated primary rotated over healthy recovery bytes");
    memoryFree(backup);
    memoryFree(after);
    twfRequire(remove(primary) == 0 && authenticationserverSaveDatabase(&ts), "forced repair failed");
    const fault_t probe_faults[] = {kReadOpen, kProbeClose};
    for (size_t i = 0; i < sizeof(probe_faults) / sizeof(probe_faults[0]); ++i)
    {
        fault  = probe_faults[i];
        writes = private_writes;
        twfRequire(! authenticationserverSaveDatabaseForReason(&ts, kAuthenticationServerSavePeriodic) &&
                       private_writes == writes && fault == kNone &&
                       ts.primary_save_last_result == kAuthenticationServerSaveFailure,
                   "failed health probe skipped successfully or started serialization/staging");
    }
    writes = private_writes;
    twfRequire(authenticationserverSaveDatabaseForReason(&ts, kAuthenticationServerSaveShutdown) &&
                   private_writes > writes,
               "final shutdown did not force clean save");
    use_test_clock = false;
    memoryFree(ts.backup_path);
    usersDestroy(&ts.store.users);
    rwlockDestroy(&ts.state_lock);
    DIR           *dir = opendir(directory);
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL)
        if (entry->d_name[0] != '.')
        {
            char path[1024];
            snprintf(path, sizeof(path), "%s/%s", directory, entry->d_name);
            twfRequire(remove(path) == 0, "clean-save file cleanup failed");
        }
    twfRequire(closedir(dir) == 0 && rmdir(directory) == 0, "clean-save directory cleanup failed");
}

static void testOwnedDatabaseCredentialWiping(void)
{
    char directory[] = "/tmp/waterwall-database-wipe-XXXXXX";
    twfRequire(mkdtemp(directory) != NULL, "database wipe directory failed");
    snprintf(primary, sizeof(primary), "%s/users.json", directory);
    static const char seed[] = "{\"users\":[{\"id\":1,\"password\":\"owned-database-secret\"}]}";
    twfRequire(authenticationserverPrivateWrite(primary, seed, sizeof(seed) - 1), "database wipe seed failed");
    authenticationserver_tstate_t ts = {.db_path = primary, .database_loaded = true};
    authenticationserverInitializeExportLimit(&ts);
    rwlockinit(&ts.state_lock);
    twfRequire(usersCreate(&ts.store.users), "database wipe users failed");
    owned_credentials_wiped   = 0;
    inspect_owned_credentials = true;
    twfRequire(authenticationserverLoadDatabase(&ts), "database wipe load failed");
    twfRequire(owned_credentials_wiped == 2 && read_watch == NULL && password_watch == NULL,
               "loaded database source/tree credentials were not wiped");
    const fault_t faults[] = {kNone, kWrite, kReadClose};
    for (size_t i = 0; i < sizeof(faults) / sizeof(faults[0]); ++i)
    {
        const unsigned before = owned_credentials_wiped;
        fault                 = faults[i];
        twfRequire(authenticationserverSaveDatabase(&ts) == (faults[i] == kNone) &&
                       owned_credentials_wiped >= before + 2 && read_watch == NULL && password_watch == NULL &&
                       serialized_watch == NULL,
                   "database success/failure released owned credentials unwiped");
    }
    twfRequire(remove(ts.backup_path) == 0, "database wipe recovery removal failed");
    static const char *rejected[] = {"{\"users\":[{\"id\":1,\"password\":\"owned-database-secret\"}]}trailing",
                                     "{\"users\":[{\"id\":1,\"\\u0069d\":2,\"password\":\"owned-database-secret\"}]}"};
    for (size_t i = 0; i < sizeof(rejected) / sizeof(rejected[0]); ++i)
    {
        twfRequire(authenticationserverPrivateWrite(primary, rejected[i], strlen(rejected[i])),
                   "rejected database wipe seed failed");
        memoryFree(ts.backup_path);
        ts.backup_path        = NULL;
        const unsigned before = owned_credentials_wiped;
        twfRequire(! authenticationserverLoadDatabase(&ts) && owned_credentials_wiped == before + 2 &&
                       read_watch == NULL && password_watch == NULL,
                   "lexical refusal released database bytes or parsed password unwiped");
    }
    inspect_owned_credentials = false;
    fault                     = kNone;
    memoryFree(ts.backup_path);
    usersDestroy(&ts.store.users);
    rwlockDestroy(&ts.state_lock);
    twfRequire(remove(primary) == 0 && rmdir(directory) == 0, "database wipe cleanup failed");
}

int main(void)
{
    twfSetCase("authenticationserver private storage and commit");
    twfRequire(createNetworkLogger(NULL, false) != NULL && wCryptoGlobalInit() == kWCryptoOk, "runtime setup failed");
    for (fault_t selected = kNone; selected <= kMissingPublication; ++selected)
    {
        testCommit(022, selected, false);
        testCommit(000, selected, false);
    }
    testCommit(022, kNone, true);
    testCommit(022, kWrite, true);
    testProducerJsonValidation();
    testExistingBackupPermissions();
    testRootDatabasePermissions();
    testMalformedDatabaseRecovery();
    testLoadFailurePreservation();
    testBackwardHistoryRetention();
    testCalendarWeeksAndLayouts();
    testCleanPeriodicSaving();
    testOwnedDatabaseCredentialWiping();
    twfRequire(private_writes > 0, "no actual private file writes were exercised");
    wCryptoGlobalCleanup();
    networkloggerDestroy();
    return 0;
}

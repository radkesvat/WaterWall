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
    cJSON *password = cJSON_GetObjectItemCaseSensitive(row, "password");
    if (cJSON_IsString(password))
    {
        twfRequire(password_watch == NULL, "prior database JSON password not released");
        password_watch        = password->valuestring;
        password_watch_length = strlen(password_watch);
    }
}

cJSON *__real_cJSON_ParseWithLength(const char *text, size_t length);
cJSON *__wrap_cJSON_ParseWithLength(const char *text, size_t length);
cJSON *__wrap_cJSON_ParseWithLength(const char *text, size_t length)
{
    cJSON *json = __real_cJSON_ParseWithLength(text, length);
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
        if (fault == kOpen)
        {
            fault = kNone;
            errno = EIO;
            return -1;
        }
    }
    if (fault == kReadOpen && strcmp(path, primary) == 0 && (flags & O_ACCMODE) == O_RDONLY)
    {
        fault = kNone;
        errno = EIO;
        return -1;
    }
    return __real_open(path, flags, mode);
}
int __real_close(int fd);
int __wrap_close(int fd);
int __wrap_close(int fd)
{
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
    rwlockinit(&ts.state_lock);
    twfRequire(usersCreate(&ts.store.users), "calendar users creation failed");
    ts.db_path                   = primary;
    static const char *layouts[] = {
        "{\"password\":{\"id\":1,\"password\":\"one\"}}",
        "{\"pass\":{\"id\":1,\"pass\":\"one\"}}",
        "{\"password\":{\"id\":1,\"password\":\"one\"},\"pass\":{\"id\":2,\"password\":\"two\"}}",
        "{\"users\":[{\"id\":1,\"password\":\"one\"}],\"pass\":{}}"};
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

static void testCleanPeriodicSaving(void)
{
    char directory[] = "/tmp/waterwall-clean-save-XXXXXX";
    twfRequire(mkdtemp(directory) != NULL, "clean-save directory failed");
    snprintf(primary, sizeof(primary), "%s/users.json", directory);
    static const char seed[] = "{\"users\":[{\"id\":1,\"password\":\"one\"}]}";
    twfRequire(authenticationserverPrivateWrite(primary, seed, sizeof(seed) - 1), "clean-save seed failed");
    authenticationserver_tstate_t ts = {0};
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
    twfRequire(! authenticationserverSaveDatabaseForReason(&ts, kAuthenticationServerSavePeriodic) &&
                   ts.primary_save_last_result == kAuthenticationServerSaveFailure,
               "empty primary was a successful clean skip");
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
    rwlockinit(&ts.state_lock);
    twfRequire(usersCreate(&ts.store.users), "database wipe users failed");
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
    inspect_owned_credentials = false;
    fault                     = kNone;
    memoryFree(ts.backup_path);
    usersDestroy(&ts.store.users);
    rwlockDestroy(&ts.state_lock);
    char backup[520];
    snprintf(backup, sizeof(backup), "%s.backup", primary);
    twfRequire(remove(backup) == 0 && remove(primary) == 0 && rmdir(directory) == 0, "database wipe cleanup failed");
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
    testCalendarWeeksAndLayouts();
    testCleanPeriodicSaving();
    testOwnedDatabaseCredentialWiping();
    twfRequire(private_writes > 0, "no actual private file writes were exercised");
    wCryptoGlobalCleanup();
    networkloggerDestroy();
    return 0;
}

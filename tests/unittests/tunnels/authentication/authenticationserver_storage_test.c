/* CTest: waterwall.authenticationserver_storage_unit
 * Fault actual file operations, execute AddNewUser and reload primary/recovery. */
#include "AuthenticationServer/structure.h"
#include "common/private_file.h"
#include "fixtures/failure/tunnel_line_failure_harness.h"
#include "loggers/network_logger.h"

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
    kPermissions
} fault_t;
static fault_t  fault;
static char     primary[512];
static unsigned private_writes;
static unsigned stage_writes, directory_syncs;

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
        if (fault == kOpen)
        {
            fault = kNone;
            errno = EIO;
            return -1;
        }
    }
    return __real_open(path, flags, mode);
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
    int result = __real_fclose(stream);
    if (fault == kClose)
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
    if (fault == kSync || (fault == kDirectorySync && S_ISDIR(info.st_mode) && ++directory_syncs == 2))
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

static void testCommit(mode_t mask, fault_t selected)
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
    ts->database_loaded     = true;
    ts->normal_backups_mode = kAuthenticationServerNormalBackupsDaily;
    ts->normal_backups_path = directory;
    if (selected == kHistory)
        ts->normal_backups_path = stringDuplicate("/nonexistent-waterwall-test-directory");
    ts->normal_backups_count_limit = 10;
    twf_line_pool_t lines;
    twfLinePoolSetup(&lines, 0, 2);
    line_t                        *line           = twfLinePoolCreateLine(&lines);
    authenticationserver_session_t session        = {.allow_user_write = true};
    const uint8_t                  correlation[4] = {0};
    static const char              addition[]     = "{\"id\":43,\"password\":\"proposed\"}";
    fault                                         = selected;
    stage_writes = directory_syncs = 0;
    rwlockWriteLock(&ts->state_lock);
    sbuf_t *response = authenticationserverDispatchRequest(kAuthenticationServerRequestTypeAddNewUser,
                                                           correlation,
                                                           server,
                                                           line,
                                                           &session,
                                                           (const uint8_t *) addition,
                                                           sizeof(addition) - 1);
    rwlockWriteUnlock(&ts->state_lock);
    const bool committed = selected == kNone || selected == kHistory || selected == kDirectorySync;
    twfRequire(response != NULL &&
                   (((const uint8_t *) sbufGetRawPtr(response))[0] == kAuthenticationServerResponseTypeOk) == committed,
               "save result disagreed with commit boundary");
    lineReuseBuffer(line, response);
    twfRequire((usersLookupByIdentifier(&ts->store.users, 43) != NULL) == committed,
               "in-memory rollback disagreed with disk");
    fault = kNone;
    reload(ts);
    twfRequire((usersLookupByIdentifier(&ts->store.users, 43) != NULL) == committed,
               "restart resurrected a rejected addition");
    if (! committed && isFile(ts->backup_path))
    {
        twfRequire(remove(primary) == 0, "could not exercise recovery");
        reload(ts);
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

int main(void)
{
    twfSetCase("authenticationserver private storage and commit");
    twfRequire(createNetworkLogger(NULL, false) != NULL && wCryptoGlobalInit() == kWCryptoOk, "runtime setup failed");
    for (fault_t selected = kNone; selected <= kDirectorySync; ++selected)
    {
        testCommit(022, selected);
        testCommit(000, selected);
    }
    twfRequire(private_writes > 0, "no actual private file writes were exercised");
    wCryptoGlobalCleanup();
    networkloggerDestroy();
    return 0;
}

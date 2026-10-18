/* CTest: waterwall.authenticationserver_audit_writer_unit
 * Real private files, retention, process ownership, and checked I/O failures. */
#include "AuthenticationServer/audit_writer.h"
#include "fixtures/assertions.h"
#include "wwapi.h"

#include <sys/wait.h>

typedef enum audit_test_fault_e
{
    kAuditTestNone,
    kAuditTestWrite,
    kAuditTestFlush,
    kAuditTestRename,
    kAuditTestClose
} audit_test_fault_t;
static audit_test_fault_t audit_fault;

size_t __real_fwrite(const void *, size_t, size_t, FILE *);
size_t __wrap_fwrite(const void *, size_t, size_t, FILE *);
size_t __wrap_fwrite(const void *data, size_t size, size_t count, FILE *stream)
{
    struct stat info;
    twfRequire(fstat(fileno(stream), &info) == 0 && (info.st_mode & 0777) == 0600,
               "audit data was written before private permissions");
    if (audit_fault == kAuditTestWrite)
    {
        audit_fault = kAuditTestNone;
        errno       = EIO;
        return __real_fwrite(data, size, count - 1, stream);
    }
    return __real_fwrite(data, size, count, stream);
}

int __real_fflush(FILE *);
int __wrap_fflush(FILE *);
int __wrap_fflush(FILE *stream)
{
    int result = __real_fflush(stream);
    if (audit_fault == kAuditTestFlush)
    {
        audit_fault = kAuditTestNone;
        errno       = ENOSPC;
        return EOF;
    }
    return result;
}

int __real_rename(const char *, const char *);
int __wrap_rename(const char *, const char *);
int __wrap_rename(const char *from, const char *to)
{
    if (audit_fault == kAuditTestRename)
    {
        audit_fault = kAuditTestNone;
        errno       = EACCES;
        return -1;
    }
    return __real_rename(from, to);
}

int __real_fclose(FILE *);
int __wrap_fclose(FILE *);
int __wrap_fclose(FILE *stream)
{
    int result = __real_fclose(stream);
    if (audit_fault == kAuditTestClose)
    {
        audit_fault = kAuditTestNone;
        errno       = EIO;
        return EOF;
    }
    return result;
}

static void auditTestContents(const char *path, const char *expected)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    twfRequire(fd >= 0, "audit file missing");
    struct stat info;
    twfRequire(fstat(fd, &info) == 0 && S_ISREG(info.st_mode) && (info.st_mode & 0777) == 0600,
               "audit file is not private and regular");
    char    content[256] = {0};
    ssize_t length       = read(fd, content, sizeof(content) - 1);
    twfRequire(length >= 0 && (size_t) length == strlen(expected) && strcmp(content, expected) == 0,
               "audit contents or retention order mismatch");
    twfRequire(close(fd) == 0, "audit reader close failed");
}

static void auditTestPut(const char *path, const char *content)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    twfRequire(fd >= 0 && write(fd, content, strlen(content)) == (ssize_t) strlen(content) && close(fd) == 0,
               "audit setup write failed");
}

static void auditTestAppend(authenticationserver_audit_writer_t *writer, unsigned index)
{
    char                               record[32];
    int                                length = snprintf(record, sizeof(record), "{\"i\":%u}\n", index);
    authenticationserver_audit_error_t error;
    twfRequire(authenticationserverAuditWriterAppend(writer, record, (size_t) length, &error) &&
                   error.code == kAuthenticationServerAuditErrorNone && error.native_error == 0,
               "valid audit record failed");
}

static void auditTestRetention(const char *directory)
{
    char path[512], archive[544];
    snprintf(path, sizeof(path), "%s/retention.jsonl", directory);
    authenticationserver_audit_error_t   error;
    authenticationserver_audit_writer_t *writer = authenticationserverAuditWriterOpen(path, 16, 3, &error);
    twfRequire(writer != NULL, "audit writer open failed");
    twfRequire(authenticationserverAuditWriterOpen(path, 16, 3, &error) == NULL &&
                   error.code == kAuthenticationServerAuditErrorOpen,
               "two writer instances shared an audit path");
    pid_t child = fork();
    twfRequire(child >= 0, "audit lock process fork failed");
    if (child == 0)
    {
        authenticationserver_audit_writer_t *duplicate = authenticationserverAuditWriterOpen(path, 16, 3, &error);
        _exit(duplicate == NULL ? 0 : 1);
    }
    int status;
    twfRequire(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0,
               "a second process shared an audit path");
    for (unsigned i = 0; i < 7; ++i)
        auditTestAppend(writer, i);
    auditTestContents(path, "{\"i\":6}\n");
    snprintf(archive, sizeof(archive), "%s.1", path);
    auditTestContents(archive, "{\"i\":4}\n{\"i\":5}\n");
    snprintf(archive, sizeof(archive), "%s.2", path);
    auditTestContents(archive, "{\"i\":2}\n{\"i\":3}\n");
    snprintf(archive, sizeof(archive), "%s.3", path);
    twfRequire(access(archive, F_OK) != 0 && errno == ENOENT, "audit exceeded retained file count");
    twfRequire(authenticationserverAuditWriterClose(writer, &error), "audit close failed");
    writer = authenticationserverAuditWriterOpen(path, 16, 3, &error);
    twfRequire(writer != NULL, "completed audit file could not reopen");
    auditTestAppend(writer, 7);
    twfRequire(authenticationserverAuditWriterClose(writer, &error), "reopened audit close failed");
    auditTestContents(path, "{\"i\":6}\n{\"i\":7}\n");
    snprintf(archive, sizeof(archive), "%s.lock", path);
    auditTestContents(archive, "");
}

static void auditTestInvalidFiles(const char *directory)
{
    char                               path[512], target[512], related[544];
    authenticationserver_audit_error_t error;
    snprintf(target, sizeof(target), "%s/target", directory);
    auditTestPut(target, "{}\n");
    snprintf(path, sizeof(path), "%s/symlink", directory);
    twfRequire(symlink(target, path) == 0, "audit symlink setup failed");
    twfRequire(authenticationserverAuditWriterOpen(path, 32, 2, &error) == NULL, "audit followed a symlink");
    auditTestContents(target, "{}\n");
    snprintf(path, sizeof(path), "%s/hardlink", directory);
    twfRequire(link(target, path) == 0, "audit hardlink setup failed");
    twfRequire(authenticationserverAuditWriterOpen(path, 32, 2, &error) == NULL &&
                   error.code == kAuthenticationServerAuditErrorInvalidFile,
               "audit accepted a hardlink alias");
    twfRequire(unlink(path) == 0, "audit hardlink cleanup failed");
    snprintf(path, sizeof(path), "%s/fifo", directory);
    twfRequire(mkfifo(path, 0600) == 0, "audit FIFO setup failed");
    twfRequire(authenticationserverAuditWriterOpen(path, 32, 2, &error) == NULL &&
                   error.code == kAuthenticationServerAuditErrorInvalidFile,
               "audit accepted a FIFO");
    snprintf(path, sizeof(path), "%s/incomplete", directory);
    auditTestPut(path, "{\"unfinished\":");
    twfRequire(authenticationserverAuditWriterOpen(path, 32, 2, &error) == NULL &&
                   error.code == kAuthenticationServerAuditErrorInvalidFile,
               "audit appended after an incomplete record");
    auditTestContents(path, "{\"unfinished\":");
    snprintf(path, sizeof(path), "%s/missing-parent/audit", directory);
    twfRequire(authenticationserverAuditWriterOpen(path, 32, 2, &error) == NULL &&
                   error.code == kAuthenticationServerAuditErrorOpen,
               "audit accepted a missing parent directory");

    snprintf(path, sizeof(path), "%s/archive-link", directory);
    snprintf(related, sizeof(related), "%s.1", path);
    twfRequire(symlink(target, related) == 0, "archive symlink setup failed");
    twfRequire(authenticationserverAuditWriterOpen(path, 32, 2, &error) == NULL && access(path, F_OK) != 0,
               "audit accepted a symlink archive or created active file before rejecting it");
    snprintf(path, sizeof(path), "%s/lock-link", directory);
    snprintf(related, sizeof(related), "%s.lock", path);
    twfRequire(symlink(target, related) == 0, "lock symlink setup failed");
    twfRequire(authenticationserverAuditWriterOpen(path, 32, 2, &error) == NULL,
               "audit followed a symlink lock sidecar");
    auditTestContents(target, "{}\n");

    snprintf(path, sizeof(path), "%s/permissions", directory);
    auditTestPut(path, "{}\n");
    twfRequire(chmod(path, 0666) == 0, "audit old permission setup failed");
    authenticationserver_audit_writer_t *writer = authenticationserverAuditWriterOpen(path, 32, 2, &error);
    twfRequire(writer != NULL && authenticationserverAuditWriterClose(writer, &error),
               "audit could not restrict its existing file");
    auditTestContents(path, "{}\n");
}

static void auditTestFault(const char *directory, audit_test_fault_t selected,
                           authenticationserver_audit_error_code_t expected)
{
    char path[512];
    snprintf(path, sizeof(path), "%s/fault-%u", directory, (unsigned) selected);
    authenticationserver_audit_error_t   error, first;
    authenticationserver_audit_writer_t *writer = authenticationserverAuditWriterOpen(path, 8, 2, &error);
    twfRequire(writer != NULL, "fault writer open failed");
    if (selected == kAuditTestRename)
        auditTestAppend(writer, 0);
    audit_fault = selected;
    if (selected == kAuditTestClose)
    {
        twfRequire(! authenticationserverAuditWriterClose(writer, &error) && error.code == expected &&
                       error.native_error,
                   "audit ignored close failure");
        writer = authenticationserverAuditWriterOpen(path, 8, 2, &error);
        twfRequire(writer != NULL, "close failure retained the audit lock");
        twfRequire(authenticationserverAuditWriterClose(writer, &error), "audit cleanup close failed");
        return;
    }
    twfRequire(! authenticationserverAuditWriterAppend(writer, "{\"i\":1}\n", 8, &first) && first.code == expected &&
                   first.native_error,
               "audit ignored or misclassified I/O failure");
    twfRequire(! authenticationserverAuditWriterAppend(writer, "{\"i\":2}\n", 8, &error) && error.code == first.code &&
                   error.native_error == first.native_error,
               "audit continued appending after uncertain I/O");
    twfRequire(authenticationserverAuditWriterClose(writer, &error), "faulted audit cleanup failed");
    if (selected == kAuditTestWrite)
    {
        auditTestContents(path, "{\"i\":1}");
        twfRequire(authenticationserverAuditWriterOpen(path, 8, 2, &error) == NULL &&
                       error.code == kAuthenticationServerAuditErrorInvalidFile,
                   "audit reopened an incomplete failed write");
    }
    else if (selected == kAuditTestRename)
        auditTestContents(path, "{\"i\":0}\n");
    else
        auditTestContents(path, "{\"i\":1}\n");
}

int main(void)
{
    char directory[] = "/tmp/waterwall-audit-writer-XXXXXX";
    twfRequire(mkdtemp(directory) != NULL, "audit temporary directory failed");
    mode_t previous_mask = umask(0);
    auditTestRetention(directory);
    auditTestInvalidFiles(directory);
    auditTestFault(directory, kAuditTestWrite, kAuthenticationServerAuditErrorWrite);
    auditTestFault(directory, kAuditTestFlush, kAuthenticationServerAuditErrorFlush);
    auditTestFault(directory, kAuditTestRename, kAuthenticationServerAuditErrorRotate);
    auditTestFault(directory, kAuditTestClose, kAuthenticationServerAuditErrorClose);
    umask(previous_mask);
    DIR *dir = opendir(directory);
    twfRequire(dir != NULL, "audit cleanup enumeration failed");
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL)
    {
        if (entry->d_name[0] == '.')
            continue;
        char path[1024];
        snprintf(path, sizeof(path), "%s/%s", directory, entry->d_name);
        twfRequire(unlink(path) == 0, "audit cleanup unlink failed");
    }
    twfRequire(closedir(dir) == 0 && rmdir(directory) == 0, "audit temporary directory cleanup failed");
    return 0;
}

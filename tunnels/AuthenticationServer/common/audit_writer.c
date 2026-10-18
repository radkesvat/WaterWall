#include "AuthenticationServer/audit_writer.h"
#include "wwapi.h"

#ifdef OS_WIN
#include <aclapi.h>
#include <io.h>
#include <sddl.h>
#else
#include <sys/file.h>
#endif

struct authenticationserver_audit_writer_s
{
    char                             **paths;
    char                              *lock_path;
    unsigned                           max_files;
    uint64_t                           max_file_size, length;
    int                                lock_fd;
    FILE                              *stream;
    authenticationserver_audit_error_t fault;
};

static bool auditWriterError(authenticationserver_audit_error_t *error, authenticationserver_audit_error_code_t code,
                             uint32_t native_error)
{
    *error = (authenticationserver_audit_error_t) {code, native_error};
    return false;
}

static uint32_t auditWriterErrno(void)
{
    return (uint32_t) (errno == 0 ? EIO : errno);
}

static int auditWriterCloseFd(int fd)
{
#ifdef OS_WIN
    return _close(fd);
#else
    return close(fd);
#endif
}

#ifdef OS_WIN
static PSECURITY_DESCRIPTOR auditWriterSecurity(void)
{
    HANDLE               token      = NULL;
    DWORD                size       = 0;
    void                *user       = NULL;
    char                *sid        = NULL;
    PSECURITY_DESCRIPTOR descriptor = NULL;
    if (! OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
        return NULL;
    GetTokenInformation(token, TokenUser, NULL, 0, &size);
    if (size == 0)
        goto done;
    user = memoryAllocate(size);
    if (! GetTokenInformation(token, TokenUser, user, size, &size) ||
        ! ConvertSidToStringSidA(((TOKEN_USER *) user)->User.Sid, &sid))
        goto done;
    char sddl[512];
    int  count = snprintf(sddl, sizeof(sddl), "D:P(A;;FA;;;SY)(A;;FA;;;%s)", sid);
    if (count > 0 && (size_t) count < sizeof(sddl))
        ConvertStringSecurityDescriptorToSecurityDescriptorA(sddl, SDDL_REVISION_1, &descriptor, NULL);
done: {
    DWORD last_error = GetLastError();
    LocalFree(sid);
    memoryFree(user);
    CloseHandle(token);
    SetLastError(last_error);
}
    return descriptor;
}
#endif

/* Native handles are validated before fdopen, so a FIFO cannot block startup
 * and a link cannot redirect a private audit write. Every file also retains an
 * exclusive writer lock; the separate sidecar spans active-file rotation. */
static int auditWriterOpenFile(const char *path, bool create, bool exclusive, uint64_t *length,
                               authenticationserver_audit_error_t *error)
{
#ifdef OS_WIN
    PSECURITY_DESCRIPTOR security = auditWriterSecurity();
    if (security == NULL)
    {
        auditWriterError(error, kAuthenticationServerAuditErrorOpen, GetLastError());
        return -1;
    }
    SECURITY_ATTRIBUTES attributes   = {sizeof(attributes), security, FALSE};
    HANDLE              handle       = CreateFileA(path,
                                GENERIC_READ | GENERIC_WRITE | READ_CONTROL | WRITE_DAC,
                                FILE_SHARE_READ,
                                &attributes,
                                exclusive ? CREATE_NEW : (create ? OPEN_ALWAYS : OPEN_EXISTING),
                                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
                                NULL);
    DWORD               native_error = GetLastError();
    if (handle == INVALID_HANDLE_VALUE)
    {
        LocalFree(security);
        auditWriterError(error, kAuthenticationServerAuditErrorOpen, native_error);
        return -1;
    }
    BY_HANDLE_FILE_INFORMATION info;
    PACL                       acl     = NULL;
    BOOL                       present = FALSE, defaulted = FALSE;
    if (! GetFileInformationByHandle(handle, &info))
    {
        native_error = GetLastError();
        LocalFree(security);
        CloseHandle(handle);
        auditWriterError(error, kAuthenticationServerAuditErrorOpen, native_error);
        return -1;
    }
    bool valid = GetFileType(handle) == FILE_TYPE_DISK &&
                 ! (info.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY)) &&
                 info.nNumberOfLinks == 1 && GetSecurityDescriptorDacl(security, &present, &acl, &defaulted) && present;
    DWORD permission_error = valid ? SetSecurityInfo(handle,
                                                     SE_FILE_OBJECT,
                                                     DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                                                     NULL,
                                                     NULL,
                                                     acl,
                                                     NULL)
                                   : ERROR_INVALID_DATA;
    LocalFree(security);
    if (! valid || permission_error != ERROR_SUCCESS)
    {
        CloseHandle(handle);
        auditWriterError(error, kAuthenticationServerAuditErrorInvalidFile, permission_error);
        return -1;
    }
    int fd = _open_osfhandle((intptr_t) handle, _O_RDWR | _O_BINARY | _O_APPEND);
    if (fd < 0)
    {
        native_error = auditWriterErrno();
        CloseHandle(handle);
        auditWriterError(error, kAuthenticationServerAuditErrorOpen, native_error);
        return -1;
    }
    *length = ((uint64_t) info.nFileSizeHigh << 32U) | info.nFileSizeLow;
#else
    int flags = O_RDWR | O_APPEND | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK;
    if (create)
        flags |= O_CREAT;
    if (exclusive)
        flags |= O_EXCL;
    int fd = open(path, flags, S_IRUSR | S_IWUSR);
    if (fd < 0)
    {
        auditWriterError(error, kAuthenticationServerAuditErrorOpen, auditWriterErrno());
        return -1;
    }
    struct stat info;
    if (fstat(fd, &info) != 0)
    {
        uint32_t native_error = auditWriterErrno();
        close(fd);
        auditWriterError(error, kAuthenticationServerAuditErrorOpen, native_error);
        return -1;
    }
    if (! S_ISREG(info.st_mode) || info.st_nlink != 1 || info.st_size < 0)
    {
        close(fd);
        auditWriterError(error, kAuthenticationServerAuditErrorInvalidFile, EINVAL);
        return -1;
    }
    if (flock(fd, LOCK_EX | LOCK_NB) != 0 || fchmod(fd, S_IRUSR | S_IWUSR) != 0)
    {
        uint32_t native_error = auditWriterErrno();
        close(fd);
        auditWriterError(error, kAuthenticationServerAuditErrorOpen, native_error);
        return -1;
    }
    *length = (uint64_t) info.st_size;
#endif
    return fd;
}

static bool auditWriterMissing(const authenticationserver_audit_error_t *error)
{
#ifdef OS_WIN
    return error->code == kAuthenticationServerAuditErrorOpen && error->native_error == ERROR_FILE_NOT_FOUND;
#else
    return error->code == kAuthenticationServerAuditErrorOpen && error->native_error == ENOENT;
#endif
}

static bool auditWriterCheckArchive(const char *path, authenticationserver_audit_error_t *error)
{
    uint64_t length;
    int      fd = auditWriterOpenFile(path, false, false, &length, error);
    if (fd < 0)
    {
        if (! auditWriterMissing(error))
            return false;
        *error = (authenticationserver_audit_error_t) {0};
        return true;
    }
    if (auditWriterCloseFd(fd) != 0)
        return auditWriterError(error, kAuthenticationServerAuditErrorClose, auditWriterErrno());
    return true;
}

static bool auditWriterOpenActive(authenticationserver_audit_writer_t *writer, bool exclusive,
                                  authenticationserver_audit_error_t *error)
{
    int fd = auditWriterOpenFile(writer->paths[0], true, exclusive, &writer->length, error);
    if (fd < 0)
        return false;
#ifdef OS_WIN
    writer->stream = _fdopen(fd, "a+b");
#else
    writer->stream = fdopen(fd, "a+b");
#endif
    if (writer->stream == NULL)
    {
        uint32_t native_error = auditWriterErrno();
        auditWriterCloseFd(fd);
        return auditWriterError(error, kAuthenticationServerAuditErrorOpen, native_error);
    }
    if (writer->length != 0)
    {
        if (fseek(writer->stream, -1, SEEK_END) != 0)
            return auditWriterError(error, kAuthenticationServerAuditErrorOpen, auditWriterErrno());
        int tail = fgetc(writer->stream);
        if (ferror(writer->stream))
            return auditWriterError(error, kAuthenticationServerAuditErrorOpen, auditWriterErrno());
        if (tail != '\n')
            return auditWriterError(error, kAuthenticationServerAuditErrorInvalidFile, EINVAL);
    }
    if (fseek(writer->stream, 0, SEEK_END) != 0)
        return auditWriterError(error, kAuthenticationServerAuditErrorOpen, auditWriterErrno());
    return true;
}

static bool auditWriterRename(const char *from, const char *to, bool missing_ok,
                              authenticationserver_audit_error_t *error)
{
#ifdef OS_WIN
    if (MoveFileExA(from, to, MOVEFILE_REPLACE_EXISTING))
        return true;
    uint32_t native_error = GetLastError();
    if (missing_ok && native_error == ERROR_FILE_NOT_FOUND)
        return true;
#else
    if (rename(from, to) == 0)
        return true;
    uint32_t native_error = auditWriterErrno();
    if (missing_ok && native_error == ENOENT)
        return true;
#endif
    return auditWriterError(error, kAuthenticationServerAuditErrorRotate, native_error);
}

static bool auditWriterRotate(authenticationserver_audit_writer_t *writer, authenticationserver_audit_error_t *error)
{
    /* Preflight every destination before replacing any retained segment. */
    for (unsigned i = 1; i < writer->max_files; ++i)
        if (! auditWriterCheckArchive(writer->paths[i], error))
            return false;
    int closed     = fclose(writer->stream);
    writer->stream = NULL;
    if (closed != 0)
        return auditWriterError(error, kAuthenticationServerAuditErrorClose, auditWriterErrno());
    for (unsigned i = writer->max_files - 1; i > 1; --i)
        if (! auditWriterRename(writer->paths[i - 1], writer->paths[i], true, error))
            return false;
    if (! auditWriterRename(writer->paths[0], writer->paths[1], false, error))
        return false;
    return auditWriterOpenActive(writer, true, error);
}

authenticationserver_audit_writer_t *authenticationserverAuditWriterOpen(const char *path, uint64_t max_file_size,
                                                                         unsigned                            max_files,
                                                                         authenticationserver_audit_error_t *error)
{
    assert(path != NULL && path[0] != '\0' && max_file_size > 0 && max_files >= 2 && max_files <= 32 && error != NULL);
    *error                                      = (authenticationserver_audit_error_t) {0};
    authenticationserver_audit_writer_t *writer = memoryAllocate(sizeof(*writer));
    *writer =
        (authenticationserver_audit_writer_t) {.max_file_size = max_file_size, .max_files = max_files, .lock_fd = -1};
    writer->paths         = memoryAllocate(max_files * sizeof(*writer->paths));
    const size_t capacity = stringLength(path) + 32;
    writer->lock_path     = memoryAllocate(capacity);
    snprintf(writer->lock_path, capacity, "%s.lock", path);
    for (unsigned i = 0; i < max_files; ++i)
    {
        writer->paths[i] = memoryAllocate(capacity);
        if (i == 0)
            snprintf(writer->paths[i], capacity, "%s", path);
        else
            snprintf(writer->paths[i], capacity, "%s.%u", path, i);
    }
    uint64_t lock_length;
    writer->lock_fd = auditWriterOpenFile(writer->lock_path, true, false, &lock_length, error);
    if (writer->lock_fd < 0)
        goto failed;
    for (unsigned i = 1; i < max_files; ++i)
        if (! auditWriterCheckArchive(writer->paths[i], error))
            goto failed;
    if (! auditWriterOpenActive(writer, false, error))
        goto failed;
    return writer;
failed: {
    authenticationserver_audit_error_t ignored;
    authenticationserverAuditWriterClose(writer, &ignored);
}
    return NULL;
}

bool authenticationserverAuditWriterAppend(authenticationserver_audit_writer_t *writer, const char *record,
                                           size_t length, authenticationserver_audit_error_t *error)
{
    assert(writer != NULL && record != NULL && length > 0 && length <= writer->max_file_size && error != NULL);
    assert(record[length - 1] == '\n' && memchr(record, '\n', length - 1) == NULL);
    *error = writer->fault;
    if (writer->fault.code != kAuthenticationServerAuditErrorNone)
        return false;
    if (writer->length != 0 &&
        (writer->length > writer->max_file_size || length > writer->max_file_size - writer->length) &&
        ! auditWriterRotate(writer, error))
        goto failed;
    errno = 0;
    if (fwrite(record, 1, length, writer->stream) != length)
    {
        auditWriterError(error, kAuthenticationServerAuditErrorWrite, auditWriterErrno());
        goto failed;
    }
    if (fflush(writer->stream) != 0)
    {
        auditWriterError(error, kAuthenticationServerAuditErrorFlush, auditWriterErrno());
        goto failed;
    }
    writer->length += length;
    return true;
failed:
    writer->fault = *error;
    return false;
}

bool authenticationserverAuditWriterClose(authenticationserver_audit_writer_t *writer,
                                          authenticationserver_audit_error_t  *error)
{
    assert(writer != NULL && error != NULL);
    *error = (authenticationserver_audit_error_t) {0};
    if (writer->stream != NULL && fclose(writer->stream) != 0)
        auditWriterError(error, kAuthenticationServerAuditErrorClose, auditWriterErrno());
    if (writer->lock_fd >= 0 && auditWriterCloseFd(writer->lock_fd) != 0 &&
        error->code == kAuthenticationServerAuditErrorNone)
        auditWriterError(error, kAuthenticationServerAuditErrorClose, auditWriterErrno());
    for (unsigned i = 0; i < writer->max_files; ++i)
        memoryFree(writer->paths[i]);
    memoryFree(writer->paths);
    memoryFree(writer->lock_path);
    memoryFree(writer);
    return error->code == kAuthenticationServerAuditErrorNone;
}

const char *authenticationserverAuditErrorName(authenticationserver_audit_error_code_t code)
{
    switch (code)
    {
    case kAuthenticationServerAuditErrorNone:
        return "none";
    case kAuthenticationServerAuditErrorOpen:
        return "open";
    case kAuthenticationServerAuditErrorWrite:
        return "write";
    case kAuthenticationServerAuditErrorFlush:
        return "flush";
    case kAuthenticationServerAuditErrorRotate:
        return "rotate";
    case kAuthenticationServerAuditErrorClose:
        return "close";
    case kAuthenticationServerAuditErrorInvalidFile:
        return "invalid-file";
    }
    assert(false);
    return "unknown";
}

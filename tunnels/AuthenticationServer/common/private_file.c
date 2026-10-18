#include "private_file.h"
#include "loggers/network_logger.h"

#ifdef OS_WIN
#include <aclapi.h>
#include <sddl.h>

static PSECURITY_DESCRIPTOR privateSecurity(void)
{
    HANDLE               token      = NULL;
    DWORD                size       = 0;
    void                *user       = NULL;
    char                *sid        = NULL;
    PSECURITY_DESCRIPTOR descriptor = NULL;
    if (! OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
        return NULL;
    GetTokenInformation(token, TokenUser, NULL, 0, &size);
    user = memoryAllocate(size);
    if (! GetTokenInformation(token, TokenUser, user, size, &size) ||
        ! ConvertSidToStringSidA(((TOKEN_USER *) user)->User.Sid, &sid))
        goto done;
    char      sddl[512];
    const int count = snprintf(sddl, sizeof(sddl), "D:P(A;;FA;;;SY)(A;;FA;;;%s)", sid);
    if (count > 0 && (size_t) count < sizeof(sddl))
        ConvertStringSecurityDescriptorToSecurityDescriptorA(sddl, SDDL_REVISION_1, &descriptor, NULL);
done:
    LocalFree(sid);
    memoryFree(user);
    CloseHandle(token);
    return descriptor;
}
#endif

bool authenticationserverPrivateRestrict(const char *path)
{
#ifdef OS_WIN
    PSECURITY_DESCRIPTOR security = privateSecurity();
    if (security == NULL)
        return false;
    HANDLE handle = CreateFileA(
        path, READ_CONTROL | WRITE_DAC, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    PACL                       acl     = NULL;
    BOOL                       present = FALSE, defaulted = FALSE;
    BY_HANDLE_FILE_INFORMATION info;
    bool                       ok = handle != INVALID_HANDLE_VALUE && GetFileInformationByHandle(handle, &info) &&
              ! (info.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY)) &&
              GetSecurityDescriptorDacl(security, &present, &acl, &defaulted) && present &&
              SetSecurityInfo(handle,
                              SE_FILE_OBJECT,
                              DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                              NULL,
                              NULL,
                              acl,
                              NULL) == ERROR_SUCCESS;
    if (handle != INVALID_HANDLE_VALUE && ! CloseHandle(handle))
        ok = false;
    LocalFree(security);
    return ok;
#else
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0)
        return false;
    struct stat info;
    bool        ok = fstat(fd, &info) == 0 && S_ISREG(info.st_mode) && fchmod(fd, S_IRUSR | S_IWUSR) == 0;
    if (close(fd) != 0)
        ok = false;
    return ok;
#endif
}

void authenticationserverPrivateDiscard(authenticationserver_private_file_t *file)
{
    if (file->path != NULL)
    {
        if (remove(file->path) != 0)
            LOGW("AuthenticationServer: failed to remove private staging file %s", file->path);
        memoryFree(file->path);
        file->path = NULL;
    }
}

bool authenticationserverPrivateStage(authenticationserver_private_file_t *file, const char *destination,
                                      const void *data, size_t length)
{
    assert(file->path == NULL);
    static atomic_uint serial   = 0;
    const size_t       capacity = stringLength(destination) + 96U;
    char              *path     = memoryAllocate(capacity);
#ifdef OS_WIN
    PSECURITY_DESCRIPTOR security = privateSecurity();
    if (security == NULL)
    {
        memoryFree(path);
        return false;
    }
    SECURITY_ATTRIBUTES attributes = {sizeof(attributes), security, FALSE};
    HANDLE              handle     = INVALID_HANDLE_VALUE;
#else
    int fd = -1;
#endif
    for (unsigned attempt = 0; attempt < 32; ++attempt)
    {
        const unsigned sequence = (unsigned) atomicInc(&serial);
        snprintf(path, capacity, "%s.tmp-%" PRIu64 "-%u", destination, (uint64_t) getHRTimeUs(), sequence);
#ifdef OS_WIN
        handle = CreateFileA(path, GENERIC_WRITE, 0, &attributes, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
        if (handle != INVALID_HANDLE_VALUE || GetLastError() != ERROR_FILE_EXISTS)
            break;
#else
        fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, S_IRUSR | S_IWUSR);
        if (fd >= 0 || errno != EEXIST)
            break;
#endif
    }
#ifdef OS_WIN
    LocalFree(security);
    if (handle == INVALID_HANDLE_VALUE)
    {
        memoryFree(path);
        return false;
    }
    file->path            = path;
    bool           ok     = true;
    const uint8_t *cursor = data;
    while (ok && length > 0)
    {
        const DWORD wanted  = (DWORD) min(length, (size_t) MAXDWORD);
        DWORD       written = 0;
        ok                  = WriteFile(handle, cursor, wanted, &written, NULL) && written == wanted;
        cursor += written;
        length -= written;
    }
    if (ok)
        ok = FlushFileBuffers(handle) != 0;
    if (! CloseHandle(handle))
        ok = false;
#else
    if (fd < 0)
    {
        memoryFree(path);
        return false;
    }
    file->path   = path;
    FILE *stream = fdopen(fd, "wb");
    bool  ok     = stream != NULL;
    if (stream != NULL)
    {
        ok = fwrite(data, 1, length, stream) == length;
        if (fflush(stream) != 0)
            ok = false;
        if (ok && fsync(fileno(stream)) != 0)
            ok = false;
        if (fclose(stream) != 0)
            ok = false;
    }
    else
        close(fd);
#endif
    if (! ok)
        authenticationserverPrivateDiscard(file);
    return ok;
}

bool authenticationserverPrivatePublish(authenticationserver_private_file_t *file, const char *destination,
                                        uint64_t *published_ms)
{
    assert(file->path != NULL);
#ifdef OS_WIN
    if (! MoveFileExA(file->path, destination, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
        return false;
#else
    if (rename(file->path, destination) != 0)
        return false;
#endif
    if (published_ms != NULL)
        *published_ms = getHRTimeUs() / 1000U;
    memoryFree(file->path);
    file->path = NULL;
#ifndef OS_WIN
    char *parent = stringDuplicate(destination);
    char *slash  = strrchr(parent, '/');
    if (slash == NULL)
        stringCopy(parent, ".");
    else if (slash == parent)
        slash[1] = '\0';
    else
        *slash = '\0';
    int fd = open(parent, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0 || fsync(fd) != 0)
        LOGW("AuthenticationServer: replacement committed but directory sync failed for %s", destination);
    if (fd >= 0 && close(fd) != 0)
        LOGW("AuthenticationServer: directory close failed after replacement of %s", destination);
    memoryFree(parent);
#endif
    return true;
}

bool authenticationserverPrivateWrite(const char *destination, const void *data, size_t length)
{
    authenticationserver_private_file_t staged = {0};
    const bool                          ok     = authenticationserverPrivateStage(&staged, destination, data, length) &&
                    authenticationserverPrivatePublish(&staged, destination, NULL);
    authenticationserverPrivateDiscard(&staged);
    return ok;
}

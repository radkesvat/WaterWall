#include "devices/windows_driver_artifacts.h"

#include "loggers/internal_logger.h"
#include <assert.h>
#include <sddl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

enum
{
    kDriverPathCapacity = 32768
};

typedef struct driver_artifact_s
{
    wchar_t              path[kDriverPathCapacity];
    HANDLE               file;
    const unsigned char *bytes;
    size_t               length;
    bool                 created;
    bool                 in_use;
} driver_artifact_t;

static const wchar_t *const artifact_names[kWindowsDriverArtifactCount] = {
    L"wintun.dll", L"WinDivert.dll", L"WinDivert64.sys"};
static driver_artifact_t artifacts[kWindowsDriverArtifactCount];
static wchar_t           directory[kDriverPathCapacity];
static HANDLE            directory_lock;
static HANDLE           *ancestor_locks;
static size_t            ancestor_count;

static void driverReportResidue(const wchar_t *path, DWORD error)
{
    char utf8[kDriverPathCapacity * 4];
    if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, path, -1, utf8, sizeof(utf8), NULL, NULL) == 0)
    {
        LOGE("DriverArtifacts: protected artifact cleanup remains pending, code: %lu", error);
        return;
    }
    LOGW("DriverArtifacts: retained protected path %s, code: %lu", utf8, error);
}

static HANDLE driverLockDirectory(const wchar_t *path)
{
    return CreateFileW(path,
                       FILE_TRAVERSE | FILE_READ_ATTRIBUTES,
                       FILE_SHARE_READ,
                       NULL,
                       OPEN_EXISTING,
                       FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                       NULL);
}

static bool driverSameFile(const BY_HANDLE_FILE_INFORMATION *a, const BY_HANDLE_FILE_INFORMATION *b)
{
    return a->dwVolumeSerialNumber == b->dwVolumeSerialNumber && a->nFileIndexHigh == b->nFileIndexHigh &&
           a->nFileIndexLow == b->nFileIndexLow;
}

/* Directory traversal handles deny replacement, including ancestor junction
 * replacement while subsequent wide path operations are in progress. */
static bool driverPinRoot(HANDLE root_handle, wchar_t *root)
{
    DWORD length =
        GetFinalPathNameByHandleW(root_handle, root, kDriverPathCapacity, FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
    if (length < 7 || length >= kDriverPathCapacity - 100 || wcsncmp(root, L"\\\\?\\", 4) != 0 || root[5] != L':' ||
        root[6] != L'\\')
    {
        SetLastError(ERROR_BAD_PATHNAME);
        return false;
    }
    wchar_t saved   = root[7];
    root[7]         = 0;
    DWORD flags     = 0;
    BOOL  volume_ok = GetVolumeInformationW(root, NULL, 0, NULL, NULL, &flags, NULL, 0);
    root[7]         = saved;
    if (! volume_ok || ! (flags & FILE_PERSISTENT_ACLS))
    {
        SetLastError(ERROR_NOT_SUPPORTED);
        return false;
    }
    while (length > 7 && root[length - 1] == L'\\')
        root[--length] = 0;
    BY_HANDLE_FILE_INFORMATION original;
    if (! GetFileInformationByHandle(root_handle, &original))
        return false;
    for (DWORD i = 7; i <= length; ++i)
    {
        if (root[i] != L'\\' && root[i] != 0)
            continue;
        saved      = root[i];
        root[i]    = 0;
        HANDLE pin = driverLockDirectory(root);
        root[i]    = saved;
        if (pin == INVALID_HANDLE_VALUE)
            return false;
        BY_HANDLE_FILE_INFORMATION info;
        if (! GetFileInformationByHandle(pin, &info) || ! (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ||
            (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) ||
            (i == length && ! driverSameFile(&original, &info)))
        {
            CloseHandle(pin);
            SetLastError(ERROR_BAD_PATHNAME);
            return false;
        }
        HANDLE *grown = realloc(ancestor_locks, (ancestor_count + 1) * sizeof(*grown));
        if (grown == NULL)
        {
            CloseHandle(pin);
            SetLastError(ERROR_NOT_ENOUGH_MEMORY);
            return false;
        }
        ancestor_locks                   = grown;
        ancestor_locks[ancestor_count++] = pin;
    }
    if (root[length - 1] != L'\\')
        root[length++] = L'\\';
    root[length] = 0;
    return true;
}

/* Same principal/integrity boundary as the packed launcher's private files.
 * Do not inherit an ordinary TEMP directory's permissive DACL. */
static PSECURITY_DESCRIPTOR driverPrivateSecurity(void)
{
    HANDLE               token = NULL;
    void                *user = NULL, *integrity = NULL;
    wchar_t             *sid = NULL, *label = NULL;
    PSECURITY_DESCRIPTOR descriptor = NULL;
    DWORD                size       = 0;
    if (! OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
        goto done;
    GetTokenInformation(token, TokenUser, NULL, 0, &size);
    user = malloc(size);
    if (user == NULL || ! GetTokenInformation(token, TokenUser, user, size, &size) ||
        ! ConvertSidToStringSidW(((TOKEN_USER *) user)->User.Sid, &sid))
        goto done;
    GetTokenInformation(token, TokenIntegrityLevel, NULL, 0, &size);
    integrity = malloc(size);
    if (integrity == NULL || ! GetTokenInformation(token, TokenIntegrityLevel, integrity, size, &size) ||
        ! ConvertSidToStringSidW(((TOKEN_MANDATORY_LABEL *) integrity)->Label.Sid, &label))
        goto done;
    wchar_t sddl[512];
    int     count = swprintf(sddl, 512, L"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;%ls)S:(ML;OICI;NW;;;%ls)", sid, label);
    if (count < 0 || count >= 512)
        goto done;
    ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, SDDL_REVISION_1, &descriptor, NULL);
done:
    if (token != NULL)
        CloseHandle(token);
    free(user);
    free(integrity);
    LocalFree(sid);
    LocalFree(label);
    return descriptor;
}

static bool driverDirectoryCleanup(void)
{
    for (size_t i = 0; i < kWindowsDriverArtifactCount; ++i)
        if (artifacts[i].created || artifacts[i].file != NULL)
            return false;
    if (directory_lock != NULL)
    {
        if (! CloseHandle(directory_lock))
            return false;
        directory_lock = NULL;
    }
    if (directory[0] != 0)
    {
        if (! RemoveDirectoryW(directory) && GetLastError() != ERROR_PATH_NOT_FOUND &&
            GetLastError() != ERROR_FILE_NOT_FOUND)
        {
            driverReportResidue(directory, GetLastError());
            return false;
        }
        directory[0] = 0;
    }
    while (ancestor_count != 0)
    {
        if (! CloseHandle(ancestor_locks[ancestor_count - 1]))
            return false;
        --ancestor_count;
    }
    free(ancestor_locks);
    ancestor_locks = NULL;
    return true;
}

static bool driverDirectoryPrepare(void)
{
    if (directory_lock != NULL)
        return true;
    if (! driverDirectoryCleanup())
        return false;
    wchar_t root[kDriverPathCapacity];
    DWORD   length = GetTempPathW(kDriverPathCapacity, root);
    if (length == 0 || length >= kDriverPathCapacity - 100)
    {
        SetLastError(ERROR_BAD_PATHNAME);
        return false;
    }
    HANDLE                     root_lock = driverLockDirectory(root);
    BY_HANDLE_FILE_INFORMATION info;
    if (root_lock == INVALID_HANDLE_VALUE)
        return false;
    bool pinned = GetFileInformationByHandle(root_lock, &info) &&
                  ! (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) && driverPinRoot(root_lock, root);
    DWORD error = GetLastError();
    CloseHandle(root_lock);
    if (! pinned)
        goto fail;
    PSECURITY_DESCRIPTOR security = driverPrivateSecurity();
    if (security == NULL)
    {
        error = GetLastError();
        goto fail;
    }
    SECURITY_ATTRIBUTES sa      = {sizeof(sa), security, FALSE};
    bool                created = false;
    for (unsigned int attempt = 0; attempt < 32; ++attempt)
    {
        LARGE_INTEGER counter;
        if (! QueryPerformanceCounter(&counter))
            break;
        int count = swprintf(directory,
                             kDriverPathCapacity,
                             L"%lsWaterwall-drivers-%lu-%llx-%u",
                             root,
                             GetCurrentProcessId(),
                             (unsigned long long) counter.QuadPart,
                             attempt);
        if (count < 0 || count >= kDriverPathCapacity)
        {
            SetLastError(ERROR_BAD_PATHNAME);
            break;
        }
        if (CreateDirectoryW(directory, &sa))
        {
            created = true;
            break;
        }
        if (GetLastError() != ERROR_ALREADY_EXISTS)
            break;
    }
    error = GetLastError();
    LocalFree(security);
    if (! created)
    {
        directory[0] = 0;
        goto fail;
    }
    directory_lock = driverLockDirectory(directory);
    if (directory_lock == INVALID_HANDLE_VALUE)
    {
        directory_lock = NULL;
        error          = GetLastError();
        goto fail;
    }
    if (! GetFileInformationByHandle(directory_lock, &info) || (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT))
    {
        error = ERROR_BAD_PATHNAME;
        goto fail;
    }
    return true;
fail:
    driverDirectoryCleanup();
    SetLastError(error);
    return false;
}

bool windowsDriverArtifactRelease(windows_driver_artifact_t artifact)
{
    assert(artifact >= 0 && artifact < kWindowsDriverArtifactCount);
    driver_artifact_t *slot = &artifacts[artifact];
    slot->in_use            = false;
    if (slot->file != NULL)
    {
        if (! CloseHandle(slot->file))
        {
            driverReportResidue(slot->path, GetLastError());
            return false;
        }
        slot->file = NULL;
    }
    if (slot->created && ! DeleteFileW(slot->path))
    {
        DWORD error = GetLastError();
        if (error != ERROR_FILE_NOT_FOUND && error != ERROR_PATH_NOT_FOUND)
        {
            /* A loaded SYS may stay owned by Windows until reboot. Preserve
             * its protected directory; never uninstall a shared driver or queue
             * pathname deletion after our ancestor pins end at process exit. */
            driverReportResidue(slot->path, error);
            return false;
        }
    }
    memset(slot, 0, sizeof(*slot));
    driverDirectoryCleanup();
    return true;
}

bool windowsDriverArtifactPrepare(windows_driver_artifact_t artifact, const unsigned char *bytes, size_t length,
                                  const wchar_t **path)
{
    assert(artifact >= 0 && artifact < kWindowsDriverArtifactCount && bytes != NULL && path != NULL);
    driver_artifact_t *slot = &artifacts[artifact];
    *path                   = NULL;
    if (slot->in_use)
    {
        if (slot->bytes != bytes || slot->length != length)
        {
            SetLastError(ERROR_INVALID_DATA);
            return false;
        }
        *path = slot->path;
        return true;
    }
    if (length == 0 || length > MAXDWORD)
    {
        SetLastError(ERROR_INVALID_DATA);
        return false;
    }
    if (! windowsDriverArtifactRelease(artifact) || ! driverDirectoryPrepare())
        return false;
    int count = swprintf(slot->path, kDriverPathCapacity, L"%ls\\%ls", directory, artifact_names[artifact]);
    if (count < 0 || count >= kDriverPathCapacity)
    {
        SetLastError(ERROR_BAD_PATHNAME);
        return false;
    }
    HANDLE file = CreateFileW(slot->path, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE)
    {
        slot->path[0] = 0;
        return false;
    }
    slot->created                      = true;
    slot->file                         = file;
    DWORD                      written = 0;
    DWORD                      error   = ERROR_SUCCESS;
    BY_HANDLE_FILE_INFORMATION original, published;
    if (! WriteFile(file, bytes, (DWORD) length, &written, NULL))
    {
        error = GetLastError();
        goto fail;
    }
    if (written != length)
    {
        error = ERROR_WRITE_FAULT;
        goto fail;
    }
    if (! FlushFileBuffers(file) || ! GetFileInformationByHandle(file, &original) || ! CloseHandle(file))
    {
        error = GetLastError();
        goto fail;
    }
    slot->file = NULL;
    file =
        CreateFileW(slot->path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    if (file == INVALID_HANDLE_VALUE)
    {
        error = GetLastError();
        goto fail;
    }
    slot->file = file;
    if (! GetFileInformationByHandle(file, &published) || ! driverSameFile(&original, &published) ||
        (published.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) || published.nFileSizeHigh != 0 ||
        published.nFileSizeLow != length)
    {
        error = ERROR_INVALID_DATA;
        goto fail;
    }
    /* Validate once at publication. The retained read handle thereafter denies
     * write/delete sharing, so repeated preparation needs no repeated hashing. */
    unsigned char buffer[4096];
    for (size_t offset = 0; offset < length;)
    {
        DWORD want = (DWORD) (length - offset > sizeof(buffer) ? sizeof(buffer) : length - offset);
        DWORD got  = 0;
        if (! ReadFile(file, buffer, want, &got, NULL))
        {
            error = GetLastError();
            goto fail;
        }
        if (got != want || memcmp(buffer, bytes + offset, want) != 0)
        {
            error = ERROR_INVALID_DATA;
            goto fail;
        }
        offset += got;
    }
    slot->bytes  = bytes;
    slot->length = length;
    slot->in_use = true;
    *path        = slot->path;
    return true;
fail:
    windowsDriverArtifactRelease(artifact);
    SetLastError(error);
    return false;
}

void windowsDriverArtifactsShutdown(void)
{
    for (int i = 0; i < kWindowsDriverArtifactCount; ++i)
        if (! artifacts[i].in_use)
            windowsDriverArtifactRelease((windows_driver_artifact_t) i);
    driverDirectoryCleanup();
}

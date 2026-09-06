/* Exercise the actual backend's quoting, PE identification, and directory pins. */
#include "../../core/launcher/launcher_windows.c"
#include <shellapi.h>

const unsigned char waterwallPackedBytes[] = {0};
const size_t        waterwallPackedLength  = 1;
const uint64_t      waterwallRuntimeLength = 1;
#ifdef _WIN64
const char waterwallPackedTarget[] = "windows-x86_64";
#else
const char waterwallPackedTarget[] = "windows-x86";
#endif

static int checkDirectoryLocks(void)
{
    wchar_t temporary[32768], directory[32768], canonical[32768];
    DWORD   length = GetTempPathW(32768, temporary);
    if (length == 0 || length > 32700 ||
        swprintf(directory,
                 32768,
                 L"%lsWaterwall-pin-%lu-%llu",
                 temporary,
                 GetCurrentProcessId(),
                 (unsigned long long) GetTickCount64()) < 0 ||
        ! CreateDirectoryW(directory, NULL))
        return 0;
    HANDLE  root     = CreateFileW(directory,
                              FILE_READ_ATTRIBUTES,
                              FILE_SHARE_READ | FILE_SHARE_WRITE,
                              NULL,
                              OPEN_EXISTING,
                              FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                              NULL);
    HANDLE *locks    = NULL;
    size_t  count    = 0;
    int     pinned   = root != INVALID_HANDLE_VALUE && pinTemporaryRoot(root, canonical, &locks, &count);
    HANDLE  deletion = INVALID_HANDLE_VALUE, writing = INVALID_HANDLE_VALUE;
    DWORD   delete_error = 0, write_error = 0;
    if (pinned)
    {
        deletion     = CreateFileW(directory,
                               DELETE,
                               FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                               NULL,
                               OPEN_EXISTING,
                               FILE_FLAG_BACKUP_SEMANTICS,
                               NULL);
        delete_error = GetLastError();
        writing      = CreateFileW(directory,
                              FILE_WRITE_DATA,
                              FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                              NULL,
                              OPEN_EXISTING,
                              FILE_FLAG_BACKUP_SEMANTICS,
                              NULL);
        write_error  = GetLastError();
    }
    if (deletion != INVALID_HANDLE_VALUE)
        CloseHandle(deletion);
    if (writing != INVALID_HANDLE_VALUE)
        CloseHandle(writing);
    while (count != 0)
        CloseHandle(locks[--count]);
    free(locks);
    if (root != INVALID_HANDLE_VALUE)
        CloseHandle(root);
    int removed = RemoveDirectoryW(directory);
    int passed  = pinned && removed && deletion == INVALID_HANDLE_VALUE && delete_error == ERROR_SHARING_VIOLATION &&
                 writing == INVALID_HANDLE_VALUE && write_error == ERROR_SHARING_VIOLATION;
    if (! passed)
        fprintf(stderr,
                "directory pin: pinned=%d removed=%d delete error=%lu write error=%lu\n",
                pinned,
                removed,
                delete_error,
                write_error);
    return passed;
}

int main(void)
{
    const wchar_t *arguments[] = {L"fixture with spaces\\",
                                  L"",
                                  L"plain",
                                  L"with spaces",
                                  L"\"quote\"",
                                  L"trailing\\",
                                  L"back\\\\\"quote",
                                  L"\\",
                                  L"\u00e9"};
    wchar_t        command[32768];
    size_t         used = 0;
    for (size_t i = 0; i < sizeof(arguments) / sizeof(arguments[0]); ++i)
        if (! appendArgument(command, &used, arguments[i]))
            return 1;
    int       argc = 0;
    wchar_t **argv = CommandLineToArgvW(command, &argc);
    if (argv == NULL || argc != sizeof(arguments) / sizeof(arguments[0]))
        return 2;
    for (int i = 0; i < argc; ++i)
        if (wcscmp(argv[i], arguments[i]) != 0)
            return 3;
    LocalFree(argv);
    used           = 32766;
    command[32767] = L'X';
    if (appendArgument(command, &used, L"x") || command[32767] != L'X')
        return 4;
    unsigned char    tiny[512] = {0};
    IMAGE_DOS_HEADER dos       = {0};
    dos.e_magic                = IMAGE_DOS_SIGNATURE;
    dos.e_lfanew               = 64;
    memcpy(tiny, &dos, sizeof(dos));
    for (size_t length = 0; length < sizeof(tiny); ++length)
        if (validImage(tiny, length))
            return 5;
    /* Ordinary characters need no escaping: the complete quoted argument fits
     * exactly within CreateProcessW's 32767-character limit including NUL. */
    wchar_t long_argument[32765];
    for (size_t i = 0; i < 32764; ++i)
        long_argument[i] = L'a';
    long_argument[32764] = 0;
    used                 = 0;
    if (! appendArgument(command, &used, long_argument) || used != 32766 || command[used] != 0)
        return 6;
    if (appendArgument(command, &used, L""))
        return 7;
    /* A trailing backslash needs doubling and no longer fits. */
    long_argument[32762] = 0;
    long_argument[32761] = L'\\';
    command[0]           = L'x';
    used                 = 1;
    if (appendArgument(command, &used, long_argument) || used != 1)
        return 8;
    if (! checkDirectoryLocks())
        return 9;
    puts("Windows launcher argument quoting, truncated PE and directory pin checks passed");
    return 0;
}

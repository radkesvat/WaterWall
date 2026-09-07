#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif
#include "launcher.h"
#include "lazy_names.h"
#include "packed_payload.h"
#include "startup_windows.h"
#include "ww_xz_decoder.h"

#include <sddl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>

#ifndef LOAD_LIBRARY_SEARCH_SYSTEM32
#define LOAD_LIBRARY_SEARCH_SYSTEM32 0x00000800
#endif

static inline uint8_t reverse_bits(uint8_t x)
{
    x = (uint8_t) (((x & 0xF0) >> 4) | ((x & 0x0F) << 4));
    x = (uint8_t) (((x & 0xCC) >> 2) | ((x & 0x33) << 2));
    x = (uint8_t) (((x & 0xAA) >> 1) | ((x & 0x55) << 1));

    return x;
}

static inline void transform(uint8_t *data, size_t length)
{
    const uint8_t key = 0xA5; /* 10100101 */

    for (size_t i = 0; i < length; i++)
    {
        data[i] = reverse_bits(data[i]) ^ key;
    }
}

/* Lazy loading subsystem conceptually modeled on Go's internal Windows syscall
 * lazy-load architecture (LazyDLL / LazyProc), resolving system libraries from
 * System32 and procedures on first demand. Names are stored transformed and
 * decrypted lazily in local stack buffers at resolution time. */
typedef struct lazy_dll_s
{
    const uint8_t   *transf_name;
    size_t           len;
    volatile HMODULE handle;
} lazy_dll_t;

typedef struct lazy_proc_s
{
    lazy_dll_t    *dll;
    const uint8_t *transf_name;
    size_t         len;
    void *volatile address;
} lazy_proc_t;

static void *lazyProcAddress(lazy_proc_t *proc)
{
    void *addr = proc->address;
    if (addr != NULL)
        return addr;

    HMODULE module = proc->dll->handle;
    if (module == NULL)
    {
        char    dll_abuf[64];
        wchar_t dll_wbuf[64];
        if (proc->dll->len == 0 || proc->dll->len >= sizeof(dll_abuf))
            return NULL;

        memcpy(dll_abuf, proc->dll->transf_name, proc->dll->len);
        transform((uint8_t *) dll_abuf, proc->dll->len);
        dll_abuf[proc->dll->len] = '\0';

        for (size_t i = 0; i <= proc->dll->len; i++)
            dll_wbuf[i] = (wchar_t) (unsigned char) dll_abuf[i];

        module = GetModuleHandleW(dll_wbuf);
        if (module == NULL)
            module = LoadLibraryExW(dll_wbuf, NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
        if (module == NULL)
            module = LoadLibraryW(dll_wbuf);

        SecureZeroMemory(dll_abuf, sizeof(dll_abuf));
        SecureZeroMemory(dll_wbuf, sizeof(dll_wbuf));

        if (module == NULL)
            return NULL;

        HMODULE existing =
            (HMODULE) InterlockedCompareExchangePointer((void *volatile *) &proc->dll->handle, module, NULL);
        if (existing != NULL && existing != module)
        {
            FreeLibrary(module);
            module = existing;
        }
    }

    char proc_abuf[128];
    if (proc->len == 0 || proc->len >= sizeof(proc_abuf))
        return NULL;

    memcpy(proc_abuf, proc->transf_name, proc->len);
    transform((uint8_t *) proc_abuf, proc->len);
    proc_abuf[proc->len] = '\0';

    FARPROC proc_address = GetProcAddress(module, proc_abuf);
    SecureZeroMemory(proc_abuf, sizeof(proc_abuf));

    if (proc_address == NULL)
        return NULL;

    InterlockedCompareExchangePointer(&proc->address, (void *) (uintptr_t) proc_address, NULL);
    return (void *) (uintptr_t) proc_address;
}

static lazy_dll_t lazy_kernel32 = {transf_kernel32, sizeof(transf_kernel32), NULL};
static lazy_dll_t lazy_advapi32 = {transf_advapi32, sizeof(transf_advapi32), NULL};

#define LAZY_WRAPPER(ret_type, default_ret, dll, name, params, args)                                                   \
    static lazy_proc_t lazy_proc_##name = {&dll, transf_##name, sizeof(transf_##name), NULL};                          \
    typedef ret_type(WINAPI *lazy_pfn_##name) params;                                                                  \
    static inline ret_type lazy_##name params                                                                          \
    {                                                                                                                  \
        lazy_pfn_##name fn = (lazy_pfn_##name) lazyProcAddress(&lazy_proc_##name);                                     \
        if (fn == NULL)                                                                                                \
        {                                                                                                              \
            SetLastError(ERROR_PROC_NOT_FOUND);                                                                        \
            return default_ret;                                                                                        \
        }                                                                                                              \
        return fn args;                                                                                                \
    }

#define LAZY_WRAPPER_VOID(dll, name, params, args)                                                                     \
    static lazy_proc_t lazy_proc_##name = {&dll, transf_##name, sizeof(transf_##name), NULL};                          \
    typedef void(WINAPI * lazy_pfn_##name) params;                                                                     \
    static inline void lazy_##name params                                                                              \
    {                                                                                                                  \
        lazy_pfn_##name fn = (lazy_pfn_##name) lazyProcAddress(&lazy_proc_##name);                                     \
        if (fn != NULL)                                                                                                \
            fn args;                                                                                                   \
    }

LAZY_WRAPPER(BOOL, FALSE, lazy_kernel32, SetConsoleCtrlHandler, (PHANDLER_ROUTINE HandlerRoutine, BOOL Add),
             (HandlerRoutine, Add))
LAZY_WRAPPER_VOID(lazy_kernel32, Sleep, (DWORD dwMilliseconds), (dwMilliseconds))
LAZY_WRAPPER(DWORD, 0, lazy_kernel32, GetModuleFileNameW, (HMODULE hModule, LPWSTR lpFilename, DWORD nSize),
             (hModule, lpFilename, nSize))
LAZY_WRAPPER(HANDLE, NULL, lazy_kernel32, CreateFileMappingW,
             (HANDLE hFile, LPSECURITY_ATTRIBUTES lpFileMappingAttributes, DWORD flProtect, DWORD dwMaximumSizeHigh,
              DWORD dwMaximumSizeLow, LPCWSTR lpName),
             (hFile, lpFileMappingAttributes, flProtect, dwMaximumSizeHigh, dwMaximumSizeLow, lpName))
LAZY_WRAPPER(LPVOID, NULL, lazy_kernel32, MapViewOfFile,
             (HANDLE hFileMappingObject, DWORD dwDesiredAccess, DWORD dwFileOffsetHigh, DWORD dwFileOffsetLow,
              SIZE_T dwNumberOfBytesToMap),
             (hFileMappingObject, dwDesiredAccess, dwFileOffsetHigh, dwFileOffsetLow, dwNumberOfBytesToMap))
LAZY_WRAPPER(BOOL, FALSE, lazy_kernel32, UnmapViewOfFile, (LPCVOID lpBaseAddress), (lpBaseAddress))
LAZY_WRAPPER(BOOL, FALSE, lazy_kernel32, DuplicateHandle,
             (HANDLE hSourceProcessHandle, HANDLE hSourceHandle, HANDLE hTargetProcessHandle, LPHANDLE lpTargetHandle,
              DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwOptions),
             (hSourceProcessHandle, hSourceHandle, hTargetProcessHandle, lpTargetHandle, dwDesiredAccess,
              bInheritHandle, dwOptions))
LAZY_WRAPPER(BOOL, FALSE, lazy_kernel32, CloseHandle, (HANDLE hObject), (hObject))
LAZY_WRAPPER(HLOCAL, (HLOCAL) hMem, lazy_kernel32, LocalFree, (HLOCAL hMem), (hMem))
LAZY_WRAPPER(HANDLE, INVALID_HANDLE_VALUE, lazy_kernel32, CreateFileW,
             (LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes,
              DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile),
             (lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition,
              dwFlagsAndAttributes, hTemplateFile))
LAZY_WRAPPER(DWORD, 0, lazy_kernel32, GetFinalPathNameByHandleW,
             (HANDLE hFile, LPWSTR lpszFilePath, DWORD cchFilePath, DWORD dwFlags),
             (hFile, lpszFilePath, cchFilePath, dwFlags))
LAZY_WRAPPER(BOOL, FALSE, lazy_kernel32, GetVolumeInformationW,
             (LPCWSTR lpRootPathName, LPWSTR lpVolumeNameBuffer, DWORD nVolumeNameSize, LPDWORD lpVolumeSerialNumber,
              LPDWORD lpMaximumComponentLength, LPDWORD lpFileSystemFlags, LPWSTR lpFileSystemNameBuffer,
              DWORD nFileSystemNameSize),
             (lpRootPathName, lpVolumeNameBuffer, nVolumeNameSize, lpVolumeSerialNumber, lpMaximumComponentLength,
              lpFileSystemFlags, lpFileSystemNameBuffer, nFileSystemNameSize))
LAZY_WRAPPER(BOOL, FALSE, lazy_kernel32, GetFileInformationByHandle,
             (HANDLE hFile, LPBY_HANDLE_FILE_INFORMATION lpFileInformation), (hFile, lpFileInformation))
LAZY_WRAPPER(int, 0, lazy_kernel32, WideCharToMultiByte,
             (UINT CodePage, DWORD dwFlags, LPCWCH lpWideCharStr, int cchWideChar, LPSTR lpMultiByteStr,
              int cbMultiByte, LPCCH lpDefaultChar, LPBOOL lpUsedDefaultChar),
             (CodePage, dwFlags, lpWideCharStr, cchWideChar, lpMultiByteStr, cbMultiByte, lpDefaultChar,
              lpUsedDefaultChar))
LAZY_WRAPPER(BOOL, FALSE, lazy_kernel32, RemoveDirectoryW, (LPCWSTR lpPathName), (lpPathName))
LAZY_WRAPPER(BOOL, FALSE, lazy_kernel32, DeleteFileW, (LPCWSTR lpFileName), (lpFileName))
LAZY_WRAPPER(HANDLE, INVALID_HANDLE_VALUE, lazy_kernel32, FindFirstFileW,
             (LPCWSTR lpFileName, LPWIN32_FIND_DATAW lpFindFileData), (lpFileName, lpFindFileData))
LAZY_WRAPPER(BOOL, FALSE, lazy_kernel32, FindNextFileW, (HANDLE hFindFile, LPWIN32_FIND_DATAW lpFindFileData),
             (hFindFile, lpFindFileData))
LAZY_WRAPPER(BOOL, FALSE, lazy_kernel32, FindClose, (HANDLE hFindFile), (hFindFile))
LAZY_WRAPPER(BOOL, FALSE, lazy_kernel32, ReadFile,
             (HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead,
              LPOVERLAPPED lpOverlapped),
             (hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped))
LAZY_WRAPPER(BOOL, FALSE, lazy_kernel32, WriteFile,
             (HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten,
              LPOVERLAPPED lpOverlapped),
             (hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped))
LAZY_WRAPPER(BOOL, FALSE, lazy_kernel32, FlushFileBuffers, (HANDLE hFile), (hFile))
LAZY_WRAPPER(DWORD, 0, lazy_kernel32, GetTempPathW, (DWORD nBufferLength, LPWSTR lpBuffer), (nBufferLength, lpBuffer))
LAZY_WRAPPER(BOOL, FALSE, lazy_kernel32, QueryPerformanceCounter, (LARGE_INTEGER * lpPerformanceCount),
             (lpPerformanceCount))
LAZY_WRAPPER(DWORD, 0, lazy_kernel32, GetCurrentProcessId, (VOID), ())
LAZY_WRAPPER(BOOL, FALSE, lazy_kernel32, CreateDirectoryW,
             (LPCWSTR lpPathName, LPSECURITY_ATTRIBUTES lpSecurityAttributes), (lpPathName, lpSecurityAttributes))
LAZY_WRAPPER(HANDLE, INVALID_HANDLE_VALUE, lazy_kernel32, GetStdHandle, (DWORD nStdHandle), (nStdHandle))
LAZY_WRAPPER(BOOL, FALSE, lazy_kernel32, InitializeProcThreadAttributeList,
             (LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList, DWORD dwAttributeCount, DWORD dwFlags, PSIZE_T lpSize),
             (lpAttributeList, dwAttributeCount, dwFlags, lpSize))
LAZY_WRAPPER(BOOL, FALSE, lazy_kernel32, UpdateProcThreadAttribute,
             (LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList, DWORD dwFlags, DWORD_PTR Attribute, PVOID lpValue,
              SIZE_T cbSize, PVOID lpPreviousValue, PSIZE_T lpReturnSize),
             (lpAttributeList, dwFlags, Attribute, lpValue, cbSize, lpPreviousValue, lpReturnSize))
LAZY_WRAPPER_VOID(lazy_kernel32, DeleteProcThreadAttributeList, (LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList),
                  (lpAttributeList))
LAZY_WRAPPER(HANDLE, NULL, lazy_kernel32, CreateJobObjectW, (LPSECURITY_ATTRIBUTES lpJobAttributes, LPCWSTR lpName),
             (lpJobAttributes, lpName))
LAZY_WRAPPER(BOOL, FALSE, lazy_kernel32, SetInformationJobObject,
             (HANDLE hJob, JOBOBJECTINFOCLASS JobObjectInformationClass, LPVOID lpJobObjectInformation,
              DWORD cbJobObjectInformationLength),
             (hJob, JobObjectInformationClass, lpJobObjectInformation, cbJobObjectInformationLength))
LAZY_WRAPPER(BOOL, FALSE, lazy_kernel32, CreateProcessW,
             (LPCWSTR lpApplicationName, LPWSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes,
              LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags,
              LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo,
              LPPROCESS_INFORMATION lpProcessInformation),
             (lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles,
              dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation))
LAZY_WRAPPER(BOOL, FALSE, lazy_kernel32, AssignProcessToJobObject, (HANDLE hJob, HANDLE hProcess), (hJob, hProcess))
LAZY_WRAPPER(DWORD, (DWORD) -1, lazy_kernel32, ResumeThread, (HANDLE hThread), (hThread))
LAZY_WRAPPER(DWORD, WAIT_FAILED, lazy_kernel32, WaitForSingleObject, (HANDLE hHandle, DWORD dwMilliseconds),
             (hHandle, dwMilliseconds))
LAZY_WRAPPER(BOOL, FALSE, lazy_kernel32, GetExitCodeProcess, (HANDLE hProcess, LPDWORD lpExitCode),
             (hProcess, lpExitCode))
LAZY_WRAPPER(BOOL, FALSE, lazy_kernel32, TerminateProcess, (HANDLE hProcess, UINT uExitCode), (hProcess, uExitCode))
LAZY_WRAPPER_VOID(lazy_kernel32, ExitProcess, (UINT uExitCode), (uExitCode))

LAZY_WRAPPER(BOOL, FALSE, lazy_advapi32, OpenProcessToken,
             (HANDLE ProcessHandle, DWORD DesiredAccess, PHANDLE TokenHandle),
             (ProcessHandle, DesiredAccess, TokenHandle))
LAZY_WRAPPER(BOOL, FALSE, lazy_advapi32, GetTokenInformation,
             (HANDLE TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass, LPVOID TokenInformation,
              DWORD TokenInformationLength, PDWORD ReturnLength),
             (TokenHandle, TokenInformationClass, TokenInformation, TokenInformationLength, ReturnLength))
LAZY_WRAPPER(BOOL, FALSE, lazy_advapi32, ConvertSidToStringSidW, (PSID Sid, LPWSTR *StringSid), (Sid, StringSid))
LAZY_WRAPPER(BOOL, FALSE, lazy_advapi32, ConvertStringSecurityDescriptorToSecurityDescriptorW,
             (LPCWSTR StringSecurityDescriptor, DWORD StringSDRevision, PSECURITY_DESCRIPTOR *SecurityDescriptor,
              PULONG SecurityDescriptorSize),
             (StringSecurityDescriptor, StringSDRevision, SecurityDescriptor, SecurityDescriptorSize))

#define SetConsoleCtrlHandler             lazy_SetConsoleCtrlHandler
#define Sleep                             lazy_Sleep
#define GetModuleFileNameW                lazy_GetModuleFileNameW
#define CreateFileMappingW                lazy_CreateFileMappingW
#define MapViewOfFile                     lazy_MapViewOfFile
#define UnmapViewOfFile                   lazy_UnmapViewOfFile
#define DuplicateHandle                   lazy_DuplicateHandle
#define CloseHandle                       lazy_CloseHandle
#define LocalFree                         lazy_LocalFree
#define CreateFileW                       lazy_CreateFileW
#define GetFinalPathNameByHandleW         lazy_GetFinalPathNameByHandleW
#define GetVolumeInformationW             lazy_GetVolumeInformationW
#define GetFileInformationByHandle        lazy_GetFileInformationByHandle
#define WideCharToMultiByte               lazy_WideCharToMultiByte
#define RemoveDirectoryW                  lazy_RemoveDirectoryW
#define DeleteFileW                       lazy_DeleteFileW
#define FindFirstFileW                    lazy_FindFirstFileW
#define FindNextFileW                     lazy_FindNextFileW
#define FindClose                         lazy_FindClose
#define ReadFile                          lazy_ReadFile
#define WriteFile                         lazy_WriteFile
#define FlushFileBuffers                  lazy_FlushFileBuffers
#define GetTempPathW                      lazy_GetTempPathW
#define QueryPerformanceCounter           lazy_QueryPerformanceCounter
#define GetCurrentProcessId               lazy_GetCurrentProcessId
#define CreateDirectoryW                  lazy_CreateDirectoryW
#define GetStdHandle                      lazy_GetStdHandle
#define InitializeProcThreadAttributeList lazy_InitializeProcThreadAttributeList
#define UpdateProcThreadAttribute         lazy_UpdateProcThreadAttribute
#define DeleteProcThreadAttributeList     lazy_DeleteProcThreadAttributeList
#define CreateJobObjectW                  lazy_CreateJobObjectW
#define SetInformationJobObject           lazy_SetInformationJobObject
#define CreateProcessW                    lazy_CreateProcessW
#define AssignProcessToJobObject          lazy_AssignProcessToJobObject
#define ResumeThread                      lazy_ResumeThread
#define WaitForSingleObject               lazy_WaitForSingleObject
#define GetExitCodeProcess                lazy_GetExitCodeProcess
#define TerminateProcess                  lazy_TerminateProcess
#define ExitProcess                       lazy_ExitProcess

#define OpenProcessToken                                     lazy_OpenProcessToken
#define GetTokenInformation                                  lazy_GetTokenInformation
#define ConvertSidToStringSidW                               lazy_ConvertSidToStringSidW
#define ConvertStringSecurityDescriptorToSecurityDescriptorW lazy_ConvertStringSecurityDescriptorToSecurityDescriptorW

/* Process-lifetime storage: the handler never borrows cleanup-owned handles.
 * 0 = bootstrap, 1 = child running, 2 = exiting. */
static volatile LONG console_phase;
static volatile LONG console_cancel;

static BOOL WINAPI launcherConsoleHandler(DWORD event)
{
    if (event != CTRL_C_EVENT && event != CTRL_BREAK_EVENT && event != CTRL_CLOSE_EVENT && event != CTRL_LOGOFF_EVENT &&
        event != CTRL_SHUTDOWN_EVENT)
        return FALSE;
    InterlockedExchange(&console_cancel, 1);
    if (event == CTRL_C_EVENT || event == CTRL_BREAK_EVENT)
        return TRUE; /* The attached child receives the original event directly. */
    /* Windows imposes its own close deadline. Give the main owner bounded time. */
    for (unsigned i = 0; i < 40 && InterlockedCompareExchange(&console_phase, 0, 0) != 2; ++i)
        Sleep(100);
    return TRUE;
}

static wchar_t *modulePath(void)
{
    for (DWORD count = 256; count <= 32768; count *= 2)
    {
        wchar_t *path = malloc((size_t) count * sizeof(*path));
        if (path == NULL)
            return NULL;
        DWORD copied = GetModuleFileNameW(NULL, path, count);
        if (copied > 0 && copied < count)
            return path;
        free(path);
        if (copied == 0)
            return NULL;
    }
    return NULL;
}

/* Always quote using the Microsoft CRT rules, including argv[0]'s special
 * handling: the program name has literal backslashes and cannot contain quotes. */
static int appendArgument(wchar_t *command, size_t *used, const wchar_t *argument)
{
    /* CreateProcessW counts the terminator in its 32767-character limit.
     * Count actual escaping before writing, so rejection leaves the command
     * unchanged and long arguments without escapes can use the available space. */
    if (*used > 32766)
        return 0;
    int program_name = *used == 0;
    if (program_name && wcschr(argument, L'"') != NULL)
        return 0;
    size_t available = 32766 - *used;
    size_t needed    = 2 + (*used != 0);
    size_t slashes   = 0;
    for (const wchar_t *p = argument;; ++p)
    {
        if (needed > available)
            return 0;
        if (*p == L'\\')
        {
            ++slashes;
            ++needed;
            continue;
        }
        if (! program_name && (*p == L'"' || *p == 0))
            needed += slashes;
        slashes = 0;
        if (*p == 0)
            break;
        needed += *p == L'"' ? 2 : 1;
    }
    if (needed > available)
        return 0;
    wchar_t *out = command + *used;
    if (*used != 0)
        *out++ = L' ';
    *out++  = L'"';
    slashes = 0;
    for (const wchar_t *p = argument;; ++p)
    {
        if (*p == L'\\')
        {
            ++slashes;
            continue;
        }
        size_t emit = ! program_name && (*p == L'"' || *p == 0) ? slashes * 2 : slashes;
        while (emit-- != 0)
            *out++ = L'\\';
        slashes = 0;
        if (*p == 0)
            break;
        if (*p == L'"')
            *out++ = L'\\';
        *out++ = *p;
    }
    *out++ = L'"';
    *out   = 0;
    *used  = (size_t) (out - command);
    return 1;
}

static int appendNarrow(wchar_t *command, size_t *used, const char *argument)
{
    wchar_t *wide = waterwallWindowsWide(argument);
    if (wide == NULL)
        return 0;
    int result = appendArgument(command, used, wide);
    free(wide);
    return result;
}

static HANDLE inputSnapshot(const char *input, size_t length)
{
    if (length == 0 || length > SIZE_MAX - sizeof(waterwall_snapshot_header_t))
        return NULL;
    uint64_t size = (uint64_t) length + sizeof(waterwall_snapshot_header_t);
    HANDLE   writable =
        CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, (DWORD) (size >> 32), (DWORD) size, NULL);
    if (writable == NULL)
        return NULL;
    void  *view     = MapViewOfFile(writable, FILE_MAP_WRITE, 0, 0, (SIZE_T) size);
    HANDLE snapshot = NULL;
    if (view != NULL)
    {
        waterwall_snapshot_header_t header = {WW_SNAPSHOT_MAGIC, length, ~(uint64_t) length};
        memcpy(view, &header, sizeof(header));
        memcpy((char *) view + sizeof(header), input, length);
        if (UnmapViewOfFile(view))
            DuplicateHandle(GetCurrentProcess(), writable, GetCurrentProcess(), &snapshot, FILE_MAP_READ, TRUE, 0);
    }
    CloseHandle(writable);
    return snapshot;
}

/* The protected DACL admits only this token's user and SYSTEM. Preserve the
 * token's integrity label so an elevated extraction is not writable below it. */
static PSECURITY_DESCRIPTOR privateSecurity(void)
{
    HANDLE               token      = NULL;
    void                *user       = NULL;
    void                *integrity  = NULL;
    wchar_t             *sid        = NULL;
    wchar_t             *label      = NULL;
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
    if (swprintf(sddl, 512, L"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;%ls)S:(ML;OICI;NW;;;%ls)", sid, label) < 0)
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

static int validImage(const unsigned char *bytes, size_t length)
{
    /* Identification only; native Windows performs all PE loading. */
    if (length < sizeof(IMAGE_DOS_HEADER) + sizeof(IMAGE_NT_HEADERS))
        return 0;
    IMAGE_DOS_HEADER dos;
    memcpy(&dos, bytes, sizeof(dos));
    if (dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew < (LONG) sizeof(dos) ||
        (size_t) dos.e_lfanew > length - sizeof(IMAGE_NT_HEADERS))
        return 0;
    IMAGE_NT_HEADERS nt;
    memcpy(&nt, bytes + dos.e_lfanew, sizeof(nt));
#ifdef _WIN64
    const WORD  machine = IMAGE_FILE_MACHINE_AMD64;
    const char *target  = "windows-x86_64";
#else
    const WORD  machine = IMAGE_FILE_MACHINE_I386;
    const char *target  = "windows-x86";
#endif
    if (strcmp(waterwallPackedTarget, target) != 0 || nt.Signature != IMAGE_NT_SIGNATURE ||
        nt.FileHeader.Machine != machine || ! (nt.FileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE) ||
        (nt.FileHeader.Characteristics & IMAGE_FILE_DLL) || nt.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC ||
        nt.OptionalHeader.AddressOfEntryPoint == 0 ||
        nt.OptionalHeader.AddressOfEntryPoint >= nt.OptionalHeader.SizeOfImage)
        return 0;
    size_t start = (size_t) dos.e_lfanew + 24 + nt.FileHeader.SizeOfOptionalHeader;
    if (nt.FileHeader.SizeOfOptionalHeader < sizeof(nt.OptionalHeader) || nt.FileHeader.NumberOfSections == 0 ||
        nt.FileHeader.NumberOfSections > 96 || start > length ||
        nt.FileHeader.NumberOfSections > (length - start) / sizeof(IMAGE_SECTION_HEADER) ||
        nt.OptionalHeader.SizeOfHeaders > length ||
        start + nt.FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER) > nt.OptionalHeader.SizeOfHeaders)
        return 0;
    int entry = 0;
    for (WORD i = 0; i < nt.FileHeader.NumberOfSections; ++i)
    {
        IMAGE_SECTION_HEADER section;
        memcpy(&section, bytes + start + i * sizeof(section), sizeof(section));
        uint64_t extent =
            section.Misc.VirtualSize > section.SizeOfRawData ? section.Misc.VirtualSize : section.SizeOfRawData;
        if ((uint64_t) section.VirtualAddress + extent > nt.OptionalHeader.SizeOfImage ||
            (section.SizeOfRawData != 0 && (section.PointerToRawData < nt.OptionalHeader.SizeOfHeaders ||
                                            (uint64_t) section.PointerToRawData + section.SizeOfRawData > length)))
            return 0;
        if (nt.OptionalHeader.AddressOfEntryPoint >= section.VirtualAddress &&
            nt.OptionalHeader.AddressOfEntryPoint < (uint64_t) section.VirtualAddress + extent &&
            (section.Characteristics & IMAGE_SCN_MEM_EXECUTE))
            entry = 1;
    }
    return entry;
}

/* Attribute-only opens do not participate in Windows sharing checks. Traverse
 * access does; deny write and delete sharing while subsequent path-based
 * operations use the directory and its ancestors. */
static HANDLE lockDirectory(const wchar_t *path)
{
    return CreateFileW(path,
                       FILE_TRAVERSE | FILE_READ_ATTRIBUTES,
                       FILE_SHARE_READ,
                       NULL,
                       OPEN_EXISTING,
                       FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                       NULL);
}

/* Pin every canonical ancestor: protecting only the last directory does not
 * prevent an attacker-controlled ancestor junction from redirecting later opens.
 * A local ACL-capable volume is required; there is no weaker extraction fallback. */
static int pinTemporaryRoot(HANDLE root_handle, wchar_t *root, HANDLE **locks, size_t *count)
{
    DWORD length = GetFinalPathNameByHandleW(root_handle, root, 32768, FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
    if (length < 7 || length >= 32700 || wcsncmp(root, L"\\\\?\\", 4) != 0 || root[5] != L':' || root[6] != L'\\')
        return 0;
    wchar_t saved   = root[7];
    root[7]         = 0;
    DWORD flags     = 0;
    BOOL  volume_ok = GetVolumeInformationW(root, NULL, 0, NULL, NULL, &flags, NULL, 0);
    root[7]         = saved;
    if (! volume_ok || ! (flags & FILE_PERSISTENT_ACLS))
        return 0;
    while (length > 7 && root[length - 1] == L'\\')
        root[--length] = 0;
    BY_HANDLE_FILE_INFORMATION original;
    if (! GetFileInformationByHandle(root_handle, &original))
        return 0;
    for (DWORD i = 7; i <= length; ++i)
    {
        if (root[i] != L'\\' && root[i] != 0)
            continue;
        saved         = root[i];
        root[i]       = 0;
        HANDLE handle = lockDirectory(root);
        root[i]       = saved;
        BY_HANDLE_FILE_INFORMATION info;
        if (handle == INVALID_HANDLE_VALUE)
            return 0;
        if (! GetFileInformationByHandle(handle, &info) || ! (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ||
            (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) ||
            (i == length &&
             (info.dwVolumeSerialNumber != original.dwVolumeSerialNumber ||
              info.nFileIndexHigh != original.nFileIndexHigh || info.nFileIndexLow != original.nFileIndexLow)))
        {
            CloseHandle(handle);
            return 0;
        }
        HANDLE *grown = realloc(*locks, (*count + 1) * sizeof(HANDLE));
        if (grown == NULL)
        {
            CloseHandle(handle);
            return 0;
        }
        *locks               = grown;
        (*locks)[(*count)++] = handle;
    }
    if (root[length - 1] != L'\\')
        root[length++] = L'\\';
    root[length] = 0;
    return 1;
}

static void reportOwnedPath(const char *kind, const wchar_t *path, DWORD error)
{
    /* stderr is byte-oriented. Emit UTF-8 rather than mixing fwprintf with it. */
    char utf8[32768 * 4];
    if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, path, -1, utf8, sizeof(utf8), NULL, NULL) == 0)
        strcpy(utf8, "<path conversion failed>");
    fprintf(stderr, "Packed runtime: could not remove owned %s %s (error %lu)\n", kind, utf8, error);
}

static void removeOwnedPath(const wchar_t *path, int directory)
{
    DWORD error = ERROR_SUCCESS;
    for (unsigned retry = 0; retry < 10; ++retry)
    {
        if (directory ? RemoveDirectoryW(path) : DeleteFileW(path))
            return;
        error = GetLastError();
        if (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND)
            return;
        if (retry != 9)
            Sleep(50);
    }
    reportOwnedPath(directory ? "directory" : "file", path, error);
}

typedef struct companion_file_s
{
    wchar_t                 *path;
    HANDLE                   lock;
    struct companion_file_s *next;
} companion_file_t;

static wchar_t *companionPath(const wchar_t *directory, const wchar_t *name)
{
    size_t directory_length = wcslen(directory);
    size_t length           = directory_length + wcslen(name) + 2;
    if (length > 32768)
    {
        SetLastError(ERROR_FILENAME_EXCED_RANGE);
        return NULL;
    }
    wchar_t *path = malloc(length * sizeof(*path));
    if (path == NULL)
    {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return NULL;
    }
    swprintf(path, length, L"%ls%ls%ls", directory, directory[directory_length - 1] == L'\\' ? L"" : L"\\", name);
    return path;
}

/* Preserve the native DLL search order, including OS CWD restrictions, by
 * restoring adjacent DLLs beside the child instead of altering its search path.
 * Create fresh files with our ACL: CopyFileW can copy the source security policy.
 * Keep only exact owned paths, never recurse into the deployment directory. */
static int copyCompanions(const wchar_t *deployment, const wchar_t *directory, SECURITY_ATTRIBUTES *security,
                          companion_file_t **owned)
{
    wchar_t *pattern = companionPath(deployment, L"*.dll");
    if (pattern == NULL)
        return 0;
    WIN32_FIND_DATAW entry;
    HANDLE           search = FindFirstFileW(pattern, &entry);
    DWORD            error  = GetLastError();
    free(pattern);
    if (search == INVALID_HANDLE_VALUE)
    {
        SetLastError(error);
        return error == ERROR_FILE_NOT_FOUND;
    }
    HANDLE source = INVALID_HANDLE_VALUE, output = INVALID_HANDLE_VALUE;
    int    result = 0;
    do
    {
        if (entry.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
            continue;
        wchar_t *source_path = companionPath(deployment, entry.cFileName);
        if (source_path == NULL)
            goto done;
        source = CreateFileW(
            source_path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
        error = GetLastError();
        free(source_path);
        SetLastError(error);
        if (source == INVALID_HANDLE_VALUE)
            goto done;
        companion_file_t *file = calloc(1, sizeof(*file));
        if (file == NULL)
        {
            SetLastError(ERROR_NOT_ENOUGH_MEMORY);
            goto done;
        }
        file->path = companionPath(directory, entry.cFileName);
        if (file->path != NULL)
            output = CreateFileW(file->path, GENERIC_WRITE, 0, security, CREATE_NEW, FILE_ATTRIBUTE_TEMPORARY, NULL);
        if (output == INVALID_HANDLE_VALUE)
        {
            error = GetLastError();
            free(file->path);
            free(file);
            SetLastError(error);
            goto done;
        }
        file->lock = INVALID_HANDLE_VALUE;
        file->next = *owned;
        *owned     = file;
        unsigned char bytes[65536];
        DWORD         count;
        for (;;)
        {
            if (! ReadFile(source, bytes, sizeof(bytes), &count, NULL))
                goto done;
            if (count == 0)
                break;
            for (DWORD written = 0; written < count;)
            {
                DWORD part;
                if (! WriteFile(output, bytes + written, count - written, &part, NULL))
                    goto done;
                if (part == 0)
                {
                    SetLastError(ERROR_WRITE_FAULT);
                    goto done;
                }
                written += part;
            }
        }
        BY_HANDLE_FILE_INFORMATION written_info, locked_info;
        if (! FlushFileBuffers(output) || ! GetFileInformationByHandle(output, &written_info))
            goto done;
        BOOL closed = CloseHandle(output);
        output      = INVALID_HANDLE_VALUE;
        if (! closed)
            goto done;
        file->lock = CreateFileW(
            file->path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, NULL);
        if (file->lock == INVALID_HANDLE_VALUE || ! GetFileInformationByHandle(file->lock, &locked_info))
            goto done;
        if ((locked_info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) ||
            locked_info.dwVolumeSerialNumber != written_info.dwVolumeSerialNumber ||
            locked_info.nFileIndexHigh != written_info.nFileIndexHigh ||
            locked_info.nFileIndexLow != written_info.nFileIndexLow)
        {
            SetLastError(ERROR_INVALID_DATA);
            goto done;
        }
        closed = CloseHandle(source);
        source = INVALID_HANDLE_VALUE;
        if (! closed)
            goto done;
    } while (FindNextFileW(search, &entry));
    result = GetLastError() == ERROR_NO_MORE_FILES;
done:
    error = GetLastError();
    if (source != INVALID_HANDLE_VALUE)
        CloseHandle(source);
    if (output != INVALID_HANDLE_VALUE)
        CloseHandle(output);
    if (! FindClose(search) && result)
    {
        error  = GetLastError();
        result = 0;
    }
    SetLastError(error);
    return result;
}

int launcherExecute(char *input, size_t length, const char *source, int argc, char *const argv[])
{
    DWORD                status   = 1;
    int                  started  = 0;
    HANDLE               snapshot = NULL, root_lock = INVALID_HANDLE_VALUE, directory_lock = INVALID_HANDLE_VALUE;
    HANDLE               file = INVALID_HANDLE_VALUE, image_lock = INVALID_HANDLE_VALUE, job = NULL;
    HANDLE               inherited[4]     = {0};
    size_t               inherited_count  = 0;
    PROCESS_INFORMATION  process          = {0};
    STARTUPINFOEXW       startup          = {0};
    int                  attributes_ready = 0;
    PSECURITY_DESCRIPTOR security         = NULL;
    wchar_t             *original = NULL, *command = NULL;
    char                *original_narrow = NULL, *exe_argument = NULL, *src_argument = NULL;
    unsigned char       *decoded = NULL;
    wchar_t              root[32768], directory[32768] = {0}, executable[32768] = {0};
    int                  owns_directory = 0, owns_file = 0;
    HANDLE              *ancestor_locks = NULL;
    size_t               ancestor_count = 0;
    companion_file_t    *companions     = NULL;
    const char          *operation      = "installing console handler";
    if (! SetConsoleCtrlHandler(launcherConsoleHandler, TRUE))
        goto done;
    operation = "capturing executable path and input";
    original  = modulePath();
    snapshot  = inputSnapshot(input, length);
    free(input);
    input = NULL;
    if (original == NULL || snapshot == NULL)
        goto done;
    original_narrow = waterwallWindowsNarrow(original);
    if (original_narrow == NULL)
        goto done;
    operation = "decoding executable";
    if (waterwallRuntimeLength == 0 || waterwallRuntimeLength > SIZE_MAX || waterwallPackedLength == 0)
        goto done;
    decoded = malloc((size_t) waterwallRuntimeLength);
    if (decoded == NULL)
        goto done;
    wwXzDecoderInit();
    if (wwXzDecode(waterwallPackedBytes,
                   waterwallPackedLength,
                   decoded,
                   (size_t) waterwallRuntimeLength,
                   (size_t) waterwallRuntimeLength) != WW_XZ_OK ||
        ! validImage(decoded, (size_t) waterwallRuntimeLength))
        goto done;
    operation         = "creating private extraction directory";
    DWORD root_length = GetTempPathW(32768, root);
    if (root_length == 0 || root_length >= 32700)
        goto done;
    root_lock = lockDirectory(root);
    BY_HANDLE_FILE_INFORMATION info;
    if (root_lock == INVALID_HANDLE_VALUE || ! GetFileInformationByHandle(root_lock, &info) ||
        (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT))
        goto done;
    operation = "pinning a local ACL-capable temporary root";
    if (! pinTemporaryRoot(root_lock, root, &ancestor_locks, &ancestor_count))
        goto done;
    security = privateSecurity();
    if (security == NULL)
        goto done;
    SECURITY_ATTRIBUTES sa = {sizeof(sa), security, FALSE};
    for (unsigned attempt = 0; attempt < 32; ++attempt)
    {
        LARGE_INTEGER counter;
        QueryPerformanceCounter(&counter);
        if (swprintf(directory,
                     32768,
                     L"%lsWaterwall-%lu-%llx-%u",
                     root,
                     GetCurrentProcessId(),
                     (unsigned long long) counter.QuadPart,
                     attempt) < 0)
            goto done;
        if (CreateDirectoryW(directory, &sa))
        {
            owns_directory = 1;
            break;
        }
        if (GetLastError() != ERROR_ALREADY_EXISTS)
            goto done;
    }
    if (! owns_directory)
        goto done;
    directory_lock = lockDirectory(directory);
    if (directory_lock == INVALID_HANDLE_VALUE || ! GetFileInformationByHandle(directory_lock, &info) ||
        (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT))
        goto done;
    if (swprintf(executable, 32768, L"%ls\\waterwall_application.exe", directory) < 0)
        goto done;
    operation = "writing restored executable";
    file      = CreateFileW(executable, GENERIC_WRITE, 0, &sa, CREATE_NEW, FILE_ATTRIBUTE_TEMPORARY, NULL);
    if (file == INVALID_HANDLE_VALUE)
        goto done;
    owns_file = 1;
    for (size_t written = 0; written < (size_t) waterwallRuntimeLength;)
    {
        size_t remaining = (size_t) waterwallRuntimeLength - written;
        DWORD  chunk     = remaining > 1024 * 1024 ? 1024 * 1024 : (DWORD) remaining;
        DWORD  count     = 0;
        if (! WriteFile(file, decoded + written, chunk, &count, NULL) || count == 0)
            goto done;
        written += count;
    }
    if (! FlushFileBuffers(file))
        goto done;
    BY_HANDLE_FILE_INFORMATION written_info;
    if (! GetFileInformationByHandle(file, &written_info))
        goto done;
    BOOL closed = CloseHandle(file);
    file        = INVALID_HANDLE_VALUE;
    if (! closed)
        goto done;
    free(decoded);
    decoded = NULL;
    image_lock =
        CreateFileW(executable, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    if (image_lock == INVALID_HANDLE_VALUE || ! GetFileInformationByHandle(image_lock, &info) ||
        (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) ||
        info.dwVolumeSerialNumber != written_info.dwVolumeSerialNumber ||
        info.nFileIndexHigh != written_info.nFileIndexHigh || info.nFileIndexLow != written_info.nFileIndexLow)
        goto done;
    operation    = "preparing child arguments";
    command      = calloc(32768, sizeof(wchar_t));
    exe_argument = malloc(strlen(original_narrow) + sizeof("--ww-internal-exe="));
    src_argument = malloc(strlen(source) + sizeof("--ww-internal-src="));
    if (command == NULL || exe_argument == NULL || src_argument == NULL)
        goto done;
    sprintf(exe_argument, "--ww-internal-exe=%s", original_narrow);
    sprintf(src_argument, "--ww-internal-src=%s", source);
    char map_argument[80], len_argument[80];
    snprintf(map_argument, sizeof(map_argument), "--ww-internal-map=%llu", (unsigned long long) (uintptr_t) snapshot);
    snprintf(len_argument, sizeof(len_argument), "--ww-internal-len=%zu", length);
    size_t used = 0;
    if (! appendNarrow(command, &used, argv[0]) || ! appendNarrow(command, &used, map_argument) ||
        ! appendNarrow(command, &used, len_argument) || ! appendNarrow(command, &used, src_argument) ||
        ! appendNarrow(command, &used, exe_argument))
        goto done;
    for (int i = 1; i < argc; ++i)
        if (! appendNarrow(command, &used, argv[i]))
            goto done;
    operation                    = "preparing inherited handles";
    inherited[inherited_count++] = snapshot;
    const DWORD standard_ids[3]  = {STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE};
    HANDLE      standard[3]      = {0};
    for (unsigned i = 0; i < 3; ++i)
    {
        HANDLE handle = GetStdHandle(standard_ids[i]);
        if (handle == NULL || handle == INVALID_HANDLE_VALUE)
            continue;
        if (! DuplicateHandle(
                GetCurrentProcess(), handle, GetCurrentProcess(), &standard[i], 0, TRUE, DUPLICATE_SAME_ACCESS))
        {
            if (GetLastError() == ERROR_INVALID_HANDLE)
                continue;
            goto done;
        }
        inherited[inherited_count++] = standard[i];
    }
    SIZE_T attribute_size = 0;
    InitializeProcThreadAttributeList(NULL, 1, 0, &attribute_size);
    startup.lpAttributeList = malloc(attribute_size);
    if (startup.lpAttributeList == NULL ||
        ! InitializeProcThreadAttributeList(startup.lpAttributeList, 1, 0, &attribute_size))
        goto done;
    attributes_ready = 1;
    if (! UpdateProcThreadAttribute(startup.lpAttributeList,
                                    0,
                                    PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                                    inherited,
                                    inherited_count * sizeof(HANDLE),
                                    NULL,
                                    NULL))
        goto done;
    startup.StartupInfo.cb                      = sizeof(startup);
    startup.StartupInfo.dwFlags                 = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput               = standard[0];
    startup.StartupInfo.hStdOutput              = standard[1];
    startup.StartupInfo.hStdError               = standard[2];
    operation                                   = "creating child job";
    job                                         = CreateJobObjectW(NULL, NULL);
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits = {0};
    limits.BasicLimitInformation.LimitFlags     = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if (job == NULL || ! SetInformationJobObject(job, JobObjectExtendedLimitInformation, &limits, sizeof(limits)))
        goto done;
    operation          = "restoring adjacent companion DLLs";
    wchar_t *separator = wcsrchr(original, L'\\');
    if (separator == NULL)
        goto done;
    if (separator == original + 2 && original[1] == L':')
        separator[1] = 0;
    else
        *separator = 0;
    if (! copyCompanions(original, directory, &sa, &companions))
        goto done;
    operation = "starting native child";
    if (InterlockedCompareExchange(&console_cancel, 0, 0))
        goto done;
    fflush(stdout);
    fflush(stderr);
    if (! CreateProcessW(executable,
                         command,
                         NULL,
                         NULL,
                         TRUE,
                         EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED,
                         NULL,
                         NULL,
                         &startup.StartupInfo,
                         &process))
        goto done;
    operation = "assigning child job (an incompatible enclosing job may reject admission)";
    if (! AssignProcessToJobObject(job, process.hProcess))
        goto done;
    if (InterlockedCompareExchange(&console_cancel, 0, 0))
        goto done;
    InterlockedExchange(&console_phase, 1);
    if (ResumeThread(process.hThread) == (DWORD) -1)
        goto done;
    started   = 1;
    operation = "waiting for child exit";
    if (WaitForSingleObject(process.hProcess, INFINITE) != WAIT_OBJECT_0 ||
        ! GetExitCodeProcess(process.hProcess, &status))
    {
        started = 0;
        goto done;
    }
done:
    if (! started)
        fprintf(stderr, "Packed runtime: failed %s (Windows error %lu)\n", operation, GetLastError());
    if (process.hProcess != NULL && ! started)
    {
        TerminateProcess(process.hProcess, 1);
        WaitForSingleObject(process.hProcess, INFINITE);
    }
    if (process.hThread != NULL)
        CloseHandle(process.hThread);
    if (process.hProcess != NULL)
        CloseHandle(process.hProcess);
    if (job != NULL)
        CloseHandle(job);
    if (attributes_ready)
        DeleteProcThreadAttributeList(startup.lpAttributeList);
    free(startup.lpAttributeList);
    for (size_t i = 1; i < inherited_count; ++i)
        CloseHandle(inherited[i]);
    if (snapshot != NULL)
        CloseHandle(snapshot);
    if (file != INVALID_HANDLE_VALUE)
        CloseHandle(file);
    if (image_lock != INVALID_HANDLE_VALUE)
        CloseHandle(image_lock);
    if (owns_file)
        removeOwnedPath(executable, 0);
    while (companions != NULL)
    {
        companion_file_t *file = companions;
        companions             = file->next;
        if (file->lock != INVALID_HANDLE_VALUE)
            CloseHandle(file->lock);
        removeOwnedPath(file->path, 0);
        free(file->path);
        free(file);
    }
    if (directory_lock != INVALID_HANDLE_VALUE)
        CloseHandle(directory_lock);
    if (owns_directory)
        removeOwnedPath(directory, 1);
    while (ancestor_count != 0)
        CloseHandle(ancestor_locks[--ancestor_count]);
    free(ancestor_locks);
    if (root_lock != INVALID_HANDLE_VALUE)
        CloseHandle(root_lock);
    LocalFree(security);
    free(input);
    free(decoded);
    free(original);
    free(original_narrow);
    free(command);
    free(exe_argument);
    free(src_argument);
    InterlockedExchange(&console_phase, 2);
    /* Preserve all 32 bits, including exception statuses. */
    ExitProcess(started ? status : 1);
    return 1;
}

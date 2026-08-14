#pragma once

#include "wplatform.h"

#if defined(OS_WIN)

typedef struct tun_windows_loader_ops_s
{
    DWORD(WINAPI *get_temp_path_w)(DWORD length, LPWSTR path);
    UINT(WINAPI *get_temp_file_name_w)(LPCWSTR path, LPCWSTR prefix, UINT unique, LPWSTR file_name);
    HANDLE(WINAPI *create_file_w)(LPCWSTR file_name, DWORD access, DWORD share_mode, LPSECURITY_ATTRIBUTES security,
                                  DWORD creation, DWORD attributes, HANDLE template_file);
    BOOL(WINAPI *write_file)(HANDLE file, LPCVOID buffer, DWORD length, LPDWORD written, LPOVERLAPPED overlapped);
    BOOL(WINAPI *close_handle)(HANDLE handle);
    BOOL(WINAPI *delete_file_w)(LPCWSTR path);
    BOOL(WINAPI *move_file_ex_w)(LPCWSTR existing_path, LPCWSTR new_path, DWORD flags);
    HMODULE(WINAPI *load_library_ex_w)(LPCWSTR path, HANDLE file, DWORD flags);
    FARPROC(WINAPI *get_proc_address)(HMODULE module, LPCSTR name);
    BOOL(WINAPI *free_library)(HMODULE module);
    DWORD(WINAPI *get_last_error)(void);
    void *(*allocate)(size_t size);
    void (*deallocate)(void *ptr);
} tun_windows_loader_ops_t;

/* Native-Windows fault-injection seams for the process-wide loader transaction. */
void tunWindowsSetLoaderOpsForTest(const tun_windows_loader_ops_t *ops);
void tunWindowsResetLoaderOpsForTest(void);
bool tunWindowsStartupForTest(void);
bool tunWindowsLoaderIsPublishedForTest(void);
bool tunWindowsLoaderHasPendingCleanupForTest(void);

#endif

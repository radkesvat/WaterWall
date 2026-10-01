#ifndef WW_LAZY_LOADER_H
#define WW_LAZY_LOADER_H

#include "lazy_names.h"
#include <stddef.h>
#include <stdint.h>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
// clang-format off
#include <winsock2.h>
#include <windows.h>
// clang-format on

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

#if defined(__GNUC__) || defined(__clang__)
__attribute__((unused, noinline))
#elif defined(_MSC_VER)
__declspec(noinline)
#endif
static void
transform(uint8_t *data, size_t length)
{
    volatile uint8_t *d   = (volatile uint8_t *) data;
    const uint8_t     key = 0xA5; /* 10100101 */

    for (size_t i = 0; i < length; i++)
    {
        d[i] = reverse_bits(d[i]) ^ key;
    }
}

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
    FARPROC volatile address;
} lazy_proc_t;

static inline FARPROC lazyProcAddress(lazy_proc_t *proc)
{
    FARPROC addr = proc->address;
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

    InterlockedCompareExchangePointer((void *volatile *) &proc->address, (void *) (uintptr_t) proc_address, NULL);
    return proc_address;
}

#define LAZY_WRAPPER(ret_type, default_ret, dll, name, params, args)                                                   \
    static lazy_proc_t lazy_proc_##name = {&dll, transf_##name, sizeof(transf_##name), NULL};                          \
    typedef ret_type(WINAPI *lazy_pfn_##name) params;                                                                  \
    static inline ret_type lazy_##name params                                                                          \
    {                                                                                                                  \
        lazy_pfn_##name fn = (lazy_pfn_##name)(uintptr_t) lazyProcAddress(&lazy_proc_##name);                          \
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
        lazy_pfn_##name fn = (lazy_pfn_##name)(uintptr_t) lazyProcAddress(&lazy_proc_##name);                          \
        if (fn != NULL)                                                                                                \
            fn args;                                                                                                   \
    }

typedef struct lazy_str_s
{
    const uint8_t *transf_data;
    size_t         len;
} lazy_str_t;

#define LAZY_STR(name) {transf_##name, sizeof(transf_##name)}

static inline const char *lazyLoadString(const uint8_t *transf_data, size_t len, char *buf, size_t buf_size)
{
    if (transf_data == NULL || len == 0 || len >= buf_size)
    {
        if (buf_size > 0)
            buf[0] = '\0';
        return "";
    }
    memcpy(buf, transf_data, len);
    transform((uint8_t *) buf, len);
    buf[len] = '\0';
    return buf;
}

static inline const char *lazyStr(const lazy_str_t *str, char *buf, size_t buf_size)
{
    if (str == NULL)
    {
        if (buf_size > 0)
            buf[0] = '\0';
        return "";
    }
    return lazyLoadString(str->transf_data, str->len, buf, buf_size);
}

#endif /* WW_LAZY_LOADER_H */

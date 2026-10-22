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

static inline uint8_t transform_mix(uint8_t nibble, uint8_t key)
{
    uint8_t x = (uint8_t) ((nibble + key) & 0x0F);
    x         = (uint8_t) (x ^ (((x << 1) | (x >> 3)) & 0x0F));
    x         = (uint8_t) ((9 * x + 5) & 0x0F);
    return (uint8_t) ((x ^ (x >> 2)) & 0x0F);
}

static inline uint8_t transform_scramble(uint8_t byte)
{
    static const uint8_t round_keys[8] = {0x3, 0xC, 0x5, 0xA, 0xE, 0x1, 0x7, 0xB};
    uint8_t              left          = (uint8_t) ((byte >> 4) & 0x0F);
    uint8_t              right         = (uint8_t) (byte & 0x0F);

    for (size_t i = 0; i < 8; i++)
    {
        uint8_t new_right = (uint8_t) (left ^ transform_mix(right, round_keys[i]));
        left              = right;
        right             = new_right;
    }

    return (uint8_t) ((left << 4) | right);
}

static inline uint8_t transform_unscramble(uint8_t byte)
{
    static const uint8_t round_keys[8] = {0x3, 0xC, 0x5, 0xA, 0xE, 0x1, 0x7, 0xB};
    uint8_t              left          = (uint8_t) ((byte >> 4) & 0x0F);
    uint8_t              right         = (uint8_t) (byte & 0x0F);

    for (size_t i = 8; i > 0; i--)
    {
        uint8_t new_left = (uint8_t) (right ^ transform_mix(left, round_keys[i - 1]));
        right            = left;
        left             = new_left;
    }

    return (uint8_t) ((left << 4) | right);
}

static inline uint8_t transform_byte(uint8_t byte)
{
    const uint8_t key   = 0xA5;
    uint8_t       mixed = (uint8_t) (transform_scramble(byte) ^ key);
    return transform_unscramble(mixed);
}

#if defined(__GNUC__) || defined(__clang__)
__attribute__((unused, noinline))
#elif defined(_MSC_VER)
__declspec(noinline)
#endif
static void
transform(uint8_t *data, size_t length)
{
    volatile uint8_t *d = (volatile uint8_t *) data;

    for (size_t i = 0; i < length; i++)
    {
        d[i] = transform_byte(d[i]);
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

static inline const wchar_t *lazyLoadWideString(const uint8_t *transf_data, size_t len, wchar_t *buf, size_t buf_chars)
{
    if (transf_data == NULL || len == 0 || len >= buf_chars)
    {
        if (buf_chars > 0)
            buf[0] = L'\0';
        return L"";
    }
    char abuf[256];
    if (len >= sizeof(abuf))
    {
        if (buf_chars > 0)
            buf[0] = L'\0';
        return L"";
    }
    memcpy(abuf, transf_data, len);
    transform((uint8_t *) abuf, len);
    abuf[len] = '\0';

    for (size_t i = 0; i <= len; i++)
        buf[i] = (wchar_t) (unsigned char) abuf[i];

    SecureZeroMemory(abuf, sizeof(abuf));
    return buf;
}

static inline const wchar_t *lazyWideStr(const lazy_str_t *str, wchar_t *buf, size_t buf_chars)
{
    if (str == NULL)
    {
        if (buf_chars > 0)
            buf[0] = L'\0';
        return L"";
    }
    return lazyLoadWideString(str->transf_data, str->len, buf, buf_chars);
}

#endif /* WW_LAZY_LOADER_H */

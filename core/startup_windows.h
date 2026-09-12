#pragma once

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif

#include <stdint.h>
#include <stdlib.h>

/* Winsock must precede windows.h for session adapter identity queries. */
// clang-format off
#include <winsock2.h>
#include <windows.h>
// clang-format on

#define WW_SNAPSHOT_MAGIC UINT64_C(0x5757534e41505348)
typedef struct waterwall_snapshot_header_s
{
    uint64_t magic;
    uint64_t length;
    uint64_t length_inverse;
} waterwall_snapshot_header_t;

/* The existing startup boundary uses the active Windows code page. Refuse
 * unrepresentable paths rather than allowing replacement characters. */
static inline char *waterwallWindowsNarrow(const wchar_t *wide)
{
    UINT  page        = GetACP();
    BOOL  substituted = FALSE;
    DWORD flags       = page == CP_UTF8 ? WC_ERR_INVALID_CHARS : WC_NO_BEST_FIT_CHARS;
    BOOL *used        = page == CP_UTF8 ? NULL : &substituted;
    int   count       = WideCharToMultiByte(page, flags, wide, -1, NULL, 0, NULL, used);
    if (count == 0 || substituted)
        return NULL;
    char *result = malloc((size_t) count);
    if (result != NULL && (! WideCharToMultiByte(page, flags, wide, -1, result, count, NULL, used) || substituted))
    {
        free(result);
        return NULL;
    }
    return result;
}

static inline wchar_t *waterwallWindowsWide(const char *narrow)
{
    int count = MultiByteToWideChar(CP_ACP, MB_ERR_INVALID_CHARS, narrow, -1, NULL, 0);
    if (count == 0)
        return NULL;
    wchar_t *result = malloc((size_t) count * sizeof(wchar_t));
    if (result != NULL && ! MultiByteToWideChar(CP_ACP, MB_ERR_INVALID_CHARS, narrow, -1, result, count))
    {
        free(result);
        return NULL;
    }
    return result;
}

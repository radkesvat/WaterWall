#include "lifecycle_capabilities_windows.h"
#include "launcher/lazy_loader.h"
#include <stdbool.h>
#include <string.h>
#include <wchar.h>
#include <winternl.h>

bool waterwallCapabilityValidate(HANDLE handle, const wchar_t *type, ACCESS_MASK access)
{
    typedef NTSTATUS(NTAPI * query_fn)(HANDLE, OBJECT_INFORMATION_CLASS, PVOID, ULONG, PULONG);
    static void *volatile cached_query;
    query_fn query = (query_fn) (uintptr_t) cached_query;
    if (query == NULL)
    {
        char    dll_abuf[sizeof(transf_ntdll) + 1];
        wchar_t dll_wbuf[sizeof(transf_ntdll) + 1];
        memcpy(dll_abuf, transf_ntdll, sizeof(transf_ntdll));
        transform((uint8_t *) dll_abuf, sizeof(transf_ntdll));
        dll_abuf[sizeof(transf_ntdll)] = '\0';
        for (size_t i = 0; i <= sizeof(transf_ntdll); i++)
            dll_wbuf[i] = (wchar_t) (unsigned char) dll_abuf[i];

        HMODULE module = GetModuleHandleW(dll_wbuf);
        SecureZeroMemory(dll_abuf, sizeof(dll_abuf));
        SecureZeroMemory(dll_wbuf, sizeof(dll_wbuf));

        if (module != NULL)
        {
            char proc_abuf[sizeof(transf_NtQueryObject) + 1];
            memcpy(proc_abuf, transf_NtQueryObject, sizeof(transf_NtQueryObject));
            transform((uint8_t *) proc_abuf, sizeof(transf_NtQueryObject));
            proc_abuf[sizeof(transf_NtQueryObject)] = '\0';

            FARPROC addr = GetProcAddress(module, proc_abuf);
            SecureZeroMemory(proc_abuf, sizeof(proc_abuf));

            if (addr != NULL)
            {
                InterlockedCompareExchangePointer(&cached_query, (void *) (uintptr_t) addr, NULL);
                query = (query_fn) (uintptr_t) addr;
            }
        }
    }
    DWORD flags;
    if (query == NULL || handle == NULL || (intptr_t) handle < 0 || ! GetHandleInformation(handle, &flags))
        return false;
    PUBLIC_OBJECT_BASIC_INFORMATION basic;
    ULONG                           length;
    if (query(handle, ObjectBasicInformation, &basic, sizeof(basic), &length) < 0 ||
        (basic.GrantedAccess & access) != access)
        return false;
    union {
        void         *alignment;
        unsigned char bytes[4096];
    } buffer;
    if (query(handle, ObjectTypeInformation, buffer.bytes, sizeof(buffer.bytes), &length) < 0)
        return false;
    PUBLIC_OBJECT_TYPE_INFORMATION *info     = (void *) buffer.bytes;
    size_t                          expected = wcslen(type) * sizeof(wchar_t);
    return info->TypeName.Length == expected && info->TypeName.Buffer != NULL &&
           memcmp(info->TypeName.Buffer, type, expected) == 0;
}

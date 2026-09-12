#include "lifecycle_capabilities_windows.h"
#include <stdbool.h>
#include <string.h>
#include <wchar.h>
#include <winternl.h>

bool waterwallCapabilityValidate(HANDLE handle, const wchar_t *type, ACCESS_MASK access)
{
    typedef NTSTATUS(NTAPI * query_fn)(HANDLE, OBJECT_INFORMATION_CLASS, PVOID, ULONG, PULONG);
    HMODULE  module = GetModuleHandleW(L"ntdll.dll");
    query_fn query  = module == NULL ? NULL : (query_fn) (uintptr_t) GetProcAddress(module, "NtQueryObject");
    DWORD    flags;
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

#include "windows_session_effects.h"
#include <limits.h>

static windows_session_effects_t *effects;

bool windowsSessionEffectsAttach(uintptr_t mapping)
{
    if (mapping == 0)
        return true;
    HANDLE handle = (HANDLE) mapping;
    void  *view   = MapViewOfFile(handle, FILE_MAP_WRITE, 0, 0, sizeof(*effects));
    CloseHandle(handle);
    if (view == NULL)
        return false;
    MEMORY_BASIC_INFORMATION region;
    if (VirtualQuery(view, &region, sizeof(region)) == 0 || region.State != MEM_COMMIT ||
        region.RegionSize < sizeof(*effects) || region.Protect != PAGE_READWRITE ||
        ((windows_session_effects_t *) view)->magic != WW_SESSION_EFFECT_MAGIC)
    {
        UnmapViewOfFile(view);
        return false;
    }
    effects = view;
    return true;
}

bool windowsSessionAdapterBegin(unsigned *slot)
{
    *slot = UINT_MAX;
    if (effects == NULL)
        return true;
    for (unsigned i = 0; i < WW_SESSION_ADAPTER_MAX; ++i)
    {
        if (InterlockedCompareExchange(&effects->adapters[i].state, 1, 0) == 0)
        {
            *slot = i;
            return true;
        }
    }
    return false;
}

bool windowsSessionAdapterConfirm(unsigned slot, const NET_LUID *luid)
{
    if (slot == UINT_MAX)
        return true;
    GUID guid;
    if (ConvertInterfaceLuidToGuid(luid, &guid) != NO_ERROR)
        return false;
    effects->adapters[slot].guid = guid;
    InterlockedExchange(&effects->adapters[slot].state, 2);
    return true;
}

void windowsSessionDriverUnsettled(void)
{
    if (effects != NULL)
        InterlockedExchange(&effects->driver_residue, 1);
}

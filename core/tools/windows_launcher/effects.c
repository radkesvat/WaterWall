#include "windows_session_effects.h"
#include <stdio.h>
#include <stdlib.h>

static void require(bool value, const char *message)
{
    if (! value)
    {
        fprintf(stderr, "%s\n", message);
        ExitProcess(1);
    }
}
int main(void)
{
    require(! windowsSessionEffectsAttach((uintptr_t) INVALID_HANDLE_VALUE), "invalid mapping accepted");
    HANDLE mapping =
        CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, sizeof(windows_session_effects_t), NULL);
    require(mapping != NULL, "create mapping");
    windows_session_effects_t *shared = MapViewOfFile(mapping, FILE_MAP_WRITE, 0, 0, sizeof(*shared));
    require(shared != NULL, "map inventory");
    shared->magic = WW_SESSION_EFFECT_MAGIC;
    HANDLE runtime;
    require(DuplicateHandle(GetCurrentProcess(), mapping, GetCurrentProcess(), &runtime, FILE_MAP_WRITE, TRUE, 0),
            "runtime capability");
    require(windowsSessionEffectsAttach((uintptr_t) runtime), "attach inventory");
    DWORD flags;
    require(! GetHandleInformation(runtime, &flags), "attach did not consume mapping handle");
    unsigned slot;
    for (unsigned i = 0; i < WW_SESSION_ADAPTER_MAX; ++i)
    {
        require(windowsSessionAdapterBegin(&slot) && slot == i && shared->adapters[i].state == 1,
                "creation intent was not published to the recovery view");
    }
    require(! windowsSessionAdapterBegin(&slot), "inventory overflow admitted untracked creation");
    NET_LUID invalid = {0};
    require(! windowsSessionAdapterConfirm(0, &invalid) && shared->adapters[0].state == 1,
            "failed identity resolution fabricated a known adapter");
    UnmapViewOfFile(shared);
    CloseHandle(mapping);
    return 0;
}

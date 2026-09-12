/* The production backend resolves DNS targets from the returned adapter handle.
 * Only identity conversion and DNS command delivery are replaced here. */
#include "global_state.h"
#include "loggers/internal_logger.h"
#include "tun_windows_dns.h"
#include "wintun.h"
#include <iphlpapi.h>
#include <netioapi.h>
#include <stdio.h>
#include <wchar.h>

static NET_IFINDEX  selected_index = 37;
static NETIO_STATUS mapping_result;
static unsigned int set_calls, clear_calls, mapping_calls;
static wchar_t      set_target[11], clear_target[11];

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "FAIL: %s\n", message);
        exit(1);
    }
}

static void WINAPI fixtureLuid(WINTUN_ADAPTER_HANDLE adapter, NET_LUID *luid)
{
    require((HANDLE) adapter == (HANDLE) (uintptr_t) 123, "LUID queried for an unowned adapter");
    luid->Value = UINT64_C(0x1122334455667788);
}

static NETIO_STATUS WINAPI fixtureIndex(const NET_LUID *luid, PNET_IFINDEX index)
{
    ++mapping_calls;
    require(luid->Value == UINT64_C(0x1122334455667788), "index lookup did not use returned adapter LUID");
    *index = selected_index;
    return mapping_result;
}

static tun_windows_dns_result_e fixtureSet(const wchar_t *target, HANDLE ownership, const char *const *servers,
                                           size_t count, HANDLE stop, bool *may_have_changed)
{
    require(wcslen(target) <= 10 && count == 1 && strcmp(servers[0], "192.0.2.1") == 0 && stop == NULL,
            "DNS target or arguments changed");
    require(ownership == (HANDLE) (uintptr_t) 456, "DNS lost device ownership");
    ++set_calls;
    *may_have_changed = true;
    wcscpy(set_target, target);
    return kTunWindowsDnsSuccess;
}

static bool fixtureClear(const wchar_t *target, HANDLE ownership)
{
    require(wcslen(target) <= 10, "cleanup target exceeded index capacity");
    require(ownership == (HANDLE) (uintptr_t) 456, "DNS cleanup lost device ownership");
    ++clear_calls;
    wcscpy(clear_target, target);
    return true;
}

#define ConvertInterfaceLuidToIndex fixtureIndex
#define tunWindowsDnsSet            fixtureSet
#define tunWindowsDnsClear          fixtureClear
#include "../../ww/devices/tun/tun_windows.c"

int main(void)
{
    require(createInternalLogger(NULL, false) != NULL, "cannot initialize fixture logger");
    wintun_api.get_adapter_luid = fixtureLuid;
    /* A requested numeric alias can identify an unrelated existing interface.
     * Neither install nor removal may use it after Wintun returns our adapter. */
    char         name[]      = "7";
    wchar_t      wide_name[] = L"7";
    tun_device_t device      = {.name           = name,
                                .name_w         = wide_name,
                                .adapter_handle = (HANDLE) (uintptr_t) 123,
                                .ownership      = (HANDLE) (uintptr_t) 456};
    const char  *servers[]   = {"192.0.2.1"};
    require(tundeviceSetDnsServers(&device, servers, 1) && tundeviceWindowsDnsNeedsCleanup(&device) &&
                tundeviceClearDnsServers(&device) && ! tundeviceWindowsDnsNeedsCleanup(&device) &&
                wcscmp(set_target, L"37") == 0 && wcscmp(clear_target, L"37") == 0 && mapping_calls == 2,
            "DNS used the requested alias instead of the returned interface index");
    selected_index = UINT32_MAX;
    require(tundeviceSetDnsServers(&device, servers, 1) && tundeviceClearDnsServers(&device) &&
                wcscmp(set_target, L"4294967295") == 0 && wcscmp(clear_target, L"4294967295") == 0,
            "maximum interface index was truncated");
    mapping_result = ERROR_NOT_FOUND;
    require(! tundeviceSetDnsServers(&device, servers, 1) && ! tundeviceClearDnsServers(&device) && set_calls == 2 &&
                clear_calls == 2 && ! tundeviceWindowsDnsNeedsCleanup(&device),
            "failed LUID mapping still issued DNS commands");
    device.adapter_handle = NULL;
    unsigned int before   = mapping_calls;
    require(! tundeviceSetDnsServers(&device, servers, 1) && ! tundeviceClearDnsServers(&device) &&
                mapping_calls == before && set_calls == 2 && clear_calls == 2 &&
                ! tundeviceWindowsDnsNeedsCleanup(&device),
            "missing owned adapter still issued DNS commands");
    internaloggerDestroy();
    return 0;
}

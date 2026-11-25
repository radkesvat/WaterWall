#pragma once

#include "../windows_kill_switch_control.h"

static inline bool tunWindowsPhysicalInterfaceUp(const MIB_IF_ROW2 *row)
{
    return row->InterfaceLuid.Value != 0 && row->InterfaceIndex != 0 &&
           row->InterfaceAndOperStatusFlags.HardwareInterface && ! row->InterfaceAndOperStatusFlags.FilterInterface &&
           row->OperStatus == IfOperStatusUp;
}

static inline bool tunWindowsBestPhysicalRoute(MIB_IF_ROW2 *best)
{
    MIB_IPFORWARD_TABLE2 *routes = NULL;
    if (GetIpForwardTable2(AF_INET, &routes) != NO_ERROR)
        return false;

    uint64_t best_metric = UINT64_MAX;
    for (ULONG i = 0; i < routes->NumEntries; ++i)
    {
        const MIB_IPFORWARD_ROW2 *route = &routes->Table[i];
        if (route->DestinationPrefix.PrefixLength != 0 || route->Loopback || route->ValidLifetime == 0)
            continue;

        MIB_IF_ROW2         row = {.InterfaceLuid = route->InterfaceLuid};
        MIB_IPINTERFACE_ROW ip  = {.Family = AF_INET, .InterfaceLuid = route->InterfaceLuid};
        if (GetIfEntry2(&row) != NO_ERROR || row.InterfaceIndex != route->InterfaceIndex ||
            ! tunWindowsPhysicalInterfaceUp(&row) || GetIpInterfaceEntry(&ip) != NO_ERROR || ! ip.Connected ||
            ip.DisableDefaultRoutes)
            continue;

        const uint64_t metric = (uint64_t) route->Metric + ip.Metric;
        if (metric < best_metric)
        {
            *best       = row;
            best_metric = metric;
        }
    }
    FreeMibTable(routes);
    return best_metric != UINT64_MAX;
}

static inline bool wwWindowsKillSwitchGetUplink(ww_kill_switch_message_t *identity)
{
    MIB_IF_ROW2 row;
    if (! tunWindowsBestPhysicalRoute(&row))
        return false;

    *identity = (ww_kill_switch_message_t) {.magic = WW_KILL_SWITCH_MESSAGE_MAGIC,
                                            .type  = WW_KILL_SWITCH_UPLINK,
                                            .luid  = row.InterfaceLuid.Value,
                                            .guid  = row.InterfaceGuid,
                                            .index = row.InterfaceIndex};
    return true;
}

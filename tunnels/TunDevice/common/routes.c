#include "structure.h"

#include "loggers/network_logger.h"

#include <ctype.h>
#include <errno.h>

#ifndef OS_WIN
#include <arpa/inet.h>
#endif

enum
{
    kTunDeviceMaxSystemRoutes = 4096
};

typedef struct route_cidr_s
{
    int     family;
    uint8_t addr[16];
    uint8_t prefix;
} route_cidr_t;

typedef struct route_list_s
{
    route_cidr_t *items;
    size_t        count;
    size_t        capacity;
} route_list_t;

static int routeFamilyBits(int family)
{
    return family == AF_INET ? 32 : 128;
}

static int routeFamilyBytes(int family)
{
    return family == AF_INET ? 4 : 16;
}

static bool routeTableIsOff(const char *table)
{
    return table == NULL || stringCompare(table, "off") == 0;
}

static bool routeTableEnablesRoutes(const char *table)
{
    return table != NULL && stringCompare(table, "off") != 0;
}

static bool routeTableIsValid(const char *table)
{
    if (table == NULL || table[0] == '\0')
    {
        return false;
    }

    for (const char *p = table; *p != '\0'; ++p)
    {
        if (! (isalnum((unsigned char) *p) || *p == '_' || *p == '-' || *p == '.'))
        {
            return false;
        }
    }

    return true;
}

static bool parseRouteCidr(const char *cidr, route_cidr_t *out)
{
    if (cidr == NULL || cidr[0] == '\0')
    {
        return false;
    }

    const char *slash = stringChr(cidr, '/');
    if (slash == NULL || slash == cidr || slash[1] == '\0')
    {
        return false;
    }

    size_t ip_len = (size_t) (slash - cidr);
    if (ip_len >= INET6_ADDRSTRLEN)
    {
        return false;
    }

    char ip_part[INET6_ADDRSTRLEN];
    memoryCopy(ip_part, cidr, ip_len);
    ip_part[ip_len] = '\0';

    errno          = 0;
    char *end_ptr  = NULL;
    long  prefix_l = strtol(slash + 1, &end_ptr, 10);
    if (errno != 0 || end_ptr == slash + 1 || *end_ptr != '\0')
    {
        return false;
    }

    memorySet(out, 0, sizeof(*out));
    if (inet_pton(AF_INET, ip_part, out->addr) == 1)
    {
        if (prefix_l < 0 || prefix_l > 32)
        {
            return false;
        }
        out->family = AF_INET;
        out->prefix = (uint8_t) prefix_l;
    }
    else if (inet_pton(AF_INET6, ip_part, out->addr) == 1)
    {
        if (prefix_l < 0 || prefix_l > 128)
        {
            return false;
        }
        out->family = AF_INET6;
        out->prefix = (uint8_t) prefix_l;
    }
    else
    {
        return false;
    }

    int full_bytes = out->prefix / 8;
    int rem_bits   = out->prefix % 8;
    int addr_bytes = routeFamilyBytes(out->family);

    if (rem_bits != 0)
    {
        out->addr[full_bytes] &= (uint8_t) (0xFFU << (8U - rem_bits));
        full_bytes++;
    }
    if (full_bytes < addr_bytes)
    {
        memorySet(out->addr + full_bytes, 0, (size_t) (addr_bytes - full_bytes));
    }

    return true;
}

static bool routeAddrPrefixEqual(const uint8_t *a, const uint8_t *b, unsigned int bits)
{
    unsigned int full_bytes = bits / 8U;
    unsigned int rem_bits   = bits % 8U;

    if (full_bytes > 0 && memoryCompare(a, b, full_bytes) != 0)
    {
        return false;
    }

    if (rem_bits == 0)
    {
        return true;
    }

    uint8_t mask = (uint8_t) (0xFFU << (8U - rem_bits));
    return (a[full_bytes] & mask) == (b[full_bytes] & mask);
}

static bool routeCidrIntersects(const route_cidr_t *a, const route_cidr_t *b)
{
    if (a->family != b->family)
    {
        return false;
    }

    return routeAddrPrefixEqual(a->addr, b->addr, min(a->prefix, b->prefix));
}

static bool routeCidrContains(const route_cidr_t *outer, const route_cidr_t *inner)
{
    if (outer->family != inner->family || outer->prefix > inner->prefix)
    {
        return false;
    }

    return routeAddrPrefixEqual(outer->addr, inner->addr, outer->prefix);
}

static bool routeCidrEquals(const route_cidr_t *a, const route_cidr_t *b)
{
    return a->family == b->family && a->prefix == b->prefix && routeAddrPrefixEqual(a->addr, b->addr, a->prefix);
}

static void routeCidrSetBit(route_cidr_t *cidr, unsigned int bit, bool value)
{
    unsigned int byte_index = bit / 8U;
    uint8_t      bit_mask   = (uint8_t) (1U << (7U - (bit % 8U)));

    if (value)
    {
        cidr->addr[byte_index] |= bit_mask;
    }
    else
    {
        cidr->addr[byte_index] &= (uint8_t) ~bit_mask;
    }
}

static void routeListFree(route_list_t *list)
{
    memoryFree(list->items);
    list->items    = NULL;
    list->count    = 0;
    list->capacity = 0;
}

static bool routeListAppend(route_list_t *list, route_cidr_t cidr)
{
    if (list->count >= kTunDeviceMaxSystemRoutes)
    {
        LOGE("TunDevice: system route expansion exceeded %d routes", kTunDeviceMaxSystemRoutes);
        return false;
    }

    if (list->count == list->capacity)
    {
        size_t next_capacity = list->capacity == 0 ? 8 : list->capacity * 2;
        if (next_capacity > kTunDeviceMaxSystemRoutes)
        {
            next_capacity = kTunDeviceMaxSystemRoutes;
        }

        route_cidr_t *new_items = memoryReAllocate(list->items, next_capacity * sizeof(route_cidr_t));
        if (new_items == NULL)
        {
            LOGE("TunDevice: failed to allocate route list");
            return false;
        }

        list->items    = new_items;
        list->capacity = next_capacity;
    }

    list->items[list->count++] = cidr;
    return true;
}

static bool routeListParseAndAppend(route_list_t *list, const char *cidr, const char *json_path)
{
    route_cidr_t parsed;
    if (! parseRouteCidr(cidr, &parsed))
    {
        LOGF("JSON Error: %s contains invalid CIDR entry: %s", json_path, cidr != NULL ? cidr : "<null>");
        return false;
    }

    return routeListAppend(list, parsed);
}

static bool routeListLoadJsonArray(route_list_t *list, const cJSON *settings, const char *key, bool *found)
{
    const cJSON *array = cJSON_GetObjectItemCaseSensitive(settings, key);
    *found             = array != NULL;
    if (array == NULL)
    {
        return true;
    }

    if (! cJSON_IsArray(array))
    {
        LOGF("JSON Error: TunDevice->settings->%s must be an array of CIDR strings", key);
        return false;
    }

    const cJSON *entry = NULL;
    cJSON_ArrayForEach(entry, array)
    {
        if (! cJSON_IsString(entry) || entry->valuestring == NULL || entry->valuestring[0] == '\0')
        {
            LOGF("JSON Error: TunDevice->settings->%s must contain only non-empty CIDR strings", key);
            return false;
        }

        char path[128];
        stringNPrintf(path, sizeof(path), "TunDevice->settings->%s", key);
        if (! routeListParseAndAppend(list, entry->valuestring, path))
        {
            return false;
        }
    }

    return true;
}

static bool routeSubtractOne(const route_cidr_t *base, const route_cidr_t *exclude, route_list_t *out)
{
    if (! routeCidrIntersects(base, exclude))
    {
        return routeListAppend(out, *base);
    }

    if (routeCidrContains(exclude, base))
    {
        return true;
    }

    int max_bits = routeFamilyBits(base->family);
    if (base->prefix >= max_bits)
    {
        return true;
    }

    route_cidr_t left  = *base;
    route_cidr_t right = *base;
    left.prefix++;
    right.prefix++;
    routeCidrSetBit(&left, base->prefix, false);
    routeCidrSetBit(&right, base->prefix, true);

    return routeSubtractOne(&left, exclude, out) && routeSubtractOne(&right, exclude, out);
}

static bool routeSubtractExcludes(route_list_t *routes, const route_list_t *excludes)
{
    for (size_t ei = 0; ei < excludes->count; ++ei)
    {
        route_list_t next = {0};

        for (size_t ri = 0; ri < routes->count; ++ri)
        {
            if (! routeSubtractOne(&routes->items[ri], &excludes->items[ei], &next))
            {
                routeListFree(&next);
                return false;
            }
        }

        routeListFree(routes);
        *routes = next;
    }

    return true;
}

static bool routeSplitDefaultRoutes(route_list_t *routes)
{
    route_list_t split = {0};

    for (size_t i = 0; i < routes->count; ++i)
    {
        route_cidr_t route = routes->items[i];
        if (route.prefix != 0)
        {
            if (! routeListAppend(&split, route))
            {
                routeListFree(&split);
                return false;
            }
            continue;
        }

        route_cidr_t left  = route;
        route_cidr_t right = route;
        left.prefix        = 1;
        right.prefix       = 1;
        routeCidrSetBit(&left, 0, false);
        routeCidrSetBit(&right, 0, true);

        if (! routeListAppend(&split, left) || ! routeListAppend(&split, right))
        {
            routeListFree(&split);
            return false;
        }
    }

    routeListFree(routes);
    *routes = split;
    return true;
}

static bool routeListDeduplicate(route_list_t *routes)
{
    route_list_t unique = {0};

    for (size_t i = 0; i < routes->count; ++i)
    {
        bool seen = false;
        for (size_t j = 0; j < unique.count; ++j)
        {
            if (routeCidrEquals(&routes->items[i], &unique.items[j]))
            {
                seen = true;
                break;
            }
        }

        if (! seen && ! routeListAppend(&unique, routes->items[i]))
        {
            routeListFree(&unique);
            return false;
        }
    }

    routeListFree(routes);
    *routes = unique;
    return true;
}

static char *routeCidrToString(const route_cidr_t *cidr)
{
    char addr[INET6_ADDRSTRLEN];
    if (inet_ntop(cidr->family, cidr->addr, addr, sizeof(addr)) == NULL)
    {
        return NULL;
    }

    char formatted[INET6_ADDRSTRLEN + 8];
    stringNPrintf(formatted, sizeof(formatted), "%s/%u", addr, cidr->prefix);
    return stringDuplicate(formatted);
}

static bool routeListStoreOnState(tundevice_tstate_t *state, const route_list_t *routes)
{
    if (routes->count == 0)
    {
        LOGF("TunDevice: system-route produced no routes after exclusions");
        return false;
    }

    state->system_routes = memoryCalloc(routes->count, sizeof(char *));
    if (state->system_routes == NULL)
    {
        LOGE("TunDevice: failed to allocate system route strings");
        return false;
    }

    state->system_route_count = routes->count;
    for (size_t i = 0; i < routes->count; ++i)
    {
        state->system_routes[i] = routeCidrToString(&routes->items[i]);
        if (state->system_routes[i] == NULL)
        {
            LOGE("TunDevice: failed to format system route");
            return false;
        }
    }

    return true;
}

bool tundeviceLoadRouteSettings(tundevice_tstate_t *state, const cJSON *settings)
{
    bool  system_route = false;
    char *route_table  = NULL;

    getBoolFromJsonObjectOrDefault(&system_route, settings, "system-route", false);
    if (! getStringFromJsonObject(&route_table, settings, "route-table"))
    {
        route_table = stringDuplicate(system_route ? "main" : "off");
    }

    if (! routeTableIsValid(route_table))
    {
        LOGF("JSON Error: TunDevice->settings->route-table must be \"off\", \"main\", \"auto\", or a platform table "
             "name");
        memoryFree(route_table);
        return false;
    }

    state->route_table          = route_table;
    state->system_route_enabled = system_route || routeTableEnablesRoutes(route_table);
    if (routeTableIsOff(route_table))
    {
        state->system_route_enabled = false;
    }

    // Self-traffic loop protection: keep Waterwall's own outbound connections out
    // of the TUN. Defaults to on whenever the TUN becomes a system route, and can
    // be disabled explicitly with "loop-protection": false.
    getBoolFromJsonObjectOrDefault(
        &state->loop_protection_enabled, settings, "loop-protection", state->system_route_enabled);

    getStringFromJsonObject(&state->post_up_script, settings, "post-up-script");
    getStringFromJsonObject(&state->pre_down_script, settings, "pre-down-script");

    if (! state->system_route_enabled)
    {
        return true;
    }

    route_list_t routes   = {0};
    route_list_t excludes = {0};
    bool         found_routes;
    bool         found_excludes;
    bool         ok = false;

    if (! routeListLoadJsonArray(&routes, settings, "route-cidrs", &found_routes))
    {
        goto done;
    }

    if (! found_routes)
    {
        const char *default_route = addressIsIp6(state->ip_present) ? "::/0" : "0.0.0.0/0";
        if (! routeListParseAndAppend(&routes, default_route, "TunDevice->settings->route-cidrs"))
        {
            goto done;
        }
    }

    if (! routeListLoadJsonArray(&excludes, settings, "route-exclude-cidrs", &found_excludes))
    {
        goto done;
    }

    discard found_excludes;

    if (! routeSubtractExcludes(&routes, &excludes))
    {
        goto done;
    }

    if (! routeSplitDefaultRoutes(&routes))
    {
        goto done;
    }

    if (! routeListDeduplicate(&routes))
    {
        goto done;
    }

    ok = routeListStoreOnState(state, &routes);

done:
    routeListFree(&routes);
    routeListFree(&excludes);
    return ok;
}

bool tundeviceApplySystemRoutes(tundevice_tstate_t *state)
{
    if (! state->system_route_enabled)
    {
        return true;
    }

    assert(state->tdev != NULL);
    state->system_routes_installed = 0;

    for (size_t i = 0; i < state->system_route_count; ++i)
    {
        if (! tundeviceAddRoute(state->tdev, state->system_routes[i], state->route_table))
        {
            LOGE("TunDevice: failed to install system route %s", state->system_routes[i]);
            tundeviceCleanupSystemRoutes(state);
            return false;
        }

        state->system_routes_installed++;
    }

    return true;
}

void tundeviceCleanupSystemRoutes(tundevice_tstate_t *state)
{
    if (! state->system_route_enabled || state->tdev == NULL)
    {
        return;
    }

    while (state->system_routes_installed > 0)
    {
        state->system_routes_installed--;
        const char *cidr = state->system_routes[state->system_routes_installed];
        if (! tundeviceRemoveRoute(state->tdev, cidr, state->route_table))
        {
            LOGW("TunDevice: failed to remove system route %s", cidr);
        }
    }
}

void tundeviceFreeRouteSettings(tundevice_tstate_t *state)
{
    tundeviceCleanupSystemRoutes(state);

    if (state->system_routes != NULL)
    {
        for (size_t i = 0; i < state->system_route_count; ++i)
        {
            memoryFree(state->system_routes[i]);
        }
        memoryFree(state->system_routes);
    }

    memoryFree(state->route_table);
    memoryFree(state->post_up_script);
    memoryFree(state->pre_down_script);

    state->system_routes           = NULL;
    state->system_route_count      = 0;
    state->system_routes_installed = 0;
    state->route_table             = NULL;
    state->post_up_script          = NULL;
    state->pre_down_script         = NULL;
    state->system_route_enabled    = false;
}

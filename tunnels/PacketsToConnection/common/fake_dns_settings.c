#include "fake_dns_internal.h"

#include "loggers/dns_logger.h"

enum
{
    kPtcFakeDnsDefaultPort    = 53,
    kPtcFakeDnsDefaultTtl     = 1,
    kPtcFakeDnsDefaultRecords = 10000,
    kPtcFakeDnsMaxTtl         = INT32_MAX
};

typedef struct ptc_fake_dns_geometry_s
{
    size_t  record_bytes;
    isize_t map_capacity;
} ptc_fake_dns_geometry_t;

static bool ptcFakeDnsComputeGeometry(uint32_t cache_size, ptc_fake_dns_geometry_t *out)
{
    if (out == NULL || cache_size == 0 || cache_size > kPtcFakeDnsMaxRecords)
    {
        return false;
    }

    const uint64_t map_capacity = (uint64_t) cache_size + kPtcDnsMaxQuestions;
    if (map_capacity > PTRDIFF_MAX || map_capacity > (UINT64_MAX - 19U) / 5U)
    {
        return false;
    }

    /* STC rounds float(capacity / 0.8) + 4 to the next power of two. */
    const uint64_t raw_buckets   = ((map_capacity * 5U) + 3U) / 4U + 4U;
    uint64_t       largest_power = 1;
    while (largest_power <= (uint64_t) PTRDIFF_MAX / 2U)
    {
        largest_power *= 2U;
    }
    if (raw_buckets > largest_power)
    {
        return false;
    }

    *out = (ptc_fake_dns_geometry_t) {
        /* At most 262144 pointers: representable on both 32-bit and 64-bit targets. */
        .record_bytes = (size_t) cache_size * sizeof(ptc_fake_dns_entry_t *),
        .map_capacity = (isize_t) map_capacity,
    };
    return true;
}

static bool ptcFakeDnsParseIpv4(ip4_addr_t *out, const char *value, const char *json_path)
{
    ip_addr_t ip;

    if (! ipaddr_aton(value, &ip) || ! ipAddrIsV4(&ip))
    {
        LOGF("JSON Error: %s must be a valid IPv4 address", json_path);
        return false;
    }

    *out = ip.u_addr.ip4;
    return true;
}

/*
 * Present but invalid is an error, not a default.
 *
 * getStringFromJsonObjectOrDefault() answers the same way for an omitted field
 * and for one of the wrong type, so `"address": 5` used to configure 198.18.0.2
 * and never say so.
 */
bool ptcLoadOptionalInteger(const cJSON *settings, const char *key, int64_t minimum, int64_t maximum,
                            int64_t *value_inout, const char *json_path)
{
    int64_t                   parsed = 0;
    const json_value_status_t status = jsonGetObjectIntegerInRange(settings, key, minimum, maximum, &parsed);

    if (status == kJsonValueMissing)
    {
        return true;
    }

    if (status == kJsonValueInvalid)
    {
        LOGF("JSON Error: %s (int field) : expected a whole number between %lld and %lld",
             json_path,
             (long long) minimum,
             (long long) maximum);
        return false;
    }

    *value_inout = parsed;
    return true;
}

static bool ptcFakeDnsLoadOptionalBoolean(const cJSON *settings, const char *key, bool *value_inout,
                                          const char *json_path)
{
    const json_value_status_t status = jsonGetObjectBoolean(settings, key, value_inout);

    if (status == kJsonValueInvalid)
    {
        LOGF("JSON Error: %s (bool field) : expected true or false", json_path);
        return false;
    }
    return true;
}

static bool ptcFakeDnsLoadIpv4Setting(ip4_addr_t *out, const cJSON *settings, const char *key, const char *def,
                                      const char *json_path)
{
    const char               *value  = def;
    const json_value_status_t status = jsonGetObjectNonEmptyString(settings, key, &value);

    if (status == kJsonValueInvalid)
    {
        LOGF("JSON Error: %s must be a non-empty string", json_path);
        return false;
    }

    return ptcFakeDnsParseIpv4(out, value, json_path);
}

static bool ptcFakeDnsIsAliasName(const char *name)
{
    return name != NULL && (stringCompare(name, "fake-dns") == 0 || stringCompare(name, "fake_dns") == 0 ||
                            stringCompare(name, "mapdns") == 0);
}

static uint32_t ptcFakeDnsFieldBit(const char *name)
{
    static const char *const fields[] = {
        "enabled",
        "address",
        "network",
        "netmask",
        "port",
        "ttl",
        "cache-size",
    };

    if (name == NULL)
    {
        return 0;
    }
    for (uint32_t index = 0; index < ARRAY_SIZE(fields); ++index)
    {
        if (stringCompare(name, fields[index]) == 0)
        {
            return UINT32_C(1) << index;
        }
    }
    return 0;
}

bool ptcFakeDnsLoadSettings(ptc_tstate_t *ts, const cJSON *settings)
{
    if (settings == NULL)
    {
        return true;
    }

    const cJSON *fake_dns        = NULL;
    unsigned int aliases_present = 0;
    const cJSON *member;
    cJSON_ArrayForEach(member, settings)
    {
        if (! ptcFakeDnsIsAliasName(member->string))
        {
            continue;
        }
        ++aliases_present;
        if (fake_dns == NULL)
        {
            fake_dns = member;
        }
    }

    if (aliases_present > 1U)
    {
        LOGF("JSON Error: PacketsToConnection->settings contains ambiguous fake-DNS aliases; use exactly one of "
             "fake-dns, fake_dns, or mapdns");
        return false;
    }

    if (fake_dns == NULL)
    {
        return true;
    }

    const cJSON *fake_dns_object = NULL;
    bool         enabled         = true;

    if (cJSON_IsBool(fake_dns))
    {
        enabled = cJSON_IsTrue(fake_dns);
    }
    else if (cJSON_IsObject(fake_dns))
    {
        fake_dns_object      = fake_dns;
        uint32_t seen_fields = 0;
        cJSON_ArrayForEach(member, fake_dns_object)
        {
            const uint32_t field_bit = ptcFakeDnsFieldBit(member->string);
            if (field_bit == 0)
            {
                continue;
            }
            if ((seen_fields & field_bit) != 0)
            {
                LOGF("JSON Error: PacketsToConnection->settings->fake-dns contains duplicate field '%s'",
                     member->string);
                return false;
            }
            seen_fields |= field_bit;
        }
        if (! ptcFakeDnsLoadOptionalBoolean(
                fake_dns_object, "enabled", &enabled, "PacketsToConnection->settings->fake-dns->enabled"))
        {
            return false;
        }
    }
    else
    {
        LOGF("JSON Error: PacketsToConnection->settings->fake-dns must be a boolean or object");
        return false;
    }

    ip4_addr_t listen_addr;
    ip4_addr_t network;
    ip4_addr_t netmask;
    int64_t    port       = kPtcFakeDnsDefaultPort;
    int64_t    ttl        = kPtcFakeDnsDefaultTtl;
    int64_t    cache_size = kPtcFakeDnsDefaultRecords;

    if (! ptcFakeDnsLoadIpv4Setting(&listen_addr,
                                    fake_dns_object,
                                    "address",
                                    "198.18.0.2",
                                    "PacketsToConnection->settings->fake-dns->address") ||
        ! ptcFakeDnsLoadIpv4Setting(
            &network, fake_dns_object, "network", "100.64.0.0", "PacketsToConnection->settings->fake-dns->network") ||
        ! ptcFakeDnsLoadIpv4Setting(
            &netmask, fake_dns_object, "netmask", "255.192.0.0", "PacketsToConnection->settings->fake-dns->netmask"))
    {
        return false;
    }

    /*
     * ip4_output_if() substitutes the netif address for ANY. Multicast,
     * broadcast, and loopback are likewise not usable public reply identities
     * for this packet bridge. Reject them at configuration time instead of
     * publishing a listener whose wire source differs or is unroutable.
     */
    if (ip4_addr_isany_val(listen_addr) || ip4_addr_isloopback(&listen_addr) || ip4_addr_ismulticast(&listen_addr) ||
        ip4_addr_get_u32(&listen_addr) == IPADDR_BROADCAST)
    {
        LOGF("JSON Error: PacketsToConnection->settings->fake-dns->address must be a concrete non-loopback IPv4 "
             "unicast source");
        return false;
    }

    if (fake_dns_object != NULL &&
        (! ptcLoadOptionalInteger(
             fake_dns_object, "port", 1, UINT16_MAX, &port, "PacketsToConnection->settings->fake-dns->port") ||
         ! ptcLoadOptionalInteger(fake_dns_object,
                                  "ttl",
                                  0,
                                  (int64_t) kPtcFakeDnsMaxTtl,
                                  &ttl,
                                  "PacketsToConnection->settings->fake-dns->ttl") ||
         ! ptcLoadOptionalInteger(fake_dns_object,
                                  "cache-size",
                                  1,
                                  INT32_MAX,
                                  &cache_size,
                                  "PacketsToConnection->settings->fake-dns->cache-size")))
    {
        return false;
    }

    uint32_t netmask_host = lwip_ntohl(netmask.addr);
    uint32_t network_host = lwip_ntohl(network.addr) & netmask_host;
    uint32_t host_mask    = ~netmask_host;

    if ((host_mask & (host_mask + 1U)) != 0)
    {
        LOGF("JSON Error: PacketsToConnection->settings->fake-dns->netmask must be a contiguous IPv4 prefix mask");
        return false;
    }

    if (host_mask == 0 || (uint64_t) cache_size > (uint64_t) host_mask + 1U)
    {
        LOGF("JSON Error: PacketsToConnection->settings->fake-dns->cache-size does not fit in configured network");
        return false;
    }

    if (network_host == 0)
    {
        LOGF("JSON Error: PacketsToConnection->settings->fake-dns->network would reserve 0.0.0.0 as a fake address");
        return false;
    }

    const uint32_t listen_host = lwip_ntohl(listen_addr.addr);
    if ((listen_host & netmask_host) == network_host && (listen_host & host_mask) < (uint32_t) cache_size)
    {
        LOGF("JSON Error: PacketsToConnection->settings->fake-dns->address overlaps the allocated fake-IP record "
             "interval");
        return false;
    }

    ptc_fake_dns_geometry_t geometry;
    if (! ptcFakeDnsComputeGeometry((uint32_t) cache_size, &geometry))
    {
        LOGF("JSON Error: PacketsToConnection->settings->fake-dns->cache-size exceeds safe allocation geometry "
             "(maximum %u records)",
             (unsigned int) kPtcFakeDnsMaxRecords);
        return false;
    }

    if (! enabled)
    {
        return true;
    }

    const isize_t           map_capacity = geometry.map_capacity;
    ptc_fake_dns_name_map_t names        = ptc_fake_dns_name_map_t_with_capacity(map_capacity);
    ptc_fake_dns_entry_t  **records      = memoryAllocateZero(geometry.record_bytes);

    assert(ptc_fake_dns_name_map_t_capacity(&names) >= map_capacity);

    ptc_fake_dns_t *dns = &ts->fake_dns;
    dns->names          = names;
    dns->records        = records;
    dns->listen_addr    = listen_addr;
    dns->network_host   = network_host;
    dns->netmask_host   = netmask_host;
    dns->capacity       = (uint32_t) cache_size;
    dns->ttl            = (uint32_t) ttl;
    dns->listen_port    = (uint16_t) port;
    dns->enabled        = true;

    return true;
}

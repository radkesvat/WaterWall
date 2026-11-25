#include "PingCommon/ping_ipv4_node.h"

#include "loggers/network_logger.h"

/* Stable lowercase names for the assigned values in the IANA ICMPv4 registries.
 * Reserved and unassigned values are still expressible as integers.
 * https://www.iana.org/assignments/icmp-parameters/ */
static const struct
{
    uint8_t     type;
    const char *name;
} kIcmpTypes[] = {
    {0, "echo-reply"},
    {3, "destination-unreachable"},
    {4, "source-quench"},
    {5, "redirect"},
    {6, "alternate-host-address"},
    {8, "echo-request"},
    {8, "echo"},
    {9, "router-advertisement"},
    {10, "router-solicitation"},
    {11, "time-exceeded"},
    {12, "parameter-problem"},
    {13, "timestamp"},
    {14, "timestamp-reply"},
    {15, "information-request"},
    {16, "information-reply"},
    {17, "address-mask-request"},
    {18, "address-mask-reply"},
    {30, "traceroute"},
    {31, "datagram-conversion-error"},
    {32, "mobile-host-redirect"},
    {33, "ipv6-where-are-you"},
    {34, "ipv6-i-am-here"},
    {35, "mobile-registration-request"},
    {36, "mobile-registration-reply"},
    {37, "domain-name-request"},
    {38, "domain-name-reply"},
    {39, "skip"},
    {40, "photuris"},
    {41, "seamoby"},
    {42, "extended-echo-request"},
    {43, "extended-echo-reply"},
    {253, "experiment-1"},
    {254, "experiment-2"},
};

static const struct
{
    uint8_t     type;
    uint8_t     code;
    const char *name;
} kIcmpCodes[] = {
    {0, 0, "no-code"},
    {3, 0, "net-unreachable"},
    {3, 1, "host-unreachable"},
    {3, 2, "protocol-unreachable"},
    {3, 3, "port-unreachable"},
    {3, 4, "fragmentation-needed-and-dont-fragment-was-set"},
    {3, 5, "source-route-failed"},
    {3, 6, "destination-network-unknown"},
    {3, 7, "destination-host-unknown"},
    {3, 8, "source-host-isolated"},
    {3, 9, "communication-with-destination-network-is-administratively-prohibited"},
    {3, 10, "communication-with-destination-host-is-administratively-prohibited"},
    {3, 11, "destination-network-unreachable-for-type-of-service"},
    {3, 12, "destination-host-unreachable-for-type-of-service"},
    {3, 13, "communication-administratively-prohibited"},
    {3, 14, "host-precedence-violation"},
    {3, 15, "precedence-cutoff-in-effect"},
    {4, 0, "no-code"},
    {5, 0, "redirect-datagram-for-the-network-or-subnet"},
    {5, 1, "redirect-datagram-for-the-host"},
    {5, 2, "redirect-datagram-for-the-type-of-service-and-network"},
    {5, 3, "redirect-datagram-for-the-type-of-service-and-host"},
    {6, 0, "alternate-address-for-host"},
    {8, 0, "no-code"},
    {9, 0, "normal-router-advertisement"},
    {9, 16, "does-not-route-common-traffic"},
    {10, 0, "no-code"},
    {11, 0, "time-to-live-exceeded-in-transit"},
    {11, 1, "fragment-reassembly-time-exceeded"},
    {12, 0, "pointer-indicates-the-error"},
    {12, 1, "missing-a-required-option"},
    {12, 2, "bad-length"},
    {13, 0, "no-code"},
    {14, 0, "no-code"},
    {15, 0, "no-code"},
    {16, 0, "no-code"},
    {17, 0, "no-code"},
    {18, 0, "no-code"},
    {40, 0, "bad-spi"},
    {40, 1, "authentication-failed"},
    {40, 2, "decompression-failed"},
    {40, 3, "decryption-failed"},
    {40, 4, "need-authentication"},
    {40, 5, "need-authorization"},
    {42, 0, "no-error"},
    {43, 0, "no-error"},
    {43, 1, "malformed-query"},
    {43, 2, "no-such-interface"},
    {43, 3, "no-such-table-entry"},
    {43, 4, "multiple-interfaces-satisfy-query"},
};

typedef enum ping_ipv4_setting_e
{
    kPingIpv4Type,
    kPingIpv4Code,
    kPingIpv4SettingCount
} ping_ipv4_setting_t;

static const char *const kSettingNames[kPingIpv4SettingCount] = {
    [kPingIpv4Type] = "icmp-type",
    [kPingIpv4Code] = "icmp-code",
};

static bool pingipv4ReadType(const cJSON *item, uint8_t *type)
{
    int64_t value;
    if (item == NULL)
    {
        *type = 8;
        return true;
    }
    if (jsonGetIntegerInRange(item, 0, UINT8_MAX, &value))
    {
        *type = (uint8_t) value;
        return true;
    }
    if (cJSON_IsString(item))
    {
        for (size_t i = 0; i < ARRAY_SIZE(kIcmpTypes); ++i)
        {
            if (strcmp(item->valuestring, kIcmpTypes[i].name) == 0)
            {
                *type = kIcmpTypes[i].type;
                return true;
            }
        }
    }
    return false;
}

static bool pingipv4ReadCode(const cJSON *item, uint8_t type, uint8_t *code)
{
    int64_t value;
    if (item == NULL)
    {
        *code = 0;
        return true;
    }
    if (jsonGetIntegerInRange(item, 0, UINT8_MAX, &value))
    {
        *code = (uint8_t) value;
        return true;
    }
    if (cJSON_IsString(item))
    {
        for (size_t i = 0; i < ARRAY_SIZE(kIcmpCodes); ++i)
        {
            if (kIcmpCodes[i].type == type && strcmp(item->valuestring, kIcmpCodes[i].name) == 0)
            {
                *code = kIcmpCodes[i].code;
                return true;
            }
        }
    }
    return false;
}

bool pingipv4ReadSettings(const node_t *node, ping_ipv4_config_t *config)
{
    const cJSON *settings = node->node_settings_json;
    const char  *name     = node->type;
    if (settings != NULL && ! cJSON_IsObject(settings))
    {
        LOGF("%s: settings must be an object", name);
        return false;
    }

    const cJSON *fields[kPingIpv4SettingCount] = {0};
    for (const cJSON *item = settings != NULL ? settings->child : NULL; item != NULL; item = item->next)
    {
        size_t setting = 0;
        while (setting < ARRAY_SIZE(kSettingNames) &&
               (item->string == NULL || strcmp(item->string, kSettingNames[setting]) != 0))
        {
            ++setting;
        }
        if (setting == ARRAY_SIZE(kSettingNames))
        {
            LOGF("%s: unknown setting '%s'", name, item->string != NULL ? item->string : "<unnamed>");
            return false;
        }
        if (fields[setting] != NULL || ! jsonObjectFieldStringsAreExact(settings, kSettingNames[setting]))
        {
            LOGF("%s: duplicate or invalid setting '%s'", name, kSettingNames[setting]);
            return false;
        }
        fields[setting] = item;
    }

    if (! pingipv4ReadType(fields[kPingIpv4Type], &config->type))
    {
        LOGF("%s: icmp-type must be an integer from 0 to 255 or a recognized ICMPv4 type name", name);
        return false;
    }
    if (! pingipv4ReadCode(fields[kPingIpv4Code], config->type, &config->code))
    {
        LOGF("%s: icmp-code must be an integer from 0 to 255 or a recognized code name for ICMPv4 type %u",
             name,
             (unsigned int) config->type);
        return false;
    }
    return true;
}

#pragma once

#include "wwapi.h"

#include "lwip/prot/ip4.h"

enum
{
    kPingIpv4IcmpPrefixLength = 8,
    kPingIpv4TrailerLength    = 2,
    kPingIpv4Overhead         = kPingIpv4IcmpPrefixLength + kPingIpv4TrailerLength,
    kPingIpv4MaxInnerLength   = kMaxAllowedPacketLength - kPingIpv4Overhead,
};

typedef enum ping_ipv4_role_e
{
    kPingIpv4Client = 1,
    kPingIpv4Server = 2,
} ping_ipv4_role_t;

typedef struct ping_ipv4_config_s
{
    uint8_t          type;
    uint8_t          code;
    ping_ipv4_role_t role;
} ping_ipv4_config_t;

/* Transform an owned resident packet in place. Return NULL on success or a
 * static drop reason on refusal. The caller retains ownership either way. */
const char *pingipv4Encode(sbuf_t *buf, const ping_ipv4_config_t *config);
const char *pingipv4Decode(sbuf_t *buf, const ping_ipv4_config_t *config);

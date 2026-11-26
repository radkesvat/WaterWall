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
    uint16_t         identifier;
    ping_ipv4_role_t role;
} ping_ipv4_config_t;

/* Transform an owned resident packet in place. Return NULL on success or a
 * static drop reason on refusal. The caller retains ownership either way.
 * A non-NULL sequence counter enables transmit identifier and sequence fields.
 * With a reply pool, decode may also return a separately owned Echo Reply. */
const char *pingipv4Encode(sbuf_t *buf, const ping_ipv4_config_t *config, atomic_u32_t *next_sequence);
const char *pingipv4Decode(sbuf_t *buf, const ping_ipv4_config_t *config, buffer_pool_t *reply_pool,
                           sbuf_t **reply_out);

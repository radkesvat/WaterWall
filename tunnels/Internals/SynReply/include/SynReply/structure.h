#pragma once

#include "wwapi.h"

typedef struct synreply_tstate_s
{
    uint32_t reply_source_ip;
    uint8_t  ttl;
    bool     has_reply_source_ip;
    bool     fake_checksum;
} synreply_tstate_t;

static inline bool synreplyAddressAllowsReply(uint32_t address_network)
{
    const ip4_addr_t address = {.addr = address_network};
    return ! ip4_addr_isany_val(address) && address_network != IPADDR_BROADCAST && ! ip4_addr_ismulticast(&address);
}

#pragma once

#include "common_types.h"


typedef struct inbounds_s
{
    uint64_t hashes[50];
    size_t len;

} inbounds_t;

typedef struct router_rule_s
{
    unsigned rule_by_inbound:1;
    unsigned rule_by_ip:1;
    unsigned rule_by_protocol:1;
    unsigned rule_by_domain:1;

    inbounds_t selected_inbounds;
    uint64_t outbound;

    //other rule matchers require more fields here

} router_rule_t;




void find_or_create_outbound(dest_context dest,);

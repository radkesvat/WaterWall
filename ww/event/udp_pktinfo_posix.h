#pragma once

#include "wsocket.h"

#include <sys/uio.h>

/* An aligned control buffer with room for either family's packet info. */
typedef union udp_packet_control_u {
    max_align_t   alignment;
    unsigned char bytes[CMSG_SPACE(sizeof(struct sockaddr_storage))];
} udp_packet_control_t;

/* BSD and System V macros differ in their expected byte order. */
static inline bool udpIPv4GroupAddress(struct in_addr address)
{
    return address.s_addr == INADDR_BROADCAST || (ntohl(address.s_addr) >> 28) == 0xe;
}

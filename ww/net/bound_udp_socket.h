#pragma once
#include "wlibc.h"
#include "wloop.h"
#include "wsocket.h"

typedef enum bound_udp_bind_policy_e
{
    kBoundUdpBindPolicyDefault   = 0,
    kBoundUdpBindPolicyExclusive = 1,
    kBoundUdpBindPolicyReusable  = 2,
} bound_udp_bind_policy_t;

typedef struct bound_udp_config_s
{
    const char             *bind_address;
    uint16_t                port;
    const char             *interface_name;
    int                     fwmark; /* -1 disables socket marking. */
    uint32_t                send_buffer_size;
    uint32_t                recv_buffer_size;
    bound_udp_bind_policy_t bind_policy;
    bool                    source_ip_configured;
} bound_udp_config_t;

/**
 * @brief Create and bind a UDP socket wrapped in a WIO on the given event loop.
 *
 * Honors exclusive vs reusable bind policy, applies interface/fwmark/buffer options,
 * and recovers the kernel-assigned local address and port via getsockname() (essential for port 0).
 *
 * @param loop Event loop to own the created WIO.
 * @param config Configuration specifying bind address, port, options, and policy.
 * @return Bound wio_t pointer on success, or NULL on error.
 */
wio_t *boundUdpSocketCreate(wloop_t *loop, const bound_udp_config_t *config);

#include "structure.h"

#include "loggers/network_logger.h"

bool tcpconnectorApplyFreeBindRandomDestIp(address_context_t *dest_ctx, uint64_t outbound_ip_range)
{
    assert(dest_ctx->type_ip);
    switch (dest_ctx->ip_address.type)
    {
    case IPADDR_TYPE_V4:
        // no probelm if overflows
        {
            const uint32_t large_random = fastRand32() % outbound_ip_range;
            uint32_t       calc         = ntohl((uint32_t) dest_ctx->ip_address.u_addr.ip4.addr);
            calc                        = calc & ~(((uint32_t) outbound_ip_range) - 1U);
            calc                        = htonl(calc + large_random);

            memoryCopy(&(dest_ctx->ip_address.u_addr.ip4), &calc, sizeof(struct in_addr));
        }
        break;
    case IPADDR_TYPE_V6:
        // no probelm if overflows
        {
            const bool     full_host_range = outbound_ip_range == UINT64_MAX;
            const uint64_t host_mask       = full_host_range ? UINT64_MAX : outbound_ip_range - 1U;
            const uint64_t large_random    = full_host_range ? fastRand64() : fastRand64() % outbound_ip_range;
            uint64_t       calc;
            memoryCopy(&calc, 8 + ((const char *) &dest_ctx->ip_address.u_addr.ip6), sizeof(calc));
            calc          = ntohll(calc) & ~host_mask;
            calc          = htonll(calc + large_random);

            memoryCopy(8 + ((char *) &(dest_ctx->ip_address.u_addr.ip6)), &calc, sizeof(calc));
        }
        break;

    default:
        LOGE("TcpConnector: invalid destination address family");
        return false;
    }
    return true;
}

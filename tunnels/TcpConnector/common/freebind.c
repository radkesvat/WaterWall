#include "structure.h"

#include "loggers/network_logger.h"

bool tcpconnectorApplyFreeBindRandomDestIp(tunnel_t* t,address_context_t *dest_ctx)
{

    tcpconnector_tstate_t* state = tunnelGetState(t);

    assert(dest_ctx->type_ip);
    switch (dest_ctx->ip_address.type)
    {
    case AF_INET:
        // no probelm if overflows
        {
            const uint32_t large_random = fastRand32() % state->outbound_ip_range;
            uint32_t calc = ntohl((uint32_t) dest_ctx->ip_address.u_addr.ip4.addr);
            calc          = calc & ~(((uint32_t)state->outbound_ip_range) - 1U);
            calc          = htonl(calc + large_random);

            memoryCopy(&(dest_ctx->ip_address.u_addr.ip4), &calc, sizeof(struct in_addr));
        }
        break;
    case AF_INET6:
        // no probelm if overflows
        {
            const uint64_t large_random = fastRand64() % state->outbound_ip_range;
            uint64_t *addr_ptr = (uint64_t *) &dest_ctx->ip_address.u_addr.ip6;
            addr_ptr += 1;

            uint64_t calc = ntohll(*addr_ptr);
            calc          = calc & ~(state->outbound_ip_range - 1ULL);
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


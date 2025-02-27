// Remember to define _CRT_RAND_S before you include
// stdlib.h.
#define _CRT_RAND_S
#include "structure.h"

#include "loggers/network_logger.h"

bool tcpconnectorApplyFreeBindRandomDestIp(tunnel_t* t,address_context_t *dest_ctx)
{

    tcpconnector_tstate_t* state = tunnelGetState(t);

    unsigned int seed = fastRand();
    assert(dest_ctx->type_ip);
    switch (dest_ctx->ip_address.type)
    {
    case AF_INET:
        // no probelm if overflows
        {
#ifdef OS_UNIX
            const uint32_t large_random = (uint32_t)(((uint64_t) rand_r(&seed)) % state->outbound_ip_range);
#else
            const uint32_t large_random = (uint32_t)(((uint64_t) rand_s(&seed)) % state->outbound_ip_range);
#endif
            uint32_t calc = ntohl((uint32_t) dest_ctx->ip_address.u_addr.ip4.addr);
            calc          = calc & ~(((uint32_t)state->outbound_ip_range) - 1U);
            calc          = htonl(calc + large_random);

            memoryCopy(&(dest_ctx->ip_address.u_addr.ip4), &calc, sizeof(struct in_addr));
        }
        break;
    case AF_INET6:
        // no probelm if overflows
        {
#ifdef OS_UNIX
            const uint64_t large_random = (((uint64_t) rand_r(&seed)) % state->outbound_ip_range);
#else
            const uint64_t large_random = (((uint64_t) rand_s(&seed)) % state->outbound_ip_range);
#endif
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


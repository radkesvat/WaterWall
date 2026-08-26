#include "bound_udp_socket.h"
#include "egress_pin.h"

wio_t *boundUdpSocketCreate(wloop_t *loop, const bound_udp_config_t *config)
{
    if (loop == NULL || config == NULL)
    {
        return NULL;
    }

    /* socketOptionApply* accepts an int length. Reject an unrepresentable
     * request before publishing any OS resource instead of narrowing it. */
    if (config->send_buffer_size > (uint32_t) INT_MAX || config->recv_buffer_size > (uint32_t) INT_MAX)
    {
        return NULL;
    }

    char        interface_ip[INET_ADDRSTRLEN] = {0};
    const char *bind_address                  = config->bind_address;

    if (config->interface_name != NULL && ! config->source_ip_configured && ! socketOptionBindToDeviceSupported())
    {
        if (! getInterfaceIpString(config->interface_name, interface_ip, sizeof(interface_ip)))
        {
            return NULL;
        }
        bind_address = interface_ip;
    }

    if (bind_address == NULL || bind_address[0] == '\0')
    {
        bind_address = "0.0.0.0";
    }

    sockaddr_u addr = {0};
    if (sockaddrSetIpAddressPort(&addr, bind_address, config->port) != 0)
    {
        return NULL;
    }

    int sockfd = socketToFd(socket(addr.sa.sa_family, SOCK_DGRAM, 0));
    if (sockfd < 0)
    {
        return NULL;
    }

    if (socketOptionBindToDevice(sockfd, config->interface_name) != 0)
    {
        closesocket(sockfd);
        return NULL;
    }

    if (egressPinApply(sockfd, addr.sa.sa_family, config->interface_name) != 0)
    {
        closesocket(sockfd);
        return NULL;
    }

    if (config->fwmark >= 0 && socketOptionSetFwMark(sockfd, config->fwmark) != 0)
    {
        closesocket(sockfd);
        return NULL;
    }

    bound_udp_bind_policy_t policy = config->bind_policy;
    if (policy == kBoundUdpBindPolicyDefault)
    {
        policy = (config->port == 0) ? kBoundUdpBindPolicyExclusive : kBoundUdpBindPolicyReusable;
    }

    if (policy == kBoundUdpBindPolicyExclusive)
    {
        if (socketOptionExclusiveAddrUse(sockfd, 1) != 0)
        {
            closesocket(sockfd);
            return NULL;
        }
    }
    else if (policy == kBoundUdpBindPolicyReusable)
    {
        if (socketOptionServerAddressUse(sockfd) != 0)
        {
            closesocket(sockfd);
            return NULL;
        }
    }

    if (addr.sa.sa_family == AF_INET6)
    {
        ipV6Only(sockfd, 0);
    }

    if (bind(sockfd, &addr.sa, sockaddrLen(&addr)) < 0)
    {
        closesocket(sockfd);
        return NULL;
    }

    /* Zero is intentional: the node parser materializes its true/default value
     * as kDefaultLargeSocketBufferSize, while an explicit false leaves the
     * kernel defaults untouched. */
    if (! socketOptionApplySendBuffer(sockfd, (int) config->send_buffer_size) ||
        ! socketOptionApplyRecvBuffer(sockfd, (int) config->recv_buffer_size))
    {
        closesocket(sockfd);
        return NULL;
    }

    sockaddr_u local_addr = {0};
    socklen_t  addr_len   = sizeof(local_addr);
    if (getsockname(sockfd, &local_addr.sa, &addr_len) < 0 || sockaddrPort(&local_addr) == 0)
    {
        closesocket(sockfd);
        return NULL;
    }

    wio_t *io = wioGet(loop, sockfd);
    if (io == NULL || wioIsClosed(io))
    {
        if (io == NULL)
        {
            closesocket(sockfd);
        }
        return NULL;
    }

    wioSetType(io, WIO_TYPE_UDP);
    wioSetLocaladdr(io, &local_addr.sa, (int) addr_len);
    weventSetPriority(io, WEVENT_HIGH_PRIORITY);

    return io;
}

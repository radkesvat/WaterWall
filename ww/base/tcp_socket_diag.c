#include "tcp_socket_diag.h"

#if defined(OS_LINUX) && ! defined(OS_CYGWIN) && ! defined(OS_ANDROID)

#include <linux/inet_diag.h>
#include <linux/netlink.h>
#include <linux/sock_diag.h>

static bool tcpDiagAddressEqual(unsigned int left_family, const uint32_t left[4], unsigned int right_family,
                                const uint32_t right[4])
{
    if (left_family == right_family)
    {
        return memcmp(left, right, left_family == AF_INET ? sizeof(uint32_t) : 4 * sizeof(uint32_t)) == 0;
    }
    if (left_family == AF_INET && right_family == AF_INET6)
    {
        return right[0] == 0 && right[1] == 0 && right[2] == htonl(0xffff) && left[0] == right[3];
    }
    if (left_family == AF_INET6 && right_family == AF_INET)
    {
        return left[0] == 0 && left[1] == 0 && left[2] == htonl(0xffff) && left[3] == right[0];
    }
    return false;
}

static bool tcpDiagHasWriteShutdown(const struct nlmsghdr *header, size_t size, const struct inet_diag_req_v2 *request)
{
    if (size < NLMSG_LENGTH(sizeof(struct inet_diag_msg)) || header->nlmsg_len > size ||
        header->nlmsg_len < NLMSG_LENGTH(sizeof(struct inet_diag_msg)) || header->nlmsg_type != SOCK_DIAG_BY_FAMILY ||
        header->nlmsg_seq != 1 || (header->nlmsg_flags & NLM_F_MULTI) != 0)
    {
        return false;
    }

    const struct inet_diag_msg *reply = NLMSG_DATA(header);
    if ((reply->idiag_family != AF_INET && reply->idiag_family != AF_INET6) ||
        (reply->idiag_state != TCP_FIN_WAIT1 && reply->idiag_state != TCP_FIN_WAIT2) ||
        reply->id.idiag_sport != request->id.idiag_sport || reply->id.idiag_dport != request->id.idiag_dport ||
        (request->id.idiag_if != 0 && reply->id.idiag_if != request->id.idiag_if) ||
        ! tcpDiagAddressEqual(reply->idiag_family, reply->id.idiag_src, request->sdiag_family, request->id.idiag_src) ||
        ! tcpDiagAddressEqual(reply->idiag_family, reply->id.idiag_dst, request->sdiag_family, request->id.idiag_dst))
    {
        return false;
    }

    size_t               remaining = header->nlmsg_len - NLMSG_LENGTH(sizeof(*reply));
    const unsigned char *cursor    = (const unsigned char *) reply + NLMSG_ALIGN(sizeof(*reply));
    bool                 found     = false;
    while (remaining >= NLA_HDRLEN)
    {
        const struct nlattr *attribute = (const struct nlattr *) cursor;
        size_t               length    = attribute->nla_len;
        if (length < NLA_HDRLEN || length > remaining || NLA_ALIGN(length) > remaining)
        {
            return false;
        }
        if (attribute->nla_type == INET_DIAG_SHUTDOWN)
        {
            if (found || length != NLA_HDRLEN + sizeof(uint8_t) || cursor[NLA_HDRLEN] != 2)
            {
                return false;
            }
            found = true;
        }
        cursor += NLA_ALIGN(length);
        remaining -= NLA_ALIGN(length);
    }
    return found && remaining == 0;
}

bool tcpSocketPeerHasWriteShutdown(int fd)
{
    struct sockaddr_storage local       = {0};
    struct sockaddr_storage peer        = {0};
    socklen_t               local_size  = sizeof(local);
    socklen_t               peer_size   = sizeof(peer);
    int                     protocol    = 0;
    socklen_t               option_size = sizeof(protocol);
    if (getsockopt(fd, SOL_SOCKET, SO_PROTOCOL, &protocol, &option_size) != 0 || protocol != IPPROTO_TCP ||
        getsockname(fd, (struct sockaddr *) &local, &local_size) != 0 ||
        getpeername(fd, (struct sockaddr *) &peer, &peer_size) != 0 || local.ss_family != peer.ss_family)
    {
        return false;
    }

    struct
    {
        struct nlmsghdr         header;
        struct inet_diag_req_v2 body;
    } request                       = {0};
    request.header.nlmsg_len        = NLMSG_LENGTH(sizeof(request.body));
    request.header.nlmsg_type       = SOCK_DIAG_BY_FAMILY;
    request.header.nlmsg_flags      = NLM_F_REQUEST;
    request.header.nlmsg_seq        = 1;
    request.body.sdiag_family       = (uint8_t) peer.ss_family;
    request.body.sdiag_protocol     = IPPROTO_TCP;
    request.body.idiag_states       = (1U << TCP_FIN_WAIT1) | (1U << TCP_FIN_WAIT2);
    request.body.id.idiag_cookie[0] = INET_DIAG_NOCOOKIE;
    request.body.id.idiag_cookie[1] = INET_DIAG_NOCOOKIE;

    if (peer.ss_family == AF_INET && local_size >= sizeof(struct sockaddr_in) &&
        peer_size >= sizeof(struct sockaddr_in))
    {
        const struct sockaddr_in *source = (const struct sockaddr_in *) &peer;
        const struct sockaddr_in *dest   = (const struct sockaddr_in *) &local;
        request.body.id.idiag_sport      = source->sin_port;
        request.body.id.idiag_dport      = dest->sin_port;
        request.body.id.idiag_src[0]     = source->sin_addr.s_addr;
        request.body.id.idiag_dst[0]     = dest->sin_addr.s_addr;
    }
    else if (peer.ss_family == AF_INET6 && local_size >= sizeof(struct sockaddr_in6) &&
             peer_size >= sizeof(struct sockaddr_in6))
    {
        const struct sockaddr_in6 *source = (const struct sockaddr_in6 *) &peer;
        const struct sockaddr_in6 *dest   = (const struct sockaddr_in6 *) &local;
        request.body.id.idiag_sport       = source->sin6_port;
        request.body.id.idiag_dport       = dest->sin6_port;
        request.body.id.idiag_if          = source->sin6_scope_id;
        memcpy(request.body.id.idiag_src, &source->sin6_addr, sizeof(source->sin6_addr));
        memcpy(request.body.id.idiag_dst, &dest->sin6_addr, sizeof(dest->sin6_addr));
    }
    else
    {
        return false;
    }

    int diagnostic_fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK, NETLINK_SOCK_DIAG);
    if (diagnostic_fd < 0)
    {
        return false;
    }

    struct sockaddr_nl kernel = {.nl_family = AF_NETLINK};
    bool               result = false;
    if (sendto(diagnostic_fd,
               &request,
               request.header.nlmsg_len,
               MSG_DONTWAIT,
               (struct sockaddr *) &kernel,
               sizeof(kernel)) == (ssize_t) request.header.nlmsg_len)
    {
        union {
            struct nlmsghdr alignment;
            unsigned char   bytes[4096];
        } response;
        struct sockaddr_nl sender  = {0};
        struct iovec       vector  = {.iov_base = response.bytes, .iov_len = sizeof(response.bytes)};
        struct msghdr      message = {
                 .msg_name = &sender, .msg_namelen = sizeof(sender), .msg_iov = &vector, .msg_iovlen = 1};
        ssize_t received = recvmsg(diagnostic_fd, &message, MSG_DONTWAIT);
        if (received > 0 && (message.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) == 0 &&
            message.msg_namelen >= sizeof(sender) && sender.nl_family == AF_NETLINK && sender.nl_pid == 0)
        {
            result =
                tcpDiagHasWriteShutdown((const struct nlmsghdr *) response.bytes, (size_t) received, &request.body);
        }
    }
    close(diagnostic_fd);
    return result;
}

#else

bool tcpSocketPeerHasWriteShutdown(int fd)
{
    (void) fd;
    return false;
}

#endif

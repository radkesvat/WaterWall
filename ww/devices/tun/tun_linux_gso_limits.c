#include "tun_linux_gso_limits.h"

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <linux/if_link.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <poll.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

enum
{
    kNetlinkReplyCapacity  = 16384,
    kNetlinkReplyTimeoutMs = 1000
};

typedef struct tun_linux_link_request_s
{
    struct nlmsghdr  header;
    struct ifinfomsg link;
    struct rtattr    attribute;
    uint32_t         max_segments;
} tun_linux_link_request_t;

static bool tunLinuxGsoSendRequest(int fd, uint16_t type, uint16_t flags, uint32_t sequence, int ifindex,
                                   const uint32_t *max_segments)
{
    tun_linux_link_request_t request = {0};
    request.header.nlmsg_type        = type;
    request.header.nlmsg_flags       = flags;
    request.header.nlmsg_seq         = sequence;
    request.header.nlmsg_len         = NLMSG_LENGTH(sizeof(request.link));
    request.link.ifi_family          = AF_UNSPEC;
    request.link.ifi_index           = ifindex;

    if (max_segments != NULL)
    {
        request.attribute.rta_type = IFLA_GSO_MAX_SEGS;
        request.attribute.rta_len  = RTA_LENGTH(sizeof(request.max_segments));
        request.max_segments       = *max_segments;
        request.header.nlmsg_len   = NLMSG_ALIGN(request.header.nlmsg_len) + request.attribute.rta_len;
    }

    struct sockaddr_nl kernel = {0};
    kernel.nl_family          = AF_NETLINK;

    ssize_t sent = sendto(fd, &request, request.header.nlmsg_len, 0, (const struct sockaddr *) &kernel, sizeof(kernel));
    if (sent < 0)
    {
        return false;
    }
    if ((uint32_t) sent != request.header.nlmsg_len)
    {
        errno = EIO;
        return false;
    }
    return true;
}

static bool tunLinuxGsoReadActive(const struct nlmsghdr *header, int ifindex, uint32_t *active)
{
    if (header->nlmsg_len < NLMSG_LENGTH(sizeof(struct ifinfomsg)))
    {
        errno = EPROTO;
        return false;
    }

    const struct ifinfomsg *link = NLMSG_DATA(header);
    if (link->ifi_index != ifindex)
    {
        errno = EPROTO;
        return false;
    }

    int                  remaining = IFLA_PAYLOAD(header);
    const struct rtattr *attribute = IFLA_RTA(link);
    while (RTA_OK(attribute, remaining))
    {
        if (attribute->rta_type == IFLA_GSO_MAX_SEGS)
        {
            if (RTA_PAYLOAD(attribute) != sizeof(*active))
            {
                errno = EPROTO;
                return false;
            }
            memcpy(active, RTA_DATA(attribute), sizeof(*active));
            return true;
        }
        attribute = RTA_NEXT(attribute, remaining);
    }

    errno = remaining == 0 ? ENODATA : EPROTO;
    return false;
}

static bool tunLinuxGsoWaitForReply(int fd, uint32_t sequence, uint16_t expected_type, int ifindex, uint32_t *active)
{
    for (;;)
    {
        struct pollfd poll_fd = {.fd = fd, .events = POLLIN};
        int           ready   = poll(&poll_fd, 1, kNetlinkReplyTimeoutMs);
        if (ready < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }
            return false;
        }
        if (ready == 0)
        {
            errno = ETIMEDOUT;
            return false;
        }
        if ((poll_fd.revents & POLLIN) == 0)
        {
            errno = EIO;
            return false;
        }

        union {
            struct nlmsghdr alignment;
            uint8_t         bytes[kNetlinkReplyCapacity];
        } reply;
        struct sockaddr_nl sender = {0};
        struct iovec       iov    = {.iov_base = reply.bytes, .iov_len = sizeof(reply.bytes)};
        struct msghdr      msg = {.msg_name = &sender, .msg_namelen = sizeof(sender), .msg_iov = &iov, .msg_iovlen = 1};

        ssize_t received = recvmsg(fd, &msg, 0);
        if (received < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }
            return false;
        }
        if ((msg.msg_flags & MSG_TRUNC) != 0)
        {
            errno = EMSGSIZE;
            return false;
        }
        if (msg.msg_namelen < sizeof(sender) || sender.nl_pid != 0 || received > INT_MAX)
        {
            errno = EPROTO;
            return false;
        }

        int              remaining = (int) received;
        struct nlmsghdr *header    = (struct nlmsghdr *) reply.bytes;
        while (NLMSG_OK(header, remaining))
        {
            if (header->nlmsg_seq == sequence)
            {
                if (header->nlmsg_type == NLMSG_ERROR)
                {
                    if (header->nlmsg_len < NLMSG_LENGTH(sizeof(struct nlmsgerr)))
                    {
                        errno = EPROTO;
                        return false;
                    }
                    const struct nlmsgerr *error = NLMSG_DATA(header);
                    if (error->error < 0)
                    {
                        errno = -error->error;
                        return false;
                    }
                    if (error->error > 0)
                    {
                        errno = EPROTO;
                        return false;
                    }
                    if (expected_type == NLMSG_ERROR)
                    {
                        return true;
                    }
                }
                else if (header->nlmsg_type == expected_type)
                {
                    return tunLinuxGsoReadActive(header, ifindex, active);
                }
                else
                {
                    errno = EPROTO;
                    return false;
                }
            }
            header = NLMSG_NEXT(header, remaining);
        }
        if (remaining != 0)
        {
            errno = EPROTO;
            return false;
        }
    }
}

bool tunLinuxGsoMaxSegmentsConfigure(const char *ifname, uint32_t requested, uint32_t *active)
{
    assert(ifname != NULL);
    assert(requested > 0 && requested <= UINT16_MAX);
    assert(active != NULL);

    *active              = 0;
    unsigned int ifindex = if_nametoindex(ifname);
    if (ifindex == 0)
    {
        return false;
    }
    if (ifindex > INT_MAX)
    {
        errno = EOVERFLOW;
        return false;
    }

    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (fd < 0)
    {
        return false;
    }

    struct sockaddr_nl local = {0};
    local.nl_family          = AF_NETLINK;
    bool sent_and_acked      = false;
    int  set_error           = 0;
    if (bind(fd, (const struct sockaddr *) &local, sizeof(local)) != 0)
    {
        set_error = errno;
        goto done;
    }

    if (! tunLinuxGsoSendRequest(fd, RTM_NEWLINK, NLM_F_REQUEST | NLM_F_ACK, 1, (int) ifindex, &requested) ||
        ! tunLinuxGsoWaitForReply(fd, 1, NLMSG_ERROR, (int) ifindex, active))
    {
        set_error = errno;
    }
    else
    {
        sent_and_acked = true;
    }

    if (! tunLinuxGsoSendRequest(fd, RTM_GETLINK, NLM_F_REQUEST, 2, (int) ifindex, NULL) ||
        ! tunLinuxGsoWaitForReply(fd, 2, RTM_NEWLINK, (int) ifindex, active))
    {
        if (sent_and_acked)
        {
            set_error = errno;
        }
        goto done;
    }

    if (sent_and_acked && *active != requested)
    {
        set_error = ERANGE;
    }

done:
    close(fd);
    if (set_error != 0)
    {
        errno = set_error;
        return false;
    }
    errno = 0;
    return sent_and_acked;
}

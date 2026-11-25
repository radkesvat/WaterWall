#include "udp_pktinfo_win.h"
#include "wloop_internal.h"

bool wioEnableDatagramLocalAddress(wio_t *io)
{
    assert(io->io_type == WIO_TYPE_UDP);
    int   fd      = wioGetFD(io);
    DWORD enabled = 1;
    if (io->localaddr->sa_family == AF_INET6)
    {
        if (setsockopt(fd, IPPROTO_IPV6, IPV6_PKTINFO, (const char *) &enabled, sizeof(enabled)) != 0)
            return false;
        DWORD v6_only = 0;
        int   size    = sizeof(v6_only);
        if (getsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, (char *) &v6_only, &size) != 0)
            return false;
        if (! v6_only && setsockopt(fd, IPPROTO_IP, IP_PKTINFO, (const char *) &enabled, sizeof(enabled)) != 0)
            return false;
    }
    else if (setsockopt(fd, IPPROTO_IP, IP_PKTINFO, (const char *) &enabled, sizeof(enabled)) != 0)
        return false;

    GUID  recv_id  = WSAID_WSARECVMSG;
    DWORD returned = 0;
    if (WSAIoctl(fd,
                 SIO_GET_EXTENSION_FUNCTION_POINTER,
                 &recv_id,
                 sizeof(recv_id),
                 &io->udp_recvmsg,
                 sizeof(io->udp_recvmsg),
                 &returned,
                 NULL,
                 NULL) != 0)
        return false;
    io->udp_track_local_address = true;
    return true;
}

void udpWinPrepareReceive(udp_win_receive_t *receive, WSABUF *buffer, struct sockaddr *peer, int peer_size)
{
    receive->message = (WSAMSG) {.name          = peer,
                                 .namelen       = peer_size,
                                 .lpBuffers     = buffer,
                                 .dwBufferCount = 1,
                                 .Control = {.len = sizeof(receive->control.bytes), .buf = receive->control.bytes}};
}

void udpWinReadLocalAddress(wio_t *io, udp_win_receive_t *receive)
{
    WSAMSG *message       = &receive->message;
    io->udp_local_address = (sockaddr_u) {0};
    io->udp_reply_address = (sockaddr_u) {0};
    if ((message->dwFlags & (MSG_CTRUNC | MSG_TRUNC)) != 0)
        return;
    for (WSACMSGHDR *cmsg = WSA_CMSG_FIRSTHDR(message); cmsg != NULL;
         cmsg             = UDP_WIN_CMSG(WSA_CMSG_NXTHDR(message, cmsg)))
    {
        if (cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_PKTINFO &&
            cmsg->cmsg_len >= WSA_CMSG_LEN(sizeof(IN_PKTINFO)))
        {
            IN_PKTINFO info;
            memcpy(&info, WSA_CMSG_DATA(cmsg), sizeof(info));
            if (info.ipi_addr.s_addr == INADDR_ANY)
                return;
            io->udp_local_address.sin.sin_family = AF_INET;
            io->udp_local_address.sin.sin_addr   = info.ipi_addr;
            break;
        }
        if (cmsg->cmsg_level == IPPROTO_IPV6 && cmsg->cmsg_type == IPV6_PKTINFO &&
            cmsg->cmsg_len >= WSA_CMSG_LEN(sizeof(IN6_PKTINFO)))
        {
            IN6_PKTINFO info;
            memcpy(&info, WSA_CMSG_DATA(cmsg), sizeof(info));
            if (IN6_IS_ADDR_UNSPECIFIED(&info.ipi6_addr))
                return;
            io->udp_local_address.sin6.sin6_family = AF_INET6;
            io->udp_local_address.sin6.sin6_addr   = info.ipi6_addr;
            if (IN6_IS_ADDR_LINKLOCAL(&info.ipi6_addr))
                io->udp_local_address.sin6.sin6_scope_id = info.ipi6_ifindex;
            break;
        }
    }
    // Winsock supplies the destination and flags group deliveries. For those
    // deliveries the socket chooses a usable unicast source when replying.
    if ((message->dwFlags & (MSG_BCAST | MSG_MCAST)) == 0)
        io->udp_reply_address = io->udp_local_address;
}

int udpWinReadDatagram(wio_t *io, void *bytes, unsigned int length)
{
    WSABUF            buffer = {.len = length, .buf = bytes};
    udp_win_receive_t receive;
    udpWinPrepareReceive(&receive, &buffer, io->peeraddr, sizeof(sockaddr_u));
    DWORD received = 0;
    if (io->udp_recvmsg(wioGetFD(io), &receive.message, &received, NULL, NULL) != 0)
        return udpWinIsTruncationError(WSAGetLastError()) ? kNioReadDropped : -1;
    udpWinReadLocalAddress(io, &receive);
    return io->udp_local_address.sa.sa_family == AF_UNSPEC ? kNioReadDropped : (int) received;
}

int udpWinSendFrom(int fd, const void *bytes, size_t length, const sockaddr_u *peer, const sockaddr_u *local)
{
    assert(local->sa.sa_family == AF_INET || local->sa.sa_family == AF_INET6);
    udp_win_control_t control = {0};
    WSABUF            buffer  = {.len = (ULONG) length, .buf = (char *) bytes};
    WSAMSG            message = {.name          = (struct sockaddr *) &peer->sa,
                                 .namelen       = SOCKADDR_LEN(peer),
                                 .lpBuffers     = &buffer,
                                 .dwBufferCount = 1,
                                 .Control       = {.buf = control.bytes}};
    WSACMSGHDR       *cmsg    = &control.aligned;
    if (local->sa.sa_family == AF_INET || IN6_IS_ADDR_V4MAPPED(&local->sin6.sin6_addr))
    {
        IN_PKTINFO info = {0};
        if (local->sa.sa_family == AF_INET)
            info.ipi_addr = local->sin.sin_addr;
        else
            memcpy(&info.ipi_addr, &local->sin6.sin6_addr.s6_addr[12], sizeof(info.ipi_addr));
        cmsg->cmsg_level    = IPPROTO_IP;
        cmsg->cmsg_type     = IP_PKTINFO;
        cmsg->cmsg_len      = WSA_CMSG_LEN(sizeof(info));
        message.Control.len = UDP_WIN_CMSG(WSA_CMSG_SPACE(sizeof(info)));
        memcpy(WSA_CMSG_DATA(cmsg), &info, sizeof(info));
    }
    else
    {
        IN6_PKTINFO info    = {.ipi6_addr = local->sin6.sin6_addr, .ipi6_ifindex = local->sin6.sin6_scope_id};
        cmsg->cmsg_level    = IPPROTO_IPV6;
        cmsg->cmsg_type     = IPV6_PKTINFO;
        cmsg->cmsg_len      = WSA_CMSG_LEN(sizeof(info));
        message.Control.len = UDP_WIN_CMSG(WSA_CMSG_SPACE(sizeof(info)));
        memcpy(WSA_CMSG_DATA(cmsg), &info, sizeof(info));
    }
    DWORD sent = 0;
    return WSASendMsg(fd, &message, 0, &sent, NULL, NULL) == 0 ? (int) sent : -1;
}

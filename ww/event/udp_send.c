#include "udp_send.h"
#include "splice_buffer.h"
#ifdef OS_WIN
#include "udp_pktinfo_win.h"
#else
#include "udp_pktinfo_posix.h"
#endif

static udp_send_result_t udpSendFailure(int error, bool retire)
{
    return (udp_send_result_t) {.bytes = -1, .error = error, .retire = retire};
}

#ifdef OS_UNIX
static int udpSendResidentFrom(int fd, const void *bytes, size_t length, int flags, const sockaddr_u *peer,
                               const sockaddr_u *local)
{
    struct iovec         iov     = {.iov_base = (void *) bytes, .iov_len = length};
    udp_packet_control_t control = {0};
    struct msghdr        msg     = {.msg_name       = (void *) &peer->sa,
                                    .msg_namelen    = SOCKADDR_LEN(peer),
                                    .msg_iov        = &iov,
                                    .msg_iovlen     = 1,
                                    .msg_control    = control.bytes,
                                    .msg_controllen = sizeof(control.bytes)};
    struct cmsghdr      *cmsg    = CMSG_FIRSTHDR(&msg);
    if (local->sa.sa_family == AF_INET6 && ! IN6_IS_ADDR_V4MAPPED(&local->sin6.sin6_addr))
    {
#ifdef IPV6_PKTINFO
        if (IN6_IS_ADDR_MULTICAST(&local->sin6.sin6_addr))
            return (int) sendto(fd, bytes, length, flags, &peer->sa, SOCKADDR_LEN(peer));
        struct in6_pktinfo info = {.ipi6_addr = local->sin6.sin6_addr, .ipi6_ifindex = local->sin6.sin6_scope_id};
        cmsg->cmsg_level        = IPPROTO_IPV6;
        cmsg->cmsg_type         = IPV6_PKTINFO;
        cmsg->cmsg_len          = CMSG_LEN(sizeof(info));
        memcpy(CMSG_DATA(cmsg), &info, sizeof(info));
        msg.msg_controllen = CMSG_SPACE(sizeof(info));
#else
        errno = ENOPROTOOPT;
        return -1;
#endif
    }
    else
    {
        struct in_addr addr;
        if (local->sa.sa_family == AF_INET)
            addr = local->sin.sin_addr;
        else if (local->sa.sa_family == AF_INET6)
            memcpy(&addr, &local->sin6.sin6_addr.s6_addr[12], sizeof(addr));
        else
        {
            errno = EAFNOSUPPORT;
            return -1;
        }
        if (addr.s_addr == INADDR_ANY || udpIPv4GroupAddress(addr))
            return (int) sendto(fd, bytes, length, flags, &peer->sa, SOCKADDR_LEN(peer));

        cmsg->cmsg_level = IPPROTO_IP;
#if defined(IP_SENDSRCADDR) && defined(IP_RECVDSTADDR)
        cmsg->cmsg_type = IP_SENDSRCADDR;
        cmsg->cmsg_len  = CMSG_LEN(sizeof(addr));
        memcpy(CMSG_DATA(cmsg), &addr, sizeof(addr));
        msg.msg_controllen = CMSG_SPACE(sizeof(addr));
#elif defined(IP_PKTINFO)
#ifdef OS_CYGWIN
        struct in_pktinfo info = {.ipi_addr = addr};
#else
        struct in_pktinfo info = {.ipi_spec_dst = addr};
#endif
        cmsg->cmsg_type = IP_PKTINFO;
        cmsg->cmsg_len  = CMSG_LEN(sizeof(info));
        memcpy(CMSG_DATA(cmsg), &info, sizeof(info));
        msg.msg_controllen = CMSG_SPACE(sizeof(info));
#else
        errno = ENOPROTOOPT;
        return -1;
#endif
    }
    return (int) sendmsg(fd, &msg, flags);
}
#endif

static int udpSendResident(int fd, const void *bytes, size_t length, int flags, const sockaddr_u *peer,
                           const sockaddr_u *local, bool retry_eintr)
{
    int result;
    do
    {
        if (local == NULL)
            result = (int) sendto(fd, bytes, length, flags, &peer->sa, SOCKADDR_LEN(peer));
        else
#ifdef OS_WIN
            result = udpWinSendFrom(fd, bytes, length, peer, local);
#else
            result = udpSendResidentFrom(fd, bytes, length, flags, peer, local);
#endif
    } while (result < 0 && retry_eintr && socketERRNO() == EINTR);
    return result;
}

#if WW_HAVE_SPLICE
enum
{
    kUdpSpliceFragmentBudgetBytes = 64U * 1024U
};

static bool udpSpliceNeedsMaterialization(splice_buffer_metadata_t metadata, uint32_t prefix)
{
    /* Linux v5.15 MAX_SKB_FRAGS is max(16, 65536 / PAGE_SIZE + 1);
     * ip_append_page rejects a new fragment once that limit is reached:
     * https://github.com/torvalds/linux/blob/v5.15/include/linux/skbuff.h
     * https://github.com/torvalds/linux/blob/v5.15/net/ipv4/ip_output.c
     * The 64 KiB budget excludes the extra alignment page in that limit,
     * leaving it available for prefix/header alignment. This is the source
     * rationale, not qualification of every kernel/page-size combination.
     * Nominal byte length does not bound the number of tiny fragments. Use
     * ordinary storage when the source pipe's capacity cannot prove this bound;
     * runtime sends must not allocate or resize pipes outside the fixed startup
     * inventory. No socket has been touched yet, so full fallback is safe. */
    const long page_size = sysconf(_SC_PAGESIZE);
    assert(page_size > 0);
    /* Reserve ceil(prefix / page_size) slots within the budget; the extra
     * alignment allowance is already outside it, not another subtraction here.
     * Pipe capacity rounds up to a power of two, so round the remaining slot
     * budget DOWN before comparing the source capacity. */
    const uint32_t prefix_pages = (prefix + (uint32_t) page_size - 1U) / (uint32_t) page_size;
    const uint32_t total_slots  = kUdpSpliceFragmentBudgetBytes / (uint32_t) page_size;
    if (prefix_pages >= total_slots)
        return true;
    const uint32_t slots       = total_slots - prefix_pages;
    uint32_t       allowed_slots = 1;
    while (allowed_slots <= slots / 2U)
        allowed_slots *= 2U;
    const uint32_t allowed_capacity = allowed_slots * (uint32_t) page_size;
    return metadata.pipe_capacity == 0 || metadata.pipe_capacity > allowed_capacity;
}
#endif

udp_send_result_t udpSendBuffer(int fd, buffer_pool_t *pool, sbuf_t *buf, const sockaddr_u *peer, bool retry_eintr)
{
    return udpSendBufferFrom(fd, pool, buf, peer, NULL, retry_eintr);
}

udp_send_result_t udpSendBufferFrom(int fd, buffer_pool_t *pool, sbuf_t *buf, const sockaddr_u *peer,
                                    const sockaddr_u *local, bool retry_eintr)
{
    const uint32_t length = sbufGetLength(buf);
    if (! sbufIsSplice(buf))
    {
        int sent = udpSendResident(fd, sbufGetRawPtr(buf), length, 0, peer, local, retry_eintr);
        return sent < 0 ? udpSendFailure(socketERRNO(), false) : (udp_send_result_t) {.bytes = sent};
    }
#if WW_HAVE_SPLICE
    /* No jumbograms. IPv4-mapped destinations have the IPv4 payload bound. */
    const bool ipv4 = peer->sa.sa_family == AF_INET ||
                      (peer->sa.sa_family == AF_INET6 && IN6_IS_ADDR_V4MAPPED(&peer->sin6.sin6_addr));
    if (length > (ipv4 ? 65507U : 65527U))
        return udpSendFailure(EMSGSIZE, false);
    const uint32_t prefix = sbufGetResidentPrefixLength(buf);
    const uint32_t body   = length - prefix;
    if (body == 0)
    {
        int sent = udpSendResident(fd, sbufGetRawPtr(buf), prefix, 0, peer, local, retry_eintr);
        if (sent >= 0)
            sbufShiftRight(buf, prefix);
        return sent < 0 ? udpSendFailure(socketERRNO(), false) : (udp_send_result_t) {.bytes = sent};
    }
    splice_buffer_metadata_t metadata = sbufSpliceMetadata(buf);
    assert(metadata.pipefd[0] >= 0 && metadata.pipefd[1] >= 0);
    // Temporarily route splice-backed UDP datagrams through materialization and ordinary writes.

    // TODO: Remove this guard once explicitly requested by the author.
    // Treat this as a temporary implementation detail: assume normal UDP splicing
    // works end-to-end, and do not make design decisions based on UDP being
    // materialized here temporarily.
    const bool force_materialization = true;
    if (force_materialization || udpSpliceNeedsMaterialization(metadata, prefix))
    {
        sbuf_t *ordinary = bufferpoolGetBestFit(pool, length, 0);
        sbufSpliceReadToBuffer(buf, ordinary, length);
        int sent  = udpSendResident(fd, sbufGetRawPtr(ordinary), length, 0, peer, local, retry_eintr);
        int error = sent < 0 ? socketERRNO() : 0;
        bufferpoolReuseBuffer(pool, ordinary);
        return sent < 0 ? udpSendFailure(error, false) : (udp_send_result_t) {.bytes = sent};
    }
    int primed = udpSendResident(fd, sbufGetRawPtr(buf), prefix, MSG_MORE, peer, local, retry_eintr);
    if (primed < 0)
        return udpSendFailure(socketERRNO(), false);
    assert((uint32_t) primed == prefix);
    sbufShiftRight(buf, prefix);

    /* MORE suppresses publication across every internal page/bvec operation.
     * A short positive result may hide an error that discarded the cork. Never
     * loop or commit that prefix/suffix, even if the socket is connected. */
    ssize_t moved = splice(metadata.pipefd[0], NULL, fd, NULL, body, SPLICE_F_NONBLOCK | SPLICE_F_MORE);
    int     error = moved < 0 ? socketERRNO() : EIO;
    if (moved > 0)
        sbufSpliceConsumeBody(buf, (uint32_t) moved);
    if (moved != (ssize_t) body)
        return udpSendFailure(error, true);

    /* Unlike clearing UDP_CORK, sendto reports commit errors. Empty priming and
     * commit are parts of this datagram, never separate zero-length messages. */
    int committed = udpSendResident(fd, "", 0, 0, peer, NULL, false);
    if (committed < 0)
        return udpSendFailure(socketERRNO(), true);
    return (udp_send_result_t) {.bytes = (int) length};
#else
    discard fd;
    discard pool;
    discard peer;
    discard retry_eintr;
    return udpSendFailure(ENOSYS, false);
#endif
}

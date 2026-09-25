#include "udp_send.h"
#include "splice_buffer.h"

#if WW_HAVE_SPLICE
#include <fcntl.h>
#endif

static udp_send_result_t udpSendFailure(int error, bool retire)
{
    return (udp_send_result_t) {.bytes = -1, .error = error, .retire = retire};
}

static int udpSendResident(int fd, const void *bytes, size_t length, int flags, const sockaddr_u *peer,
                           bool retry_eintr)
{
    int result;
    do
    {
        result = (int) sendto(fd, bytes, length, flags, &peer->sa, SOCKADDR_LEN(peer));
    } while (result < 0 && retry_eintr && socketERRNO() == EINTR);
    return result;
}

#if WW_HAVE_SPLICE
enum
{
    kUdpSpliceFragmentBudgetBytes = 64U * 1024U
};

static bool udpSpliceNeedsMaterialization(splice_buffer_metadata_t metadata, uint32_t body, uint32_t prefix)
{
    /* Linux v5.15 MAX_SKB_FRAGS is max(16, 65536 / PAGE_SIZE + 1);
     * ip_append_page rejects a new fragment once that limit is reached:
     * https://github.com/torvalds/linux/blob/v5.15/include/linux/skbuff.h
     * https://github.com/torvalds/linux/blob/v5.15/net/ipv4/ip_output.c
     * The 64 KiB budget excludes the extra alignment page in that limit,
     * leaving it available for prefix/header alignment. This is the source
     * rationale, not qualification of every kernel/page-size combination.
     * Large-capacity source pipes need a non-consuming tee probe: nominal byte
     * length does not bound the number of tiny fragments. No socket has been
     * touched yet; probe/resource refusal permits full fallback. */
    const long page_size = sysconf(_SC_PAGESIZE);
    assert(page_size > 0);
    /* Reserve ceil(prefix / page_size) slots within the budget; the extra
     * alignment allowance is already outside it, not another subtraction here.
     * Pipe capacity rounds up to a power of two, so round the remaining slot
     * budget DOWN before requesting the probe capacity. */
    const uint32_t prefix_pages = (prefix + (uint32_t) page_size - 1U) / (uint32_t) page_size;
    const uint32_t total_slots  = kUdpSpliceFragmentBudgetBytes / (uint32_t) page_size;
    if (prefix_pages >= total_slots)
        return true;
    const uint32_t slots       = total_slots - prefix_pages;
    uint32_t       probe_slots = 1;
    while (probe_slots <= slots / 2U)
        probe_slots *= 2U;
    const int probe_capacity = (int) (probe_slots * (uint32_t) page_size);
    if (metadata.pipe_capacity != 0 && metadata.pipe_capacity <= (uint32_t) probe_capacity)
        return false;
    int probe[2];
    if (pipe2(probe, O_NONBLOCK | O_CLOEXEC) != 0)
        return true;
    int capacity = fcntl(probe[1], F_SETPIPE_SZ, probe_capacity);
    if (capacity < 0)
        capacity = fcntl(probe[1], F_GETPIPE_SZ);
    ssize_t copied = -1;
    if (capacity > 0 && capacity <= probe_capacity)
        copied = tee(metadata.pipefd[0], probe[1], body, SPLICE_F_NONBLOCK);
    close(probe[0]);
    close(probe[1]);
    return copied != (ssize_t) body;
}
#endif

udp_send_result_t udpSendBuffer(int fd, sbuf_t *buf, const sockaddr_u *peer, bool retry_eintr)
{
    const uint32_t length = sbufGetLength(buf);
    if (! sbufIsSplice(buf))
    {
        int sent = udpSendResident(fd, sbufGetRawPtr(buf), length, 0, peer, retry_eintr);
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
        int sent = udpSendResident(fd, sbufGetRawPtr(buf), prefix, 0, peer, retry_eintr);
        if (sent >= 0)
            sbufShiftRight(buf, prefix);
        return sent < 0 ? udpSendFailure(socketERRNO(), false) : (udp_send_result_t) {.bytes = sent};
    }
    splice_buffer_metadata_t metadata = sbufSpliceMetadata(buf);
    assert(metadata.pipefd[0] >= 0 && metadata.pipefd[1] >= 0);
    // Temporarily route splice-backed UDP datagrams through materialization and ordinary writes.
    // TODO: Remove this guard once the kernel UDP splice fix is mature and widely deployed.
    const bool force_materialization = true;
    if (force_materialization || udpSpliceNeedsMaterialization(metadata, body, prefix))
    {
        sbuf_t *ordinary = sbufCreate(length);
        sbufSpliceReadToBuffer(buf, ordinary, length);
        int sent  = udpSendResident(fd, sbufGetRawPtr(ordinary), length, 0, peer, retry_eintr);
        int error = sent < 0 ? socketERRNO() : 0;
        sbufDestroy(ordinary);
        return sent < 0 ? udpSendFailure(error, false) : (udp_send_result_t) {.bytes = sent};
    }
    int primed = udpSendResident(fd, sbufGetRawPtr(buf), prefix, MSG_MORE, peer, retry_eintr);
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
    int committed = udpSendResident(fd, "", 0, 0, peer, false);
    if (committed < 0)
        return udpSendFailure(socketERRNO(), true);
    return (udp_send_result_t) {.bytes = (int) length};
#else
    discard fd;
    discard peer;
    discard retry_eintr;
    return udpSendFailure(ENOSYS, false);
#endif
}

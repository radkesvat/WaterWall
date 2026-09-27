#include "capture_linux_checksum.h"
#include "capture_linux_internal.h"
#include "capture_private.h"
#include "devices/device_flow_affinity.h"
#include "devices/device_fragment_policy.h"
#include "generic_pool.h"
#include "global_state.h"
#include "loggers/internal_logger.h"
#include "worker.h"
#include "wproc.h"
#include "wtime.h"
#include <arpa/inet.h>
#include <fcntl.h>
#include <linux/filter.h>
#include <linux/if_ether.h>
#include <linux/ipv6.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_queue.h>
#include <linux/netfilter/xt_bpf.h>
#include <linux/netlink.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include "capture_linux_nfqueue.h"
#include "capture_linux_private.h"
#include "capture_linux_rules.h"

#define NETFILTER_MAX_PAYLOAD_SIZE sizeof(struct nfqnl_msg_verdict_hdr)
#define NETFILTER_MESSAGE_BUFFER_SIZE                                                                                  \
    (NLMSG_ALIGN(NLMSG_LENGTH(sizeof(struct nfgenmsg))) + NFA_ALIGN(NFA_LENGTH(NETFILTER_MAX_PAYLOAD_SIZE)))

static_assert(SMALL_BUFFER_SIZE >= kNetfilterReadBufferSize, "Linux capture requires 4096-byte small buffers");
static_assert(kCaptureCommandTimeoutMs > kCaptureIptablesLockWaitSeconds * 1000,
              "the parent command deadline must stay strictly longer than the numeric xtables lock wait");
static_assert(kMaxAllowedPacketLength <= kNetfilterReadBufferSize, "packet policy must fit in netlink read buffer");
static_assert(kMaxReadDistributeQueueSize <= UINT16_MAX, "capture read batch count must fit in the reader session");
static_assert(sizeof(struct nfqnl_msg_config_cmd) <= NETFILTER_MAX_PAYLOAD_SIZE,
              "NFQUEUE command payload must fit in message storage");
static_assert(sizeof(struct nfqnl_msg_config_params) <= NETFILTER_MAX_PAYLOAD_SIZE,
              "NFQUEUE parameter payload must fit in message storage");
static_assert(sizeof(uint32_t) <= NETFILTER_MAX_PAYLOAD_SIZE,
              "NFQUEUE queue-length payload must fit in message storage");
static_assert(_Alignof(ww_max_align_t) >= _Alignof(struct nlmsghdr), "netlink storage must align nlmsghdr");
static_assert(_Alignof(ww_max_align_t) >= _Alignof(struct nlmsgerr), "netlink storage must align nlmsgerr");
static_assert(_Alignof(ww_max_align_t) >= _Alignof(struct nfgenmsg), "netlink storage must align nfgenmsg");
static_assert(_Alignof(ww_max_align_t) >= _Alignof(struct nfattr), "netlink storage must align nfattr");
static_assert(NLMSG_HDRLEN % _Alignof(struct nfgenmsg) == 0, "nfgenmsg geometry must preserve alignment");
static_assert(NLMSG_HDRLEN % _Alignof(struct nlmsgerr) == 0, "nlmsgerr geometry must preserve alignment");
static_assert(NLMSG_ALIGN(NLMSG_LENGTH(sizeof(struct nfgenmsg))) % _Alignof(struct nfattr) == 0,
              "nfattr geometry must preserve alignment");

static atomic_uint netfilter_sequence = ATOMIC_VAR_INIT(0);

static bool netfilterPollUntil(int netfilter_socket, short events, uint64_t deadline_us)
{
    for (;;)
    {
        const uint64_t now_us = (uint64_t) getHRTimeUs();
        if (now_us >= deadline_us)
        {
            errno = ETIMEDOUT;
            return false;
        }

        const uint64_t remaining_us = deadline_us - now_us;
        const int      timeout_ms   = (int) min((remaining_us + 999U) / 1000U, (uint64_t) INT_MAX);
        struct pollfd  pfd          = {
                      .fd     = netfilter_socket,
                      .events = events,
        };
        int result = poll(&pfd, 1, max(timeout_ms, 1));
        if (result < 0 && errno == EINTR)
        {
            continue;
        }
        if (result < 0)
        {
            return false;
        }
        if (result == 0)
        {
            errno = ETIMEDOUT;
            return false;
        }
        if ((pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) != 0)
        {
            errno = EIO;
            return false;
        }
        if ((pfd.revents & events) != 0)
        {
            return true;
        }
    }
}

static bool netfilterRetryInterruptedUntil(uint64_t deadline_us, uint32_t *interruptions)
{
    *interruptions += 1U;
    if (*interruptions >= (uint32_t) kCaptureInterruptedRetryBudget || (uint64_t) getHRTimeUs() >= deadline_us)
    {
        errno = ETIMEDOUT;
        return false;
    }
    return true;
}

static bool netfilterSendBounded(int netfilter_socket, const void *message, size_t size,
                                 const struct sockaddr_nl *nl_addr, uint64_t deadline_us)
{
    uint32_t interruptions = 0;
    for (;;)
    {
        ssize_t result =
            sendto(netfilter_socket, message, size, MSG_DONTWAIT, (const struct sockaddr *) nl_addr, sizeof(*nl_addr));
        if (result == (ssize_t) size)
        {
            return true;
        }
        if (result >= 0)
        {
            errno = EIO;
            return false;
        }
        if (errno == EINTR)
        {
            if (! netfilterRetryInterruptedUntil(deadline_us, &interruptions))
            {
                return false;
            }
            continue;
        }
        if (errno != EAGAIN && errno != EWOULDBLOCK)
        {
            return false;
        }
        if (! netfilterPollUntil(netfilter_socket, POLLOUT, deadline_us))
        {
            return false;
        }
    }
}

static bool netfilterWaitForAck(int netfilter_socket, uint32_t sequence, uint64_t deadline_us)
{
    _Alignas(ww_max_align_t) uint8_t ack_buff[kNetfilterAckBufferSize];
    uint32_t                         interruptions = 0;

    for (;;)
    {
        if (! netfilterPollUntil(netfilter_socket, POLLIN, deadline_us))
        {
            return false;
        }

        struct sockaddr_nl nl_addr;
        struct iovec       iov = {.iov_base = ack_buff, .iov_len = sizeof(ack_buff)};
        struct msghdr      msg = {
                 .msg_name    = &nl_addr,
                 .msg_namelen = sizeof(nl_addr),
                 .msg_iov     = &iov,
                 .msg_iovlen  = 1,
        };
        ssize_t result = recvmsg(netfilter_socket, &msg, MSG_DONTWAIT | MSG_TRUNC);
        if (result < 0 && errno == EINTR)
        {
            if (! netfilterRetryInterruptedUntil(deadline_us, &interruptions))
            {
                return false;
            }
            continue;
        }
        if (result < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
        {
            continue;
        }
        if (result < 0)
        {
            return false;
        }
        if ((msg.msg_flags & MSG_TRUNC) != 0 || result > (ssize_t) sizeof(ack_buff))
        {
            errno = EMSGSIZE;
            return false;
        }
        if (msg.msg_namelen != sizeof(nl_addr) || nl_addr.nl_family != AF_NETLINK || nl_addr.nl_pid != 0 ||
            nl_addr.nl_groups != 0)
        {
            errno = EBADMSG;
            return false;
        }
        bool   matching_ack_seen  = false;
        int    matching_ack_error = 0;
        size_t offset             = 0;
        while (offset < (size_t) result)
        {
            const size_t remaining = (size_t) result - offset;
            if (remaining < sizeof(struct nlmsghdr))
            {
                errno = EBADMSG;
                return false;
            }

            struct nlmsghdr nl_hdr;
            memoryCopy(&nl_hdr, ack_buff + offset, sizeof(nl_hdr));
            if (nl_hdr.nlmsg_len < sizeof(nl_hdr) || nl_hdr.nlmsg_len > remaining)
            {
                errno = EBADMSG;
                return false;
            }

            if (nl_hdr.nlmsg_type == NLMSG_ERROR && nl_hdr.nlmsg_len < NLMSG_LENGTH(sizeof(struct nlmsgerr)))
            {
                errno = EBADMSG;
                return false;
            }

            if (nl_hdr.nlmsg_seq == sequence)
            {
                if (matching_ack_seen || nl_hdr.nlmsg_type != NLMSG_ERROR ||
                    nl_hdr.nlmsg_len < NLMSG_LENGTH(sizeof(struct nlmsgerr)) || (nl_hdr.nlmsg_flags & NLM_F_MULTI) != 0)
                {
                    errno = EBADMSG;
                    return false;
                }

                struct nlmsgerr ack;
                memoryCopy(&ack, ack_buff + offset + NLMSG_HDRLEN, sizeof(ack));
                if (ack.error > 0)
                {
                    errno = EBADMSG;
                    return false;
                }
                matching_ack_seen  = true;
                matching_ack_error = ack.error;
            }

            const size_t aligned_length = NLMSG_ALIGN((size_t) nl_hdr.nlmsg_len);
            if (aligned_length > remaining)
            {
                // A final message need not carry bytes beyond nlmsg_len. Any
                // other short alignment gap would make another header
                // impossible and is therefore malformed.
                if ((size_t) nl_hdr.nlmsg_len == remaining)
                {
                    offset = (size_t) result;
                    break;
                }
                errno = EBADMSG;
                return false;
            }
            offset += aligned_length;
        }

        if (matching_ack_seen)
        {
            if (matching_ack_error == 0)
            {
                return true;
            }
            errno = matching_ack_error == INT_MIN ? EIO : -matching_ack_error;
            return false;
        }
    }
}

/* Send one message and, for configuration requests, its matching ACK before an absolute deadline. */
static bool netfilterSendMessageUntil(int netfilter_socket, uint16_t nl_type, int nfa_type, uint16_t res_id, bool ack,
                                      const void *msg, size_t size, uint64_t deadline_us)
{
    if (size > NETFILTER_MAX_PAYLOAD_SIZE)
    {
        errno = EMSGSIZE;
        return false;
    }

    const size_t nl_size = NLMSG_ALIGN(NLMSG_LENGTH(sizeof(struct nfgenmsg))) + NFA_ALIGN(NFA_LENGTH(size));
    _Alignas(ww_max_align_t) uint8_t buff[NETFILTER_MESSAGE_BUFFER_SIZE];
    memoryZero(buff, nl_size);
    struct nlmsghdr *nl_hdr = (struct nlmsghdr *) buff;

    nl_hdr->nlmsg_len   = NLMSG_LENGTH(sizeof(struct nfgenmsg));
    nl_hdr->nlmsg_flags = NLM_F_REQUEST | (ack ? NLM_F_ACK : 0);
    nl_hdr->nlmsg_type  = (NFNL_SUBSYS_QUEUE << 8) | nl_type;
    nl_hdr->nlmsg_pid   = 0;
    do
    {
        nl_hdr->nlmsg_seq = (uint32_t) atomicAddExplicit(&netfilter_sequence, 1, memory_order_relaxed) + 1U;
    } while (nl_hdr->nlmsg_seq == 0);

    struct nfgenmsg *nl_gen_msg = (struct nfgenmsg *) (nl_hdr + 1);
    nl_gen_msg->version         = NFNETLINK_V0;
    nl_gen_msg->nfgen_family    = AF_UNSPEC;
    nl_gen_msg->res_id          = htons(res_id);

    struct nfattr *nl_attr     = (struct nfattr *) (buff + NLMSG_ALIGN(nl_hdr->nlmsg_len));
    size_t         nl_attr_len = NFA_LENGTH(size);
    nl_hdr->nlmsg_len          = NLMSG_ALIGN(nl_hdr->nlmsg_len) + NFA_ALIGN(nl_attr_len);
    nl_attr->nfa_type          = nfa_type;
    nl_attr->nfa_len           = NFA_LENGTH(size);

    memoryMove(NFA_DATA(nl_attr), msg, size);

    struct sockaddr_nl nl_addr;
    memoryZero(&nl_addr, sizeof(nl_addr));
    nl_addr.nl_family = AF_NETLINK;

    if (! netfilterSendBounded(netfilter_socket, buff, nl_size, &nl_addr, deadline_us))
    {
        return false;
    }

    if (! ack)
    {
        return true;
    }

    return netfilterWaitForAck(netfilter_socket, nl_hdr->nlmsg_seq, deadline_us);
}

/* Send one independently bounded message on the normal configuration/reader path. */
static bool netfilterSendMessage(int netfilter_socket, uint16_t nl_type, int nfa_type, uint16_t res_id, bool ack,
                                 const void *msg, size_t size)
{
    const uint64_t deadline_us = (uint64_t) getHRTimeUs() + (uint64_t) kNetfilterIoDeadlineMs * 1000U;
    return netfilterSendMessageUntil(netfilter_socket, nl_type, nfa_type, res_id, ack, msg, size, deadline_us);
}

/*
 * Set a netfilter configuration option.
 */
bool netfilterSetConfig(int netfilter_socket, uint8_t cmd, uint16_t qnum, uint16_t pf)
{
    struct nfqnl_msg_config_cmd nl_cmd = {.command = cmd, .pf = htons(pf)};
    return netfilterSendMessage(netfilter_socket, NFQNL_MSG_CONFIG, NFQA_CFG_CMD, qnum, true, &nl_cmd, sizeof(nl_cmd));
}

/*
 * Set the netfilter parameters.
 */
bool netfilterSetParams(int netfilter_socket, uint16_t qnumber, uint8_t mode, uint32_t range)
{
    struct nfqnl_msg_config_params nl_params = {.copy_mode = mode, .copy_range = htonl(range)};
    return netfilterSendMessage(
        netfilter_socket, NFQNL_MSG_CONFIG, NFQA_CFG_PARAMS, qnumber, true, &nl_params, sizeof(nl_params));
}

/*
 * Set the netfilter queue length.
 */
bool netfilterSetQueueLength(int netfilter_socket, uint16_t qnumber, uint32_t qlen)
{
    uint32_t qlen_be = htonl(qlen);
    return netfilterSendMessage(
        netfilter_socket, NFQNL_MSG_CONFIG, NFQA_CFG_QUEUE_MAXLEN, qnumber, true, &qlen_be, sizeof(qlen_be));
}

static bool netfilterPointerRangeInside(const uint8_t *base, size_t size, const uint8_t *ptr, size_t len)
{
    uintptr_t base_addr = (uintptr_t) base;
    uintptr_t ptr_addr  = (uintptr_t) ptr;

    if (ptr_addr < base_addr)
    {
        return false;
    }

    size_t offset = ptr_addr - base_addr;
    return offset <= size && len <= size - offset;
}

static void netfilterPacketViewReset(netfilter_packet_view_t *view)
{
    memoryZero(view, sizeof(*view));
}

netfilter_packet_parse_result_t captureLinuxNetfilterParsePacket(uint8_t *message, size_t copied_len,
                                                                 netfilter_packet_view_t *view)
{
    if (message == NULL || view == NULL)
    {
        return kNetfilterPacketParseMalformed;
    }

    netfilterPacketViewReset(view);

    if (copied_len > (size_t) INT_MAX || copied_len <= sizeof(struct nlmsghdr))
    {
        return kNetfilterPacketParseMalformed;
    }

    struct nlmsghdr *nl_hdr          = (struct nlmsghdr *) message;
    int              remaining_bytes = (int) copied_len;
    if (! NLMSG_OK(nl_hdr, (unsigned int) remaining_bytes))
    {
        return kNetfilterPacketParseMalformed;
    }
    if (NFNL_SUBSYS_ID(nl_hdr->nlmsg_type) != NFNL_SUBSYS_QUEUE)
    {
        return kNetfilterPacketParseMalformed;
    }
    if (NFNL_MSG_TYPE(nl_hdr->nlmsg_type) != NFQNL_MSG_PACKET)
    {
        return kNetfilterPacketParseMalformed;
    }

    size_t attr_offset = (size_t) NLMSG_HDRLEN + (size_t) NLMSG_ALIGN(sizeof(struct nfgenmsg));
    if ((size_t) nl_hdr->nlmsg_len < attr_offset)
    {
        return kNetfilterPacketParseMalformed;
    }

    struct nfattr *nl_attr       = NFM_NFA(NLMSG_DATA(nl_hdr));
    int            nl_attr_size  = (int) ((size_t) nl_hdr->nlmsg_len - attr_offset);
    bool           found_payload = false;

    while (nl_attr_size > 0)
    {
        if (! NFA_OK(nl_attr, nl_attr_size))
        {
            return kNetfilterPacketParseMalformed;
        }

        int nl_attr_type    = NFA_TYPE(nl_attr);
        int nl_attr_payload = NFA_PAYLOAD(nl_attr);
        if (UNLIKELY(nl_attr_payload < 0))
        {
            return kNetfilterPacketParseMalformed;
        }
        if (UNLIKELY(! netfilterPointerRangeInside(
                message, (size_t) nl_hdr->nlmsg_len, (const uint8_t *) NFA_DATA(nl_attr), (size_t) nl_attr_payload)))
        {
            return kNetfilterPacketParseMalformed;
        }

        switch (nl_attr_type)
        {
        case NFQA_PAYLOAD:
            if (found_payload)
            {
                return kNetfilterPacketParseMalformed;
            }
            found_payload        = true;
            view->payload        = (const uint8_t *) NFA_DATA(nl_attr);
            view->payload_length = (uint32_t) nl_attr_payload;
            break;
        case NFQA_PACKET_HDR:
            if (view->has_packet_id)
            {
                return kNetfilterPacketParseMalformed;
            }
            if (nl_attr_payload != (int) sizeof(struct nfqnl_msg_packet_hdr))
            {
                return kNetfilterPacketParseMalformed;
            }
            view->has_packet_id = true;
            memoryCopy(&view->packet_id,
                       &((const struct nfqnl_msg_packet_hdr *) NFA_DATA(nl_attr))->packet_id,
                       sizeof(view->packet_id));
            break;
        case NFQA_CAP_LEN: {
            uint32_t raw_capture_length = 0;
            if (view->has_capture_length)
            {
                return kNetfilterPacketParseMalformed;
            }
            if (nl_attr_payload != (int) sizeof(raw_capture_length))
            {
                return kNetfilterPacketParseMalformed;
            }
            view->has_capture_length = true;
            memoryCopy(&raw_capture_length, NFA_DATA(nl_attr), sizeof(raw_capture_length));
            view->capture_length = ntohl(raw_capture_length);
            break;
        }
        case NFQA_SKB_INFO: {
            uint32_t raw_skb_info = 0;
            if (view->has_skb_info || nl_attr_payload != (int) sizeof(raw_skb_info))
            {
                return kNetfilterPacketParseMalformed;
            }
            memoryCopy(&raw_skb_info, NFA_DATA(nl_attr), sizeof(raw_skb_info));
            view->skb_info     = ntohl(raw_skb_info);
            view->has_skb_info = true;
            break;
        }
        default:
            // Ignore other attributes
            break;
        }
        nl_attr = NFA_NEXT(nl_attr, nl_attr_size);
    }

    if (! found_payload || ! view->has_packet_id)
    {
        return kNetfilterPacketParseMalformed;
    }
    if (view->has_capture_length && view->capture_length < view->payload_length)
    {
        return kNetfilterPacketParseMalformed;
    }
    if (view->payload_length > kMaxAllowedPacketLength)
    {
        return kNetfilterPacketParseDiscarded;
    }
    if (view->has_capture_length &&
        (view->capture_length > view->payload_length || view->capture_length > kMaxAllowedPacketLength))
    {
        return kNetfilterPacketParseDiscarded;
    }

    return kNetfilterPacketParseReady;
}

bool captureLinuxNetfilterTryReadPacketIdFromPrefix(const uint8_t *message, size_t copied_len, uint32_t *packet_id)
{
    if (message == NULL || packet_id == NULL || copied_len < sizeof(struct nlmsghdr))
    {
        return false;
    }

    const struct nlmsghdr *nl_hdr = (const struct nlmsghdr *) message;
    if (NFNL_SUBSYS_ID(nl_hdr->nlmsg_type) != NFNL_SUBSYS_QUEUE)
    {
        return false;
    }
    if (NFNL_MSG_TYPE(nl_hdr->nlmsg_type) != NFQNL_MSG_PACKET)
    {
        return false;
    }

    size_t attr_offset = (size_t) NLMSG_HDRLEN + (size_t) NLMSG_ALIGN(sizeof(struct nfgenmsg));
    if ((size_t) nl_hdr->nlmsg_len < attr_offset || copied_len < attr_offset)
    {
        return false;
    }

    size_t nlmsg_limit         = (size_t) nl_hdr->nlmsg_len;
    size_t prefix_limit        = copied_len < nlmsg_limit ? copied_len : nlmsg_limit;
    size_t attr_offset_current = attr_offset;
    while (prefix_limit - attr_offset_current >= sizeof(struct nfattr))
    {
        const struct nfattr *nl_attr  = (const struct nfattr *) (const void *) (message + attr_offset_current);
        size_t               attr_len = (size_t) nl_attr->nfa_len;
        if (attr_len < (size_t) NFA_LENGTH(0))
        {
            return false;
        }
        if (attr_len > prefix_limit - attr_offset_current)
        {
            return false;
        }

        if (NFA_TYPE(nl_attr) == NFQA_PACKET_HDR)
        {
            if (NFA_PAYLOAD(nl_attr) != (int) sizeof(struct nfqnl_msg_packet_hdr))
            {
                return false;
            }
            memoryCopy(
                packet_id, &((const struct nfqnl_msg_packet_hdr *) NFA_DATA(nl_attr))->packet_id, sizeof(*packet_id));
            return true;
        }

        size_t aligned_attr_len = (size_t) NFA_ALIGN(attr_len);
        if (aligned_attr_len == 0 || aligned_attr_len > prefix_limit - attr_offset_current)
        {
            return false;
        }
        attr_offset_current += aligned_attr_len;
    }

    return false;
}

void captureLinuxNetfilterExposePacket(sbuf_t *buff, const uint8_t *message, const netfilter_packet_view_t *view)
{
    assert(buff != NULL);
    assert(message != NULL);
    assert(view != NULL);
    assert(view->payload != NULL);
    assert(view->payload >= message);

    uintptr_t payload_addr   = (uintptr_t) view->payload;
    uintptr_t message_addr   = (uintptr_t) message;
    uint32_t  payload_offset = (uint32_t) (payload_addr - message_addr);

    buff->curpos += payload_offset;
    sbufSetLength(buff, view->payload_length);
}

static bool netfilterSendVerdictUntil(int netfilter_socket, uint16_t qnumber, uint32_t packet_id, uint32_t verdict,
                                      uint64_t deadline_us)
{
    struct nfqnl_msg_verdict_hdr nl_verdict;
    nl_verdict.verdict = htonl(verdict);
    nl_verdict.id      = packet_id;
    return netfilterSendMessageUntil(netfilter_socket,
                                     NFQNL_MSG_VERDICT,
                                     NFQA_VERDICT_HDR,
                                     qnumber,
                                     false,
                                     &nl_verdict,
                                     sizeof(nl_verdict),
                                     deadline_us);
}

static bool netfilterSendVerdict(int netfilter_socket, uint16_t qnumber, uint32_t packet_id, uint32_t verdict)
{
    const uint64_t deadline_us = (uint64_t) getHRTimeUs() + (uint64_t) kNetfilterIoDeadlineMs * 1000U;
    return netfilterSendVerdictUntil(netfilter_socket, qnumber, packet_id, verdict, deadline_us);
}

/*
 * Get a packet from netfilter.
 */
netfilter_packet_result_t netfilterGetPacketUntil(capture_device_t *cdev, int netfilter_socket, uint16_t qnumber,
                                                  sbuf_t *buff, uint64_t verdict_deadline_us)
{
    assert(sbufGetMaximumWriteableSize(buff) >= kNetfilterReadBufferSize);
    if (UNLIKELY(sbufGetMaximumWriteableSize(buff) < kNetfilterReadBufferSize))
    {
        errno = EMSGSIZE;
        return kNetfilterPacketError;
    }

    // Read a message from netlink (non-blocking)
    struct sockaddr_nl nl_addr;
    memoryZero(&nl_addr, sizeof(nl_addr));
    uint8_t      *message = sbufGetMutablePtr(buff);
    struct iovec  iov     = {.iov_base = message, .iov_len = kNetfilterReadBufferSize};
    struct msghdr msg     = {.msg_name = &nl_addr, .msg_iov = &iov, .msg_iovlen = 1};
    ssize_t       result;
    uint32_t      interruptions = 0;
    for (;;)
    {
        msg.msg_namelen = sizeof(nl_addr);
        msg.msg_flags   = 0;
        result          = recvmsg(netfilter_socket, &msg, MSG_DONTWAIT | MSG_TRUNC);
        if (result >= 0 || errno != EINTR)
        {
            break;
        }
        if (! netfilterRetryInterruptedUntil(verdict_deadline_us, &interruptions))
        {
            return kNetfilterPacketError;
        }
    }

    if (result < 0)
    {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
        {
            return kNetfilterPacketWouldBlock;
        }
        return kNetfilterPacketError;
    }

    if (result == 0)
    {
        return kNetfilterPacketEof;
    }

    if (msg.msg_namelen != sizeof(nl_addr) || nl_addr.nl_pid != 0)
    {
        errno = EINVAL;
        return kNetfilterPacketError;
    }

    size_t copied_len =
        result > (ssize_t) kNetfilterReadBufferSize ? (size_t) kNetfilterReadBufferSize : (size_t) result;
    if ((msg.msg_flags & MSG_TRUNC) != 0 || result > (ssize_t) kNetfilterReadBufferSize)
    {
        uint32_t packet_id = 0;
        if (! captureLinuxNetfilterTryReadPacketIdFromPrefix(message, copied_len, &packet_id))
        {
            LOGW("CaptureDevice: oversized netfilter datagram did not contain a complete packet id");
            errno = EBADMSG;
            return kNetfilterPacketError;
        }
        const bool active = atomicLoadRelaxed(&cdev->capture_active);
        if (! netfilterSendVerdictUntil(
                netfilter_socket, qnumber, packet_id, active ? NF_DROP : NF_ACCEPT, verdict_deadline_us))
        {
            return kNetfilterPacketError;
        }
        return active ? kNetfilterPacketDiscarded : kNetfilterPacketAccepted;
    }

    sbufSetLength(buff, (uint32_t) copied_len);

    netfilter_packet_view_t         packet_view;
    netfilter_packet_parse_result_t parse_result = captureLinuxNetfilterParsePacket(message, copied_len, &packet_view);
    if (parse_result == kNetfilterPacketParseMalformed)
    {
        if (! packet_view.has_packet_id)
        {
            errno = EBADMSG;
            return kNetfilterPacketError;
        }
        const bool active = atomicLoadRelaxed(&cdev->capture_active);
        if (! netfilterSendVerdictUntil(
                netfilter_socket, qnumber, packet_view.packet_id, active ? NF_DROP : NF_ACCEPT, verdict_deadline_us))
        {
            return kNetfilterPacketError;
        }
        return active ? kNetfilterPacketMalformedDiscarded : kNetfilterPacketAccepted;
    }

    const bool active = atomicLoadRelaxed(&cdev->capture_active);
    if (! netfilterSendVerdictUntil(
            netfilter_socket, qnumber, packet_view.packet_id, active ? NF_DROP : NF_ACCEPT, verdict_deadline_us))
    {
        return kNetfilterPacketError;
    }
    if (! active)
    {
        return kNetfilterPacketAccepted;
    }

    if (parse_result == kNetfilterPacketParseDiscarded)
    {
        return kNetfilterPacketDiscarded;
    }

    captureLinuxNetfilterExposePacket(buff, message, &packet_view);

    if (! captureLinuxPreparePacket(
            sbufGetMutablePtr(buff), sbufGetLength(buff), packet_view.has_skb_info, packet_view.skb_info))
    {
        return kNetfilterPacketMalformedDiscarded;
    }
    return kNetfilterPacketReady;
}

netfilter_packet_result_t netfilterGetPacket(capture_device_t *cdev, int netfilter_socket, uint16_t qnumber,
                                             sbuf_t *buff)
{
    const uint64_t deadline_us = (uint64_t) getHRTimeUs() + (uint64_t) kNetfilterIoDeadlineMs * 1000U;
    return netfilterGetPacketUntil(cdev, netfilter_socket, qnumber, buff, deadline_us);
}

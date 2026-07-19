#include "capture.h"
#include "capture_linux_internal.h"
#include "generic_pool.h"
#include "global_state.h"
#include "loggers/internal_logger.h"
#include "worker.h"
#include "wproc.h"
#include "wtime.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/if_ether.h>
#include <linux/ipv6.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_queue.h>
#include <linux/netlink.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef useExecCmd
#define useExecCmd 1
#endif

enum
{
    kNetfilterReadBufferSize    = kCaptureLinuxNetfilterReadBufferSize,
    kMaxReadDistributeQueueSize = 512,
    kNetfilterQueueLen          = 64 * 1024,
    kNetfilterSocketRecvBuffer  = 64 * 1024 * 1024
};

static_assert(SMALL_BUFFER_SIZE >= kNetfilterReadBufferSize, "Linux capture requires 4096-byte small buffers");
static_assert(kMaxAllowedPacketLength <= kNetfilterReadBufferSize, "packet policy must fit in netlink read buffer");
static_assert(kMaxReadDistributeQueueSize <= UINT16_MAX, "capture read batch count must fit in msg_event.count");

typedef enum netfilter_packet_result_e
{
    kNetfilterPacketError = -1,
    kNetfilterPacketWouldBlock,
    kNetfilterPacketEof,
    kNetfilterPacketDiscarded,
    kNetfilterPacketMalformedDiscarded,
    kNetfilterPacketReady
} netfilter_packet_result_t;

typedef struct capturedevice_sysctl_setting_s
{
    const char *argv_setting;
    const char *shell_setting;
} capturedevice_sysctl_setting_t;

static const capturedevice_sysctl_setting_t sysctl_settings[] = {
    {"net.core.rmem_max=134217728", "net.core.rmem_max=134217728"},
    {"net.core.wmem_max=134217728", "net.core.wmem_max=134217728"},
    {"net.ipv4.tcp_rmem=4096 87380 134217728", "net.ipv4.tcp_rmem='4096 87380 134217728'"},
    {"net.ipv4.tcp_wmem=4096 65536 134217728", "net.ipv4.tcp_wmem='4096 65536 134217728'"},
    {"net.core.netdev_max_backlog=250000", "net.core.netdev_max_backlog=250000"},
    {"net.core.somaxconn=65535", "net.core.somaxconn=65535"},
    {"net.ipv4.tcp_window_scaling=1", "net.ipv4.tcp_window_scaling=1"},
    {"net.ipv4.tcp_timestamps=0", "net.ipv4.tcp_timestamps=0"},
    {"net.ipv4.tcp_sack=1", "net.ipv4.tcp_sack=1"},
    {"net.ipv4.tcp_no_metrics_save=1", "net.ipv4.tcp_no_metrics_save=1"},
    {"net.ipv4.tcp_mtu_probing=1", "net.ipv4.tcp_mtu_probing=1"},
    {"net.ipv4.tcp_tw_reuse=1", "net.ipv4.tcp_tw_reuse=1"},
    {"net.ipv4.tcp_fin_timeout=15", "net.ipv4.tcp_fin_timeout=15"},
    {"net.ipv4.ip_local_port_range=10000 65535", "net.ipv4.ip_local_port_range='10000 65535'"}
};

static uint8_t capturedeviceIpv4MaskPrefixLength(const ip_addr_t *mask)
{
    uint32_t mask_host = lwip_ntohl(mask->u_addr.ip4.addr);
    uint8_t  prefix    = 0;

    while ((mask_host & 0x80000000U) != 0)
    {
        ++prefix;
        mask_host <<= 1U;
    }

    return prefix;
}

static void capturedeviceFormatIpv4(uint32_t addr_host, char *dest, size_t dest_len)
{
    stringNPrintf(dest,
                  dest_len,
                  "%u.%u.%u.%u",
                  (addr_host >> 24U) & 0xFFU,
                  (addr_host >> 16U) & 0xFFU,
                  (addr_host >> 8U) & 0xFFU,
                  addr_host & 0xFFU);
}

static void capturedeviceFormatCidr(const ipmask_t *range, char *dest, size_t dest_len)
{
    char    ip[16];
    uint8_t prefix = capturedeviceIpv4MaskPrefixLength(&range->mask);

    capturedeviceFormatIpv4(lwip_ntohl(range->ip.u_addr.ip4.addr), ip, sizeof(ip));
    stringNPrintf(dest, dest_len, "%s/%u", ip, prefix);
}

static void capturedeviceFormatCommand(const char *const argv[], char *dest, size_t dest_len)
{
    size_t offset = 0;

    if (dest_len == 0)
    {
        return;
    }

    dest[0] = '\0';

    for (size_t i = 0; argv[i] != NULL && offset < dest_len; ++i)
    {
        int written = stringNPrintf(dest + offset, dest_len - offset, "%s%s", i == 0 ? "" : " ", argv[i]);
        if (written < 0)
        {
            break;
        }

        if ((size_t) written >= dest_len - offset)
        {
            offset = dest_len - 1;
            break;
        }

        offset += (size_t) written;
    }
}

static int capturedeviceRunCommand(const char *command_name, const char *const argv[])
{
    char command[512];
    capturedeviceFormatCommand(argv, command, sizeof(command));
    LOGD("CaptureDevice: Running command: %s", command);

#if useExecCmd
    discard command_name;
    return execCmd(command).exit_code;
#else
    long  open_max = execCmdOpenMax();
    pid_t childpid = fork();
    if (childpid < 0)
    {
        LOGE("CaptureDevice: failed to fork for %s: %s", command_name, strerror(errno));
        return -1;
    }

    if (childpid == 0)
    {
        execCmdCloseInheritedFds(open_max);
        execvp(command_name, (char *const *) argv);
        perror(command_name);
        _exit(127);
    }

    int status = 0;
    while (waitpid(childpid, &status, 0) < 0)
    {
        if (errno == EINTR)
        {
            continue;
        }

        LOGE("CaptureDevice: failed to wait for %s: %s", command_name, strerror(errno));
        return -1;
    }

    if (WIFEXITED(status))
    {
        return WEXITSTATUS(status);
    }

    if (WIFSIGNALED(status))
    {
        LOGE("CaptureDevice: %s terminated by signal %d", command_name, WTERMSIG(status));
    }

    return -1;
#endif
}

static void capturedeviceSetSysctl(const capturedevice_sysctl_setting_t *setting)
{
#if useExecCmd
    char command[256];
    stringNPrintf(command, sizeof(command), "sysctl -w %s", setting->shell_setting);
    LOGD("CaptureDevice: Running command: %s", command);
    discard execCmd(command).exit_code;
#else
    const char *const argv[] = {"sysctl", "-w", setting->argv_setting, NULL};
    discard           capturedeviceRunCommand("sysctl", argv);
#endif
}

static void capturedeviceApplySysctls(void)
{
    for (size_t i = 0; i < sizeof(sysctl_settings) / sizeof(sysctl_settings[0]); ++i)
    {
        capturedeviceSetSysctl(&sysctl_settings[i]);
    }
}

static void capturedeviceLogSocketBufferSize(int socket_fd, int option, const char *name)
{
    int       actual = 0;
    socklen_t len    = sizeof(actual);

    if (getsockopt(socket_fd, SOL_SOCKET, option, &actual, &len) != 0)
    {
        LOGW("CaptureDevice: failed to read actual %s: %s", name, strerror(errno));
        return;
    }

    LOGD("CaptureDevice: actual %s is %d bytes", name, actual);
}

static bool capturedeviceRunIptablesQueueRule(const char *operation, const char *cidr, uint32_t queue_number)
{
    char queue_number_arg[16];
    stringNPrintf(queue_number_arg, sizeof(queue_number_arg), "%u", queue_number);

    const char *const argv[] = {
        "iptables", operation, "INPUT", "-s", cidr, "-j", "NFQUEUE", "--queue-num", queue_number_arg, NULL};
    return capturedeviceRunCommand("iptables", argv) == 0;
}

static char *capturedeviceFormatCidrString(const ipmask_t *range)
{
    char cidr[24];
    capturedeviceFormatCidr(range, cidr, sizeof(cidr));
    return stringDuplicate(cidr);
}

static void capturedeviceFreeCidrs(char **cidrs, uint32_t count)
{
    if (cidrs == NULL)
    {
        return;
    }

    for (uint32_t i = 0; i < count; ++i)
    {
        if (cidrs[i] != NULL)
        {
            memoryFree(cidrs[i]);
        }
    }

    memoryFree(cidrs);
}

/**
 * Event message structure for TUN device communication
 */
struct msg_event
{
    capture_device_t *cdev;
    sbuf_t           *bufs[kMaxReadDistributeQueueSize];
    uint16_t          count;
};
static pool_item_t *allocCaptureMsgPoolHandle(void *userdata)
{
    discard userdata;
    return memoryAllocate(sizeof(struct msg_event));
}

static void destroyCaptureMsgPoolHandle(master_pool_item_t *item)
{
    memoryFree(item);
}

static void reuseCaptureBuffers(capture_device_t *cdev, sbuf_t **bufs, unsigned int count)
{
    for (unsigned int i = 0; i < count; i++)
    {
        bufferpoolReuseBuffer(cdev->reader_buffer_pool, bufs[i]);
    }
}

static void cleanupCaptureMessage(struct msg_event *msg)
{
    if (msg == NULL)
    {
        return;
    }

    for (unsigned int i = 0; i < msg->count; i++)
    {
        sbufDestroy(msg->bufs[i]);
    }
    masterpoolReuseItems(msg->cdev->reader_message_pool, (void **) &msg, 1);
}

static void cleanupPostedCaptureMessage(void *arg1, void *arg2, void *arg3)
{
    struct msg_event *msg = arg1;
    discard           arg2;
    discard           arg3;

    cleanupCaptureMessage(msg);
}

/**
 * Handles events received on the local thread
 * @param worker Worker receiving message
 * @param arg1 Message data
 */
static void localThreadMessageReceived(void *worker, void *arg1, void *arg2, void *arg3)
{
    struct msg_event *msg = arg1;
    wid_t             wid = ((worker_t *) worker)->wid;
    discard           arg2;
    discard           arg3;

    for (unsigned int i = 0; i < msg->count; i++)
    {
        msg->cdev->read_event_callback(msg->cdev, msg->cdev->userdata, msg->bufs[i], wid);
    }

    masterpoolReuseItems(msg->cdev->reader_message_pool, (void **) &msg, 1);
}

/**
 * Distributes a packet payload to the target worker thread
 * @param cdev Capture device handle
 * @param target_wid Target thread ID
 * @param buf Buffer containing packet data
 */
static void distributePacketPayloads(capture_device_t *cdev, wid_t target_wid, sbuf_t **buf, unsigned int queued_count)
{
    assert(queued_count <= kMaxReadDistributeQueueSize);
    assert(queued_count <= UINT16_MAX);

    if (UNLIKELY(isApplicationTerminating() || GSTATE.shortcut_loops == NULL))
    {
        reuseCaptureBuffers(cdev, buf, queued_count);
        return;
    }

    struct msg_event *msg;
    masterpoolGetItems(cdev->reader_message_pool, (const void **) &(msg), 1, cdev);

    msg->cdev  = cdev;
    msg->count = (uint16_t) queued_count;
    for (unsigned int i = 0; i < queued_count; i++)
    {
        msg->bufs[i] = buf[i];
    }

    sendWorkerMessageForceQueueWithCleanup(
        target_wid, localThreadMessageReceived, cleanupPostedCaptureMessage, msg, NULL, NULL);
}

/*
 * Send a message to the netfilter system and wait for an acknowledgement.
 */
static bool netfilterSendMessage(int netfilter_socket, uint16_t nl_type, int nfa_type, uint16_t res_id, bool ack,
                                 void *msg, size_t size)
{
    size_t  nl_size = NLMSG_ALIGN(NLMSG_LENGTH(sizeof(struct nfgenmsg))) + NFA_ALIGN(NFA_LENGTH(size));
    uint8_t buff[nl_size];
    memoryZero(buff, nl_size);
    struct nlmsghdr *nl_hdr = (struct nlmsghdr *) buff;

    nl_hdr->nlmsg_len   = NLMSG_LENGTH(sizeof(struct nfgenmsg));
    nl_hdr->nlmsg_flags = NLM_F_REQUEST | (ack ? NLM_F_ACK : 0);
    nl_hdr->nlmsg_type  = (NFNL_SUBSYS_QUEUE << 8) | nl_type;
    nl_hdr->nlmsg_pid   = 0;
    nl_hdr->nlmsg_seq   = 0;

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

    ssize_t send_result = sendto(netfilter_socket, buff, sizeof(buff), 0, (struct sockaddr *) &nl_addr, sizeof(nl_addr));
    if (send_result != (ssize_t) sizeof(buff))
    {
        if (send_result >= 0)
        {
            errno = EIO;
        }
        return false;
    }

    if (! ack)
    {
        return true;
    }

    uint8_t   ack_buff[64];
    socklen_t nl_addr_len = sizeof(nl_addr);
    ssize_t   result =
        recvfrom(netfilter_socket, ack_buff, sizeof(ack_buff), 0, (struct sockaddr *) &nl_addr, &nl_addr_len);
    nl_hdr = (struct nlmsghdr *) ack_buff;

    if (result < 0)
    {
        return false;
    }

    if (nl_addr_len != sizeof(nl_addr) || nl_addr.nl_pid != 0)
    {
        errno = EINVAL;
        return false;
    }

    if (NLMSG_OK(nl_hdr, result) && nl_hdr->nlmsg_type == NLMSG_ERROR)
    {
        errno = -(*(int *) NLMSG_DATA(nl_hdr));
        return (errno == 0);
    }

    errno = EBADMSG;
    return false;
}

/*
 * Set a netfilter configuration option.
 */
static bool netfilterSetConfig(int netfilter_socket, uint8_t cmd, uint16_t qnum, uint16_t pf)
{
    struct nfqnl_msg_config_cmd nl_cmd = {.command = cmd, .pf = htons(pf)};
    return netfilterSendMessage(netfilter_socket, NFQNL_MSG_CONFIG, NFQA_CFG_CMD, qnum, true, &nl_cmd, sizeof(nl_cmd));
}

/*
 * Set the netfilter parameters.
 */
static bool netfilterSetParams(int netfilter_socket, uint16_t qnumber, uint8_t mode, uint32_t range)
{
    struct nfqnl_msg_config_params nl_params = {.copy_mode = mode, .copy_range = htonl(range)};
    return netfilterSendMessage(
        netfilter_socket, NFQNL_MSG_CONFIG, NFQA_CFG_PARAMS, qnumber, true, &nl_params, sizeof(nl_params));
}

/*
 * Set the netfilter queue length.
 */
static bool netfilterSetQueueLength(int netfilter_socket, uint16_t qnumber, uint32_t qlen)
{
    return netfilterSendMessage(
        netfilter_socket, NFQNL_MSG_CONFIG, NFQA_CFG_QUEUE_MAXLEN, qnumber, true, &qlen, sizeof(qlen));
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
    if (! NLMSG_OK(nl_hdr, remaining_bytes))
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

    struct nfattr *nl_attr      = NFM_NFA(NLMSG_DATA(nl_hdr));
    int            nl_attr_size = (int) ((size_t) nl_hdr->nlmsg_len - attr_offset);
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
            found_payload       = true;
            view->payload       = (const uint8_t *) NFA_DATA(nl_attr);
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
        case NFQA_CAP_LEN:
        {
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

    size_t nlmsg_limit = (size_t) nl_hdr->nlmsg_len;
    size_t prefix_limit = copied_len < nlmsg_limit ? copied_len : nlmsg_limit;
    size_t attr_offset_current = attr_offset;
    while (prefix_limit - attr_offset_current >= sizeof(struct nfattr))
    {
        const struct nfattr *nl_attr = (const struct nfattr *) (const void *) (message + attr_offset_current);
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
            memoryCopy(packet_id,
                       &((const struct nfqnl_msg_packet_hdr *) NFA_DATA(nl_attr))->packet_id,
                       sizeof(*packet_id));
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

    uintptr_t payload_addr = (uintptr_t) view->payload;
    uintptr_t message_addr = (uintptr_t) message;
    uint32_t  payload_offset = (uint32_t) (payload_addr - message_addr);

    buff->curpos += payload_offset;
    sbufSetLength(buff, view->payload_length);
}

static bool netfilterSendDropVerdict(int netfilter_socket, uint16_t qnumber, uint32_t packet_id)
{
    struct nfqnl_msg_verdict_hdr nl_verdict;
    nl_verdict.verdict = htonl(NF_DROP);
    nl_verdict.id      = packet_id;
    return netfilterSendMessage(
        netfilter_socket, NFQNL_MSG_VERDICT, NFQA_VERDICT_HDR, qnumber, false, &nl_verdict, sizeof(nl_verdict));
}

/*
 * Get a packet from netfilter.
 */
static netfilter_packet_result_t netfilterGetPacket(int netfilter_socket, uint16_t qnumber, sbuf_t *buff)
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
    uint8_t       *message = sbufGetMutablePtr(buff);
    struct iovec   iov     = {.iov_base = message, .iov_len = kNetfilterReadBufferSize};
    struct msghdr  msg     = {.msg_name    = &nl_addr,
                              .msg_namelen = sizeof(nl_addr),
                              .msg_iov     = &iov,
                              .msg_iovlen  = 1};
    ssize_t        result  = recvmsg(netfilter_socket, &msg, MSG_DONTWAIT | MSG_TRUNC);

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

    size_t copied_len = result > (ssize_t) kNetfilterReadBufferSize ? (size_t) kNetfilterReadBufferSize :
                                                                      (size_t) result;
    if ((msg.msg_flags & MSG_TRUNC) != 0 || result > (ssize_t) kNetfilterReadBufferSize)
    {
        uint32_t packet_id = 0;
        if (! captureLinuxNetfilterTryReadPacketIdFromPrefix(message, copied_len, &packet_id))
        {
            LOGW("CaptureDevice: oversized netfilter datagram did not contain a complete packet id");
            errno = EBADMSG;
            return kNetfilterPacketError;
        }
        if (! netfilterSendDropVerdict(netfilter_socket, qnumber, packet_id))
        {
            return kNetfilterPacketError;
        }
        return kNetfilterPacketDiscarded;
    }

    sbufSetLength(buff, (uint32_t) copied_len);

    netfilter_packet_view_t         packet_view;
    netfilter_packet_parse_result_t parse_result =
        captureLinuxNetfilterParsePacket(message, copied_len, &packet_view);
    if (parse_result == kNetfilterPacketParseMalformed)
    {
        if (! packet_view.has_packet_id)
        {
            errno = EBADMSG;
            return kNetfilterPacketError;
        }
        if (! netfilterSendDropVerdict(netfilter_socket, qnumber, packet_view.packet_id))
        {
            return kNetfilterPacketError;
        }
        return kNetfilterPacketMalformedDiscarded;
    }

    if (! netfilterSendDropVerdict(netfilter_socket, qnumber, packet_view.packet_id))
    {
        return kNetfilterPacketError;
    }

    if (parse_result == kNetfilterPacketParseDiscarded)
    {
        return kNetfilterPacketDiscarded;
    }

    captureLinuxNetfilterExposePacket(buff, message, &packet_view);
    return kNetfilterPacketReady;
}

static void capturedeviceRecordNetfilterDiscard(capture_device_t *cdev)
{
    unsigned long long now_ms = getTimeOfDayMS();

    cdev->netfilter_discarded_total++;
    cdev->netfilter_discarded_suppressed++;

    if (cdev->netfilter_discard_last_report_ms == 0)
    {
        cdev->netfilter_discard_last_report_ms = now_ms;
        return;
    }

    unsigned long long elapsed_ms = now_ms - cdev->netfilter_discard_last_report_ms;
    if (elapsed_ms < 1000)
    {
        return;
    }

    LOGW("CaptureDevice: discarded %llu truncated or oversized netfilter packet(s) over %llums (total=%llu)",
         LLU(cdev->netfilter_discarded_suppressed),
         LLU(elapsed_ms),
         LLU(cdev->netfilter_discarded_total));
    cdev->netfilter_discarded_suppressed   = 0;
    cdev->netfilter_discard_last_report_ms = now_ms;
}

static void capturedeviceReportPendingNetfilterDiscards(capture_device_t *cdev)
{
    if (cdev->netfilter_discarded_suppressed == 0)
    {
        return;
    }

    LOGW("CaptureDevice: discarded %llu truncated or oversized netfilter packet(s) before reader exit (total=%llu)",
         LLU(cdev->netfilter_discarded_suppressed),
         LLU(cdev->netfilter_discarded_total));
    cdev->netfilter_discarded_suppressed = 0;
}

static WTHREAD_ROUTINE(routineReadFromCapture) // NOLINT
{
    capture_device_t *cdev = userdata;

    struct pollfd fds[2];
    fds[0].fd     = cdev->socket;
    fds[1].fd     = cdev->linux_pipe_fds[0];
    fds[0].events = POLLIN;
    fds[1].events = POLLIN;

    while (atomicLoadExplicit(&(cdev->running), memory_order_relaxed))
    {
        int ret = poll(fds, 2, -1);
        if (ret < 0)
        {
            if (errno == EINTR)
            {
                continue; // Interrupted by signal, just retry
            }
            LOGE("CaptureDevice: Exit read routine due to poll failed with error %d (%s)", errno, strerror(errno));
            break;
        }

        if (ret == 0)
        {
            // ret == 0, which shouldn't happen with infinite timeout
            LOGF("CaptureDevice: poll returned 0 with infinite timeout");
            exit(1);
        }

        if (fds[1].revents & POLLIN)
        {
            char    drain_byte;
            ssize_t drain_res = read(cdev->linux_pipe_fds[0], &drain_byte, 1);
            discard drain_res;
            LOGW("CaptureDevice: Exit read routine due to pipe event");
            break;
        }

        // Check for socket errors
        if (fds[0].revents & (POLLERR | POLLHUP | POLLNVAL))
        {
            int       socket_error = 0;
            socklen_t err_len      = sizeof(socket_error);
            getsockopt(cdev->socket, SOL_SOCKET, SO_ERROR, &socket_error, &err_len);
            LOGE("CaptureDevice: Exit read routine due to socket error event: %s%s%s, socket error: %d (%s)",
                 (fds[0].revents & POLLERR) ? "POLLERR " : "",
                 (fds[0].revents & POLLHUP) ? "POLLHUP " : "",
                 (fds[0].revents & POLLNVAL) ? "POLLNVAL " : "",
                 socket_error,
                 strerror(socket_error));
            break;
        }

        if (fds[0].revents & POLLIN)
        {
            uint16_t queued_count = 0;
            sbuf_t  *bufs[kMaxReadDistributeQueueSize];

            // Drain multiple packets while the socket remains readable
            for (uint32_t i = 0; i < RAM_PROFILE && queued_count < kMaxReadDistributeQueueSize; ++i)
            {
                bool leave_drain_loop = false;
                bufs[queued_count] = bufferpoolGetSmallBuffer(cdev->reader_buffer_pool);
                bufs[queued_count] = sbufReserveSpace(bufs[queued_count], kNetfilterReadBufferSize);

                netfilter_packet_result_t packet_result =
                    netfilterGetPacket(cdev->socket, cdev->queue_number, bufs[queued_count]);

                switch (packet_result)
                {
                case kNetfilterPacketReady:
                    // Length was set in netfilterGetPacket via sbufSetLength.
                    if (UNLIKELY(sbufGetLength(bufs[queued_count]) > kMaxAllowedPacketLength))
                    {
                        capturedeviceRecordNetfilterDiscard(cdev);
                        bufferpoolReuseBuffer(cdev->reader_buffer_pool, bufs[queued_count]);
                        continue;
                    }
                    queued_count++;
                    break;

                case kNetfilterPacketDiscarded:
                    capturedeviceRecordNetfilterDiscard(cdev);
                    bufferpoolReuseBuffer(cdev->reader_buffer_pool, bufs[queued_count]);
                    continue;

                case kNetfilterPacketMalformedDiscarded:
                    LOGW("CaptureDevice: discarded a malformed netfilter packet after sending NF_DROP");
                    bufferpoolReuseBuffer(cdev->reader_buffer_pool, bufs[queued_count]);
                    continue;

                case kNetfilterPacketWouldBlock:
                    bufferpoolReuseBuffer(cdev->reader_buffer_pool, bufs[queued_count]);
                    if (queued_count > 0)
                    {
                        distributePacketPayloads(cdev, getNextDistributionWID(), bufs, queued_count);
                        queued_count = 0;
                    }
                    leave_drain_loop = true;
                    break;

                case kNetfilterPacketEof:
                    bufferpoolReuseBuffer(cdev->reader_buffer_pool, bufs[queued_count]);
                    if (queued_count > 0)
                    {
                        distributePacketPayloads(cdev, getNextDistributionWID(), bufs, queued_count);
                        queued_count = 0;
                    }
                    capturedeviceReportPendingNetfilterDiscards(cdev);
                    LOGE("CaptureDevice: Exit read routine due to End Of File");
                    return 0;

                case kNetfilterPacketError:
                default:
                {
                    int saved_errno = errno;
                    bufferpoolReuseBuffer(cdev->reader_buffer_pool, bufs[queued_count]);
                    if (queued_count > 0)
                    {
                        distributePacketPayloads(cdev, getNextDistributionWID(), bufs, queued_count);
                        queued_count = 0;
                    }
                    LOGW("CaptureDevice: failed to read a packet from netfilter socket, errno is %d (%s)",
                         saved_errno,
                         strerror(saved_errno));
                    leave_drain_loop = true;
                    break;
                }
                }

                if (leave_drain_loop)
                {
                    break;
                }
            }

            // Distribute all accumulated packets in one batch
            if (queued_count > 0)
            {
                distributePacketPayloads(cdev, getNextDistributionWID(), bufs, queued_count);
            }
            continue;
        }

        // If we get here, poll returned > 0 but none of our expected events occurred
        LOGE("CaptureDevice: Exit read routine due to unexpected poll events - fd[0].revents=0x%x, fd[1].revents=0x%x",
             fds[0].revents,
             fds[1].revents);
        capturedeviceReportPendingNetfilterDiscards(cdev);
        return 0;
    }

    capturedeviceReportPendingNetfilterDiscards(cdev);
    return 0;
}

bool caputredeviceBringUp(capture_device_t *cdev)
{
    assert(! cdev->up);

    for (uint32_t i = 0; i < cdev->capture_range_count; ++i)
    {
        if (! capturedeviceRunIptablesQueueRule("-I", cdev->capture_cidrs[i], cdev->queue_number))
        {
            LOGE("CaptureDevice: failed to install iptables NFQUEUE rule for %s", cdev->capture_cidrs[i]);
            terminateProgram(1);
            return false;
        }
    }

    bufferpoolUpdateAllocationPaddings(cdev->reader_buffer_pool,
                                       bufferpoolGetLargeBufferPadding(getWorkerBufferPool(getWID())),
                                       bufferpoolGetSmallBufferPadding(getWorkerBufferPool(getWID())));

    cdev->up      = true;
    cdev->running = true;

    LOGI("CaptureDevice: device %s is now up", cdev->name);

    cdev->read_thread = threadCreate(cdev->routine_reader, cdev);
    return true;
}

bool caputredeviceBringDown(capture_device_t *cdev)
{
    assert(cdev->up);

    bool result = true;

    cdev->running = false;
    cdev->up      = false;

    atomicThreadFence(memory_order_release);

    for (uint32_t i = 0; i < cdev->capture_range_count; ++i)
    {
        if (! capturedeviceRunIptablesQueueRule("-D", cdev->capture_cidrs[i], cdev->queue_number))
        {
            LOGE("CaptureDevice: failed to remove iptables NFQUEUE rule for %s", cdev->capture_cidrs[i]);
            result = false;
        }
    }

    ssize_t write_res = write(cdev->linux_pipe_fds[1], "x", 1);
    discard write_res;
    safeThreadJoin(cdev->read_thread);

    LOGI("CaptureDevice: device %s is now down", cdev->name);

    return result;
}

capture_device_t *caputredeviceCreate(const char *name, const ipmask_t *capture_ranges, uint32_t capture_range_count,
                                      void *userdata, CaptureReadEventHandle cb)
{
    if (capture_ranges == NULL || capture_range_count == 0)
    {
        LOGE("CaptureDevice: no capture ranges configured");
        return NULL;
    }

    /* Best-effort kernel tuning; capture startup must continue if a sysctl fails. */
    capturedeviceApplySysctls();

    int socket_netfilter = socket(AF_NETLINK, SOCK_RAW, NETLINK_NETFILTER);
    if (socket_netfilter < 0)
    {
        LOGE("CaptureDevice: unable to create a netfilter socket");
        return NULL;
    }

    struct sockaddr_nl nl_addr;
    memoryZero(&nl_addr, sizeof(nl_addr));
    nl_addr.nl_family = AF_NETLINK;
    nl_addr.nl_pid    = 0;

    if (bind(socket_netfilter, (struct sockaddr *) &nl_addr, sizeof(nl_addr)) != 0)
    {
        LOGE("CaptureDevice: unable to bind netfilter socket to current process");
        close(socket_netfilter);
        return NULL;
    }

    // Best-effort: avoid ENOBUFS notifications waking us up and set non-blocking
    {
        int one = 1;
        if (setsockopt(socket_netfilter, SOL_NETLINK, NETLINK_NO_ENOBUFS, &one, sizeof(one)) < 0)
        {
            LOGW("CaptureDevice: failed to set NETLINK_NO_ENOBUFS: %s", strerror(errno));
        }
        int flags = fcntl(socket_netfilter, F_GETFL, 0);
        if (flags >= 0)
        {
            if (fcntl(socket_netfilter, F_SETFL, flags | O_NONBLOCK) < 0)
            {
                LOGW("CaptureDevice: failed to set O_NONBLOCK: %s", strerror(errno));
            }
        }
        else
        {
            LOGW("CaptureDevice: failed to get socket flags for O_NONBLOCK: %s", strerror(errno));
        }
    }

    if (! netfilterSetConfig(socket_netfilter, NFQNL_CFG_CMD_PF_UNBIND, 0, PF_INET))
    {
        LOGE("CaptureDevice: unable to unbind netfilter from PF_INET");
        close(socket_netfilter);
        return NULL;
    }
    if (! netfilterSetConfig(socket_netfilter, NFQNL_CFG_CMD_PF_BIND, 0, PF_INET))
    {
        LOGE("CaptureDevice: unable to bind netfilter to PF_INET");
        close(socket_netfilter);
        return NULL;
    }
    int queue_number = GSTATE.capturedevice_queue_start_number++;

    char **capture_cidrs = memoryAllocateZero((size_t) capture_range_count * sizeof(*capture_cidrs));

    for (uint32_t i = 0; i < capture_range_count; ++i)
    {
        capture_cidrs[i] = capturedeviceFormatCidrString(&capture_ranges[i]);
        if (capture_cidrs[i] == NULL)
        {
            LOGE("CaptureDevice: failed to format capture range");
            close(socket_netfilter);
            capturedeviceFreeCidrs(capture_cidrs, capture_range_count);
            return NULL;
        }
    }

    if (! netfilterSetConfig(socket_netfilter, NFQNL_CFG_CMD_BIND, queue_number, 0))
    {
        LOGE("CaptureDevice: unable to bind netfilter to queue number %u", queue_number);
        close(socket_netfilter);
        capturedeviceFreeCidrs(capture_cidrs, capture_range_count);
        return NULL;
    }

    uint32_t range = kMaxAllowedPacketLength;
    if (! netfilterSetParams(socket_netfilter, queue_number, NFQNL_COPY_PACKET, range))
    {
        LOGE("CaptureDevice: unable to set netfilter into copy packet mode with maximum "
             "packet payload copy size %u",
             range);

        close(socket_netfilter);
        capturedeviceFreeCidrs(capture_cidrs, capture_range_count);
        return NULL;
    }
    if (! netfilterSetQueueLength(socket_netfilter, queue_number, kNetfilterQueueLen))
    {
        LOGE("CaptureDevice: unable to set netfilter queue maximum length to %u", kNetfilterQueueLen);

        close(socket_netfilter);
        capturedeviceFreeCidrs(capture_cidrs, capture_range_count);
        return NULL;
    }
    int rcvbuf_size = kNetfilterSocketRecvBuffer;
    if (setsockopt(socket_netfilter, SOL_SOCKET, SO_RCVBUF, &rcvbuf_size, sizeof(rcvbuf_size)) < 0)
    {
        LOGE("CaptureDevice: failed to set SO_RCVBUF: %s", strerror(errno));
        close(socket_netfilter);
        capturedeviceFreeCidrs(capture_cidrs, capture_range_count);
        return NULL;
    }
    capturedeviceLogSocketBufferSize(socket_netfilter, SO_RCVBUF, "SO_RCVBUF");

    buffer_pool_t *reader_bpool = bufferpoolCreate(GSTATE.masterpool_buffer_pools_large,
                                                   GSTATE.masterpool_buffer_pools_small,
                                                   RAM_PROFILE,
                                                   bufferpoolGetLargeBufferSize(getWorkerBufferPool(getWID())),
                                                   bufferpoolGetSmallBufferSize(getWorkerBufferPool(getWID()))

    );
    if (UNLIKELY(bufferpoolGetSmallBufferSize(reader_bpool) < kNetfilterReadBufferSize))
    {
        LOGE("CaptureDevice: Linux capture requires small buffers of at least %u bytes, configured size is %u",
             kNetfilterReadBufferSize,
             bufferpoolGetSmallBufferSize(reader_bpool));
        close(socket_netfilter);
        capturedeviceFreeCidrs(capture_cidrs, capture_range_count);
        bufferpoolDestroy(reader_bpool);
        return NULL;
    }

    capture_device_t *cdev = memoryAllocate(sizeof(capture_device_t));

    *cdev = (capture_device_t) {.name                   = stringDuplicate(name),
                                .running                = false,
                                .up                     = false,
                                .routine_reader         = routineReadFromCapture,
                                .socket                 = socket_netfilter,
                                .queue_number           = queue_number,
                                .read_event_callback    = cb,
                                .userdata               = userdata,
                                .reader_message_pool    = masterpoolCreateWithCapacity(RAM_PROFILE * 2),
                                .netfilter_queue_number = queue_number,
                                .capture_cidrs          = capture_cidrs,
                                .capture_range_count    = capture_range_count,
                                .reader_buffer_pool     = reader_bpool};
    if (pipe(cdev->linux_pipe_fds) != 0)
    {
        LOGE("CaptureDevice: failed to create pipe for linux_pipe_fds");
        memoryFree(cdev->name);
        capturedeviceFreeCidrs(cdev->capture_cidrs, cdev->capture_range_count);
        bufferpoolDestroy(cdev->reader_buffer_pool);
        masterpoolDestroy(cdev->reader_message_pool);
        close(cdev->socket);
        memoryFree(cdev);
        return NULL;
    }

    masterpoolInstallCallBacks(cdev->reader_message_pool, allocCaptureMsgPoolHandle, destroyCaptureMsgPoolHandle);

    return cdev;
}

void capturedeviceDestroy(capture_device_t *cdev)
{
    if (cdev->up)
    {
        caputredeviceBringDown(cdev);
    }
    memoryFree(cdev->name);
    capturedeviceFreeCidrs(cdev->capture_cidrs, cdev->capture_range_count);
    bufferpoolDestroy(cdev->reader_buffer_pool);
    masterpoolMakeEmpty(cdev->reader_message_pool);
    masterpoolDestroy(cdev->reader_message_pool);
    close(cdev->socket);
    close(cdev->linux_pipe_fds[0]);
    close(cdev->linux_pipe_fds[1]);
    memoryFree(cdev);
}

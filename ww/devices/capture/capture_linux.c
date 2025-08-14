#include "capture.h"
#include "generic_pool.h"
#include "global_state.h"
#include "loggers/internal_logger.h"
#include "wchan.h"
#include "worker.h"
#include "wproc.h"
#include <arpa/inet.h>
#include <fcntl.h>
#include <linux/if_ether.h>
#include <linux/ipv6.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_queue.h>
#include <linux/netlink.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <poll.h>
#include <string.h>
#include <sys/ioctl.h>

enum
{
    kEthDataLen        = 1500,
    kNetfilterQueueLen = 16384 * 32
};

static const char *ip_tables_enable_queue_mi  = "iptables -I INPUT -s %s -j NFQUEUE --queue-num %d";
static const char *ip_tables_disable_queue_mi = "iptables -D INPUT -s %s -j NFQUEUE --queue-num %d";

static const char *sysctl_set_rmem_max     = "sysctl -w net.core.rmem_max=67108864";
static const char *sysctl_set_rmem_default = "sysctl -w net.core.rmem_default=33554432";
static const char *sysctl_set_wmem_max     = "sysctl -w net.core.wmem_max=33554432";
static const char *sysctl_set_wmem_default = "sysctl -w net.core.wmem_default=16777216";

/**
 * Event message structure for TUN device communication
 */
struct msg_event
{
    capture_device_t *cdev;
    sbuf_t           *bufs[kMaxReadDistributeQueueSize];
    uint8_t           count;
};
static pool_item_t *allocCaptureMsgPoolHandle(master_pool_t *pool, void *userdata)
{
    discard userdata;
    discard pool;
    return memoryAllocate(sizeof(struct msg_event));
}

static void destroyCaptureMsgPoolHandle(master_pool_t *pool, master_pool_item_t *item, void *userdata)
{
    discard pool;
    discard userdata;
    memoryFree(item);
}

/**
 * Handles events received on the local thread
 * @param ev Event containing message data
 */
static void localThreadEventReceived(wevent_t *ev)
{
    struct msg_event *msg = weventGetUserdata(ev);
    wid_t             wid = (wid_t) (wloopGetWid(weventGetLoop(ev)));

    for (uint8_t i = 0; i < msg->count; i++)
    {
        msg->cdev->read_event_callback(msg->cdev, msg->cdev->userdata, msg->bufs[i], wid);
    }

    masterpoolReuseItems(msg->cdev->reader_message_pool, (void **) &msg, 1, msg->cdev);
}

/**
 * Distributes a packet payload to the target worker thread
 * @param cdev Capture device handle
 * @param target_wid Target thread ID
 * @param buf Buffer containing packet data
 */
static void distributePacketPayloads(capture_device_t *cdev, wid_t target_wid, sbuf_t **buf, uint8_t queued_count)
{
    struct msg_event *msg;
    masterpoolGetItems(cdev->reader_message_pool, (const void **) &(msg), 1, cdev);

    msg->cdev  = cdev;
    msg->count = queued_count;
    for (uint8_t i = 0; i < queued_count; i++)
    {
        msg->bufs[i] = buf[i];
    }

    wevent_t ev;
    memorySet(&ev, 0, sizeof(ev));
    ev.loop = getWorkerLoop(target_wid);
    ev.cb   = localThreadEventReceived;
    weventSetUserData(&ev, msg);
    if (UNLIKELY(false == wloopPostEvent(getWorkerLoop(target_wid), &ev)))
    {
        for (uint8_t i = 0; i < queued_count; i++)
        {
            bufferpoolReuseBuffer(cdev->reader_buffer_pool, msg->bufs[i]);
        }
        masterpoolReuseItems(cdev->reader_message_pool, (void **) &msg, 1, cdev);
    }
}

/*
 * Send a message to the netfilter system and wait for an acknowledgement.
 */
static bool netfilterSendMessage(int netfilter_socket, uint16_t nl_type, int nfa_type, uint16_t res_id, bool ack,
                                 void *msg, size_t size)
{
    size_t  nl_size = NLMSG_ALIGN(NLMSG_LENGTH(sizeof(struct nfgenmsg))) + NFA_ALIGN(NFA_LENGTH(size));
    uint8_t buff[nl_size];
    memorySet(buff, 0, nl_size);
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
    memorySet(&nl_addr, 0x0, sizeof(nl_addr));
    nl_addr.nl_family = AF_NETLINK;

    if (sendto(netfilter_socket, buff, sizeof(buff), 0, (struct sockaddr *) &nl_addr, sizeof(nl_addr)) !=
        (long) sizeof(buff))
    {
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
    return netfilterSendMessage(netfilter_socket, NFQNL_MSG_CONFIG, NFQA_CFG_PARAMS, qnumber, true, &nl_params,
                                sizeof(nl_params));
}

/*
 * Set the netfilter queue length.
 */
static bool netfilterSetQueueLength(int netfilter_socket, uint16_t qnumber, uint32_t qlen)
{
    return netfilterSendMessage(netfilter_socket, NFQNL_MSG_CONFIG, NFQA_CFG_QUEUE_MAXLEN, qnumber, true, &qlen,
                                sizeof(qlen));
}

/*
 * Get a packet from netfilter.
 */
static int netfilterGetPacket(int netfilter_socket, uint16_t qnumber, sbuf_t *buff)
{
    // Read a message from netlink (non-blocking)
    char               nl_buff[512 + kEthDataLen + sizeof(struct ethhdr) + sizeof(struct nfqnl_msg_packet_hdr)];
    struct sockaddr_nl nl_addr;
    socklen_t          nl_addr_len = sizeof(nl_addr);
    ssize_t            result =
        recvfrom(netfilter_socket, nl_buff, sizeof(nl_buff), MSG_DONTWAIT, (struct sockaddr *) &nl_addr, &nl_addr_len);

    if (result < 0)
    {
        // Preserve errno for caller (e.g., EAGAIN)
        return -1;
    }

    if (result <= (int) sizeof(struct nlmsghdr))
    {
        errno = EINVAL;
        return -1;
    }
    if (nl_addr_len != sizeof(nl_addr) || nl_addr.nl_pid != 0)
    {
        errno = EINVAL;
        return -1;
    }

    struct nlmsghdr *nl_hdr = (struct nlmsghdr *) nl_buff;
    if (NFNL_SUBSYS_ID(nl_hdr->nlmsg_type) != NFNL_SUBSYS_QUEUE)
    {
        errno = EINVAL;
        return -1;
    }
    if (NFNL_MSG_TYPE(nl_hdr->nlmsg_type) != NFQNL_MSG_PACKET)
    {
        errno = EINVAL;
        return -1;
    }
    if (nl_hdr->nlmsg_len < sizeof(struct nfgenmsg))
    {
        errno = EINVAL;
        return -1;
    }

    // Get the packet data
    int nl_size0 = NLMSG_SPACE(sizeof(struct nfgenmsg));
    if ((int) nl_hdr->nlmsg_len < nl_size0)
    {
        errno = EINVAL;
        return -1;
    }
    struct nfattr               *nl_attr      = NFM_NFA(NLMSG_DATA(nl_hdr));
    int                          nl_attr_size = (int) (nl_hdr->nlmsg_len - NLMSG_ALIGN(nl_size0));
    bool                         found_data = false, found_pkt_hdr = false;
    uint8_t                     *nl_data      = NULL;
    size_t                       nl_data_size = 0;
    struct nfqnl_msg_packet_hdr *nl_pkt_hdr   = NULL;
    while (NFA_OK(nl_attr, nl_attr_size))
    {
        int nl_attr_type = NFA_TYPE(nl_attr);
        switch (nl_attr_type)
        {
        case NFQA_PAYLOAD:
            if (found_data)
            {
                errno = EINVAL;
                return -1;
            }
            found_data   = true;
            nl_data      = (uint8_t *) NFA_DATA(nl_attr);
            nl_data_size = (size_t) NFA_PAYLOAD(nl_attr);
            break;
        case NFQA_PACKET_HDR:
            if (found_pkt_hdr)
            {
                errno = EINVAL;
                return -1;
            }
            found_pkt_hdr = true;
            nl_pkt_hdr    = (struct nfqnl_msg_packet_hdr *) NFA_DATA(nl_attr);
            break;
        default:
            // Ignore other attributes
            break;
        }
        nl_attr = NFA_NEXT(nl_attr, nl_attr_size);
    }
    if (! found_data || ! found_pkt_hdr)
    {
        errno = EINVAL;
        return -1;
    }

    // Tell netlink to drop the packet
    struct nfqnl_msg_verdict_hdr nl_verdict;
    nl_verdict.verdict = htonl(NF_DROP);
    nl_verdict.id      = nl_pkt_hdr->packet_id;
    if (! netfilterSendMessage(netfilter_socket, NFQNL_MSG_VERDICT, NFQA_VERDICT_HDR, qnumber, false, &nl_verdict,
                               sizeof(nl_verdict)))
    {
        return -1;
    }

    // Copy the packet's contents to the output buffer.
    // Also add a phony ethernet header.
    // struct ethhdr *eth_header = (struct ethhdr *) buff;
    // memorySet(&eth_header->h_dest, 0x0, ETH_ALEN);
    // memorySet(&eth_header->h_source, 0x0, ETH_ALEN);
    // eth_header->h_proto = htons(ETH_P_IP);

    sbufSetLength(buff, nl_data_size);

    struct iphdr *ip_header = (struct iphdr *) sbufGetMutablePtr(buff);
    memoryCopyLarge(ip_header, nl_data, (intmax_t) nl_data_size);

    return (int) (nl_data_size);
}

static WTHREAD_ROUTINE(routineReadFromCapture) // NOLINT
{
    capture_device_t *cdev = userdata;
    ssize_t           nread;

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
                 (fds[0].revents & POLLERR) ? "POLLERR " : "", (fds[0].revents & POLLHUP) ? "POLLHUP " : "",
                 (fds[0].revents & POLLNVAL) ? "POLLNVAL " : "", socket_error, strerror(socket_error));
            break;
        }

        if (fds[0].revents & POLLIN)
        {
            uint8_t queued_count = 0;
            sbuf_t *bufs[kMaxReadDistributeQueueSize];

            // Drain multiple packets while the socket remains readable
            for (uint32_t i = 0; i < RAM_PROFILE && queued_count < kMaxReadDistributeQueueSize; ++i)
            {
                bufs[queued_count] = bufferpoolGetSmallBuffer(cdev->reader_buffer_pool);
                sbufReserveSpace(bufs[queued_count], kReadPacketSize);

                nread = netfilterGetPacket(cdev->socket, cdev->queue_number, bufs[queued_count]);

                if (nread == 0)
                {
                    bufferpoolReuseBuffer(cdev->reader_buffer_pool, bufs[queued_count]);
                    // Distribute any packets we've accumulated before returning
                    if (queued_count > 0)
                    {
                        distributePacketPayloads(cdev, getNextDistributionWID(), bufs, queued_count);
                        queued_count = 0;
                    }
                    LOGE("CaptureDevice: Exit read routine due to End Of File");
                    return 0;
                }

                if (nread < 0)
                {
                    int saved_errno = errno;
                    bufferpoolReuseBuffer(cdev->reader_buffer_pool, bufs[queued_count]);
                    // No more packets right now; distribute any packets we've accumulated and go back to poll
                    if (queued_count > 0)
                    {
                        distributePacketPayloads(cdev, getNextDistributionWID(), bufs, queued_count);
                        queued_count = 0;
                    }

                    if (saved_errno == EAGAIN || saved_errno == EWOULDBLOCK)
                    {
                        break;
                    }
                    LOGW("CaptureDevice: failed to read a packet from netfilter socket, errno is %d (%s)", saved_errno,
                         strerror(saved_errno));
                    // On other errors, also go back to poll to avoid a tight loop
                    break;
                }

                // Length was set in netfilterGetPacket via sbufSetLength
                if (UNLIKELY(sbufGetLength(bufs[queued_count]) > GLOBAL_MTU_SIZE))
                {
                    // we are capturing packets and this can happen, so we just log it
                    LOGW("CaptureDevice: ReadThread: read packet size %d exceeds GLOBAL_MTU_SIZE %d",
                         sbufGetLength(bufs[queued_count]), GLOBAL_MTU_SIZE);
                    bufferpoolReuseBuffer(cdev->reader_buffer_pool, bufs[queued_count]);
                    continue;
                }

                queued_count++;
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
             fds[0].revents, fds[1].revents);
        return 0;
    }

    return 0;
}

bool caputredeviceBringUp(capture_device_t *cdev)
{
    assert(! cdev->up);

    if (execCmd(cdev->bringup_command).exit_code != 0)
    {
        LOGE("CaptureDevice: command failed: %s", cdev->bringup_command);
        terminateProgram(1);
        return false;
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

    cdev->running = false;
    cdev->up      = false;

    atomicThreadFence(memory_order_release);

    if (execCmd(cdev->bringdown_command).exit_code != 0)
    {
        LOGE("CaptureDevice: command failed: %s", cdev->bringdown_command);
        terminateProgram(1);
    }

    ssize_t write_res = write(cdev->linux_pipe_fds[1], "x", 1);
    discard write_res;
    safeThreadJoin(cdev->read_thread);

    LOGI("CaptureDevice: device %s is now down", cdev->name);

    return true;
}

capture_device_t *caputredeviceCreate(const char *name, const char *capture_ip, void *userdata,
                                      CaptureReadEventHandle cb)
{

    /* Fixing the most crazy socket stop reason */
    execCmd(sysctl_set_rmem_max);
    execCmd(sysctl_set_rmem_default);
    execCmd(sysctl_set_wmem_max);
    execCmd(sysctl_set_wmem_default);

    int socket_netfilter = socket(AF_NETLINK, SOCK_RAW, NETLINK_NETFILTER);
    if (socket_netfilter < 0)
    {
        LOGE("CaptureDevice: unable to create a netfilter socket");
        return NULL;
    }

    struct sockaddr_nl nl_addr;
    memorySet(&nl_addr, 0x0, sizeof(nl_addr));
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

    char *bringup_cmd   = memoryAllocate(100);
    char *bringdown_cmd = memoryAllocate(100);
    stringNPrintf(bringup_cmd, 100, ip_tables_enable_queue_mi, capture_ip, queue_number);
    stringNPrintf(bringdown_cmd, 100, ip_tables_disable_queue_mi, capture_ip, queue_number);

    if (! netfilterSetConfig(socket_netfilter, NFQNL_CFG_CMD_BIND, queue_number, 0))
    {
        LOGE("CaptureDevice: unable to bind netfilter to queue number %u", queue_number);
        close(socket_netfilter);
        return NULL;
    }

    uint32_t range = kEthDataLen + sizeof(struct ethhdr) + sizeof(struct nfqnl_msg_packet_hdr);
    if (! netfilterSetParams(socket_netfilter, queue_number, NFQNL_COPY_PACKET, range))
    {
        LOGE("CaptureDevice: unable to set netfilter into copy packet mode with maximum "
             "buffer size %u",
             range);

        close(socket_netfilter);
        return NULL;
    }
    if (! netfilterSetQueueLength(socket_netfilter, queue_number, kNetfilterQueueLen))
    {
        LOGE("CaptureDevice: unable to set netfilter queue maximum length to %u", kNetfilterQueueLen);

        close(socket_netfilter);
        return NULL;
    }
    int rcvbuf_size = 64 * 1024 * 1024; // 64MB
    if (setsockopt(socket_netfilter, SOL_SOCKET, SO_RCVBUF, &rcvbuf_size, sizeof(rcvbuf_size)) < 0)
    {
        LOGE("CaptureDevice: failed to set SO_RCVBUF: %s", strerror(errno));
        close(socket_netfilter);
        return NULL;
    }

    buffer_pool_t *reader_bpool =
        bufferpoolCreate(GSTATE.masterpool_buffer_pools_large, GSTATE.masterpool_buffer_pools_small, RAM_PROFILE,
                         bufferpoolGetLargeBufferSize(getWorkerBufferPool(getWID())),
                         bufferpoolGetSmallBufferSize(getWorkerBufferPool(getWID()))

        );

    capture_device_t *cdev = memoryAllocate(sizeof(capture_device_t));

    *cdev = (capture_device_t){.name                   = stringDuplicate(name),
                               .running                = false,
                               .up                     = false,
                               .routine_reader         = routineReadFromCapture,
                               .socket                 = socket_netfilter,
                               .queue_number           = queue_number,
                               .read_event_callback    = cb,
                               .userdata               = userdata,
                               .reader_message_pool    = masterpoolCreateWithCapacity(RAM_PROFILE * 2),
                               .netfilter_queue_number = queue_number,
                               .bringup_command        = bringup_cmd,
                               .bringdown_command      = bringdown_cmd,
                               .reader_buffer_pool     = reader_bpool};
    if (pipe(cdev->linux_pipe_fds) != 0)
    {
        LOGE("CaptureDevice: failed to create pipe for linux_pipe_fds");
        memoryFree(cdev->name);
        memoryFree(cdev->bringup_command);
        memoryFree(cdev->bringdown_command);
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
    memoryFree(cdev->bringup_command);
    memoryFree(cdev->bringdown_command);
    bufferpoolDestroy(cdev->reader_buffer_pool);
    masterpoolMakeEmpty(cdev->reader_message_pool, NULL);
    masterpoolDestroy(cdev->reader_message_pool);
    close(cdev->socket);
    memoryFree(cdev);
}

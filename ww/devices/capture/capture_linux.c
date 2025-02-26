#include "capture.h"
#include "generic_pool.h"
#include "wchan.h"
#include "loggers/internal_logger.h"
#include "worker.h"
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
#include <string.h>
#include <sys/ioctl.h>

enum
{
    kReadPacketSize              = 1500,
    kEthDataLen                  = 1500,
    kMasterMessagePoosbufGetLeftCapacity        = 64,
    kQueueLen                    = 512,
    kCaptureWriteChannelQueueMax = 128
};

struct msg_event
{
    capture_device_t *cdev;
    sbuf_t   *buf;
};

static pool_item_t *allocCaptureMsgPoolHandle(master_pool_t *pool, void *userdata)
{
    (void) userdata;
    (void) pool;
    return memoryAllocate(sizeof(struct msg_event));
}

static void destroyCaptureMsgPoolHandle(master_pool_t *pool, master_pool_item_t *item, void *userdata)
{
    (void) pool;
    (void) userdata;
    memoryFree(item);
}

static void localThreadEventReceived(wevent_t *ev)
{
    struct msg_event *msg = weventGetUserdata(ev);
    wid_t             tid = (wid_t) (wloopGetWid(weventGetLoop(ev)));

    msg->cdev->read_event_callback(msg->cdev, msg->cdev->userdata, msg->buf, tid);

    masterpoolReuseItems(msg->cdev->reader_message_pool, (void **) &msg, 1, msg->cdev);
}

static void distributePacketPayload(capture_device_t *cdev, wid_t target_wid, sbuf_t *buf)
{
    struct msg_event *msg;
    masterpoolGetItems(cdev->reader_message_pool, (const void **) &(msg), 1, cdev);

    *msg = (struct msg_event) {.cdev = cdev, .buf = buf};

    wevent_t ev;
    memorySet(&ev, 0, sizeof(ev));
    ev.loop = getWorkerLoop(target_wid);
    ev.cb   = localThreadEventReceived;
    weventSetUserData(&ev, msg);
    wloopPostEvent(getWorkerLoop(target_wid), &ev);
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
    // Read a message from netlink
    char               nl_buff[512 + kEthDataLen + sizeof(struct ethhdr) + sizeof(struct nfqnl_msg_packet_hdr)];
    struct sockaddr_nl nl_addr;
    socklen_t          nl_addr_len = sizeof(nl_addr);
    ssize_t            result =
        recvfrom(netfilter_socket, nl_buff, sizeof(nl_buff), 0, (struct sockaddr *) &nl_addr, &nl_addr_len);

    if (result <= (int) sizeof(struct nlmsghdr))
    {
        errno = EINVAL;
        return -1;
    }
    if (nl_addr_len != sizeof(nl_addr) || nl_addr.nl_pid != 0)
    {
        errno = EINVAL;
        return false;
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
    sbufSetLength(buff, nl_data_size);
    // struct ethhdr *eth_header = (struct ethhdr *) buff;
    // memorySet(&eth_header->h_dest, 0x0, ETH_ALEN);
    // memorySet(&eth_header->h_source, 0x0, ETH_ALEN);
    // eth_header->h_proto = htons(ETH_P_IP);

    struct iphdr *ip_header = (struct iphdr *) sbufGetMutablePtr(buff);
    memoryMove(ip_header, nl_data, nl_data_size);

    return (int) (nl_data_size);
}

static WTHREAD_ROUTINE(routineReadFromCapture) // NOLINT
{
    capture_device_t *cdev           = userdata;
    wid_t             distribute_tid = 0;
    sbuf_t   *buf;
    ssize_t           nread;

    while (atomicLoadExplicit(&(cdev->running), memory_order_relaxed))
    {
        buf = bufferpoolGetSmallBuffer(cdev->reader_buffer_pool);

        buf = sbufReserveSpace(buf, kReadPacketSize);

        nread = netfilterGetPacket(cdev->socket, cdev->queue_number, buf);

        if (nread == 0)
        {
            bufferpoolReuseBuffer(cdev->reader_buffer_pool, buf);
            LOGW("CaptureDevice: Exit read routine due to End Of File");
            return 0;
        }

        if (nread < 0)
        {
            bufferpoolReuseBuffer(cdev->reader_buffer_pool, buf);
            LOGW("CaptureDevice: failed to read a packet from netfilter socket, retrying...");
            continue;
        }

        sbufSetLength(buf, nread);

        distributePacketPayload(cdev, distribute_tid++, buf);

        if (distribute_tid >= getWorkersCount())
        {
            distribute_tid = 0;
        }
    }

    return 0;
}

static WTHREAD_ROUTINE(routineWriteToCapture) // NOLINT
{
    capture_device_t *cdev = userdata;
    sbuf_t   *buf;
    ssize_t           nwrite;

    while (atomicLoadExplicit(&(cdev->running), memory_order_relaxed))
    {
        if (! chanRecv(cdev->writer_buffer_channel, &buf))
        {
            LOGD("CaptureDevice: routine write will exit due to channel closed");
            return 0;
        }

        struct iphdr *ip_header = (struct iphdr *) sbufGetRawPtr(buf);

        struct sockaddr_in to_addr = {.sin_family = AF_INET, .sin_addr.s_addr = ip_header->daddr};

        nwrite = sendto(cdev->socket, ip_header, sbufGetLength(buf), 0, (struct sockaddr *) (&to_addr), sizeof(to_addr));

        bufferpoolReuseBuffer(cdev->writer_buffer_pool, buf);

        if (nwrite == 0)
        {
            LOGW("CaptureDevice: Exit write routine due to End Of File");
            return 0;
        }

        if (nwrite < 0)
        {
            LOGW("CaptureDevice: writing a packet to Capture device failed, code: %d", (int) nwrite);
            if (errno == EINVAL || errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
            {
                continue;
            }
            LOGE("CaptureDevice: Exit write routine due to critical error");
            return 0;
        }
    }
    return 0;
}

bool writeToCaptureDevce(capture_device_t *cdev, sbuf_t *buf)
{
    bool closed = false;
    if (! chanTrySend(cdev->writer_buffer_channel, &buf, &closed))
    {
        if (closed)
        {
            LOGE("CaptureDevice: write failed, channel was closed");
        }
        else
        {
            LOGE("CaptureDevice:write failed, ring is full");
        }
        return false;
    }
    return true;
}

bool bringCaptureDeviceUP(capture_device_t *cdev)
{
    assert(! cdev->up);

    cdev->up      = true;
    cdev->running = true;

    LOGD("CaptureDevice: device %s is now up", cdev->name);

    cdev->read_thread  = threadCreate(cdev->routine_reader, cdev);
    cdev->write_thread = threadCreate(cdev->routine_writer, cdev);
    return true;
}

bool bringCaptureDeviceDown(capture_device_t *cdev)
{
    assert(cdev->up);

    cdev->running = false;
    cdev->up      = false;

    chanClose(cdev->writer_buffer_channel);

    LOGD("CaptureDevice: device %s is now down", cdev->name);

    threadJoin(cdev->read_thread);
    threadJoin(cdev->write_thread);

    sbuf_t *buf;
    while (chanRecv(cdev->writer_buffer_channel, &buf))
    {
        bufferpoolReuseBuffer(cdev->reader_buffer_pool, buf);
    }

    return true;
}

capture_device_t *createCaptureDevice(const char *name, uint32_t queue_number, void *userdata,
                                      CaptureReadEventHandle cb)
{

    int socket_netfilter = socket(AF_NETLINK, SOCK_RAW, NETLINK_NETFILTER);
    if (socket_netfilter < 0)
    {
        LOGE("CaptureDevice: unable to create a netfilter socket");
    }

    struct sockaddr_nl nl_addr;
    memorySet(&nl_addr, 0x0, sizeof(nl_addr));
    nl_addr.nl_family = AF_NETLINK;
    nl_addr.nl_pid    = getpid();

    if (bind(socket_netfilter, (struct sockaddr *) &nl_addr, sizeof(nl_addr)) != 0)
    {
        LOGE("CaptureDevice: unable to bind netfilter socket to current process");
    }

    if (! netfilterSetConfig(socket_netfilter, NFQNL_CFG_CMD_PF_UNBIND, 0, PF_INET))
    {
        LOGE("CaptureDevice: unable to unbind netfilter from PF_INET");
    }
    if (! netfilterSetConfig(socket_netfilter, NFQNL_CFG_CMD_PF_BIND, 0, PF_INET))
    {
        LOGE("CaptureDevice: unable to bind netfilter to PF_INET");
    }
    if (! netfilterSetConfig(socket_netfilter, NFQNL_CFG_CMD_BIND, queue_number, 0))
    {
        LOGE("CaptureDevice: unable to bind netfilter to queue number %u", queue_number);
    }
    uint32_t range = kEthDataLen + sizeof(struct ethhdr) + sizeof(struct nfqnl_msg_packet_hdr);
    if (! netfilterSetParams(socket_netfilter, queue_number, NFQNL_COPY_PACKET, range))
    {
        LOGE("CaptureDevice: unable to set netfilter into copy packet mode with maximum "
             "buffer size %u",
             range);
    }
    if (! netfilterSetQueueLength(socket_netfilter, queue_number, kQueueLen))
    {
        LOGE("CaptureDevice: unable to set netfilter queue maximum length to %u", kQueueLen);
    }

    buffer_pool_t *reader_bpool = bufferpoolCreate(GSTATE.masterpool_buffer_pools_large,
                                                   GSTATE.masterpool_buffer_pools_small, GSTATE.ram_profile);

    buffer_pool_t *writer_bpool =
        bufferpoolCreate(GSTATE.masterpool_buffer_pools_large, GSTATE.masterpool_buffer_pools_small, 1);

    capture_device_t *cdev = memoryAllocate(sizeof(capture_device_t));

    *cdev = (capture_device_t) {.name                  = stringDuplicate(name),
                                .running               = false,
                                .up                    = false,
                                .routine_reader        = routineReadFromCapture,
                                .routine_writer        = routineWriteToCapture,
                                .socket                = socket_netfilter,
                                .queue_number          = queue_number,
                                .read_event_callback   = cb,
                                .userdata              = userdata,
                                .writer_buffer_channel = chanOpen(sizeof(void *), kCaptureWriteChannelQueueMax),
                                .reader_message_pool   = masterpoolCreateWithCapacity(kMasterMessagePoosbufGetLeftCapacity),
                                .reader_buffer_pool    = reader_bpool,
                                .writer_buffer_pool    = writer_bpool};

    masterpoolInstallCallBacks(cdev->reader_message_pool, allocCaptureMsgPoolHandle, destroyCaptureMsgPoolHandle);

    return cdev;
}

#pragma once
#include "capture_linux_private.h"

typedef enum netfilter_packet_result_e
{
    kNetfilterPacketError = -1,
    kNetfilterPacketWouldBlock,
    kNetfilterPacketYield,
    kNetfilterPacketEof,
    kNetfilterPacketAccepted,
    kNetfilterPacketDiscarded,
    kNetfilterPacketMalformedDiscarded,
    kNetfilterPacketReady
} netfilter_packet_result_t;

typedef enum netfilter_verdict_result_e
{
    kNetfilterVerdictError = -1,
    kNetfilterVerdictWouldBlock,
    kNetfilterVerdictYield,
    kNetfilterVerdictSent
} netfilter_verdict_result_t;

typedef struct netfilter_packet_record_s
{
    sbuf_t                   *buffer;
    netfilter_packet_result_t result;
    uint32_t                  packet_id;
    uint32_t                  verdict;
    int                       error;
} netfilter_packet_record_t;

typedef struct netfilter_batch_workspace_s netfilter_batch_workspace_t;

/* Queue-local descriptor/message storage. It owns no packet buffers and may be
 * reused only after its synchronous receive or verdict call returns. */
netfilter_batch_workspace_t *netfilterBatchWorkspaceCreate(uint16_t capacity);
void                         netfilterBatchWorkspaceDestroy(netfilter_batch_workspace_t *workspace);

/* Receive at most capacity datagrams without waiting for a full batch. Every
 * records[i].buffer must provide kNetfilterReadBufferSize writable bytes. Ready
 * means received contains the consumed datagram count; inspect every record's
 * result/error, including after a malformed datagram. Every Ready, Discarded or
 * MalformedDiscarded record owes its packet_id a verdict; Error/Eof do not.
 * Other aggregate results consume no datagrams and set received to zero. The
 * caller retains all buffers on every result. */
netfilter_packet_result_t netfilterReceiveBatch(int netfilter_socket, netfilter_batch_workspace_t *workspace,
                                                netfilter_packet_record_t *records, uint16_t capacity,
                                                uint16_t *received);

/* Submit explicit per-packet verdicts. Sent commits the returned nonempty
 * prefix, which may be shorter than count. Retain the unsent suffix in order.
 * Other results commit no records. No buffer or record ownership transfers. */
netfilter_verdict_result_t netfilterTrySendVerdictBatch(int netfilter_socket, uint16_t qnumber,
                                                        netfilter_batch_workspace_t     *workspace,
                                                        const netfilter_packet_record_t *records, uint16_t count,
                                                        uint16_t *sent);

/* Probe only before any capture rules can enqueue packets. A successful ACK or
 * ENOENT establishes support; EINVAL/EOPNOTSUPP means unavailable. Other errors
 * fail setup. Return 1, 0 or -1 respectively. */
int netfilterProbeVerdictBatch(int netfilter_socket, uint16_t qnumber);

/* The queue's exclusive reader may settle one same-verdict prefix through its
 * final network-order packet id. Every queued id covered by that boundary must
 * already belong to that prefix. Never choose a boundary by numeric maximum:
 * packet ids wrap. No buffer or record ownership transfers. */
netfilter_verdict_result_t netfilterTrySendCumulativeVerdict(int netfilter_socket, uint16_t qnumber,
                                                             uint32_t last_packet_id, uint32_t verdict);

/* Both operations are nonblocking, retain caller ownership of buf and never
 * poll. Ready/Discarded/MalformedDiscarded mean one packet was consumed and
 * packet_id receives its network-order id: the caller owes a verdict even for
 * discarded input. Ready exposes the validated IP packet in buf. Other results
 * leave packet_id unchanged and owe no verdict. Yield bounds interrupted
 * syscalls and requires an explicit continuation, without a readiness edge.
 *
 * Keep the packet, id and selected host-order verdict until Sent; no packet may
 * be published before that result. WouldBlock needs writable readiness, Yield
 * needs a continuation, and the owner enforces its absolute verdict deadline. */
netfilter_packet_result_t  netfilterReceivePacket(int netfilter_socket, sbuf_t *buf, uint32_t *packet_id);
netfilter_verdict_result_t netfilterTrySendVerdict(int netfilter_socket, uint16_t qnumber, uint32_t packet_id,
                                                   uint32_t verdict);

/* Acknowledged setup and bounded coordinator-only cleanup. Do not call the
 * blocking GetPacket wrappers from an event-worker receive callback. */
bool                      netfilterSetConfig(int netfilter_socket, uint8_t cmd, uint16_t qnum, uint16_t pf);
bool                      netfilterSetParams(int netfilter_socket, uint16_t qnumber, uint8_t mode, uint32_t range);
bool                      netfilterSetQueueLength(int netfilter_socket, uint16_t qnumber, uint32_t qlen);
netfilter_packet_result_t netfilterGetPacketUntil(capture_device_t *cdev, int netfilter_socket, uint16_t qnumber,
                                                  sbuf_t *buff, uint64_t verdict_deadline_us);
netfilter_packet_result_t netfilterGetPacket(capture_device_t *cdev, int netfilter_socket, uint16_t qnumber,
                                             sbuf_t *buff);

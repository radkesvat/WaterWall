#include "global_state.h"
#include "loggers/internal_logger.h"
#include "net/ipv4_packet_view.h"
#include "raw_linux_internal.h"
#include "raw_linux_send_policy.h"
#include "raw_private.h"
#include "worker.h"
#include <arpa/inet.h>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/ipv6.h>
#include <netinet/ip.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

enum
{
    kRawWriteQueueMax    = 128 * 1024,
    kRawSocketSendBuffer = 16 * 1024 * 1024
};

typedef enum rawdevice_discard_reason_e
{
    kRawDeviceDiscardOversized,
    kRawDeviceDiscardMessageTooLarge,
    kRawDeviceDiscardPacketLocalSendError,
    kRawDeviceDiscardTransientSendError
} rawdevice_discard_reason_t;

static void rawdeviceLogSocketBufferSize(int socket_fd, int option, const char *name)
{
    int       actual = 0;
    socklen_t len    = sizeof(actual);

    if (getsockopt(socket_fd, SOL_SOCKET, option, &actual, &len) != 0)
    {
        LOGW("RawDevice: failed to read actual %s: %s", name, strerror(errno));
        return;
    }

    LOGD("RawDevice: actual %s is %d bytes", name, actual);
}

static void rawdeviceRecordDiscard(raw_linux_writer_state_t *state, rawdevice_discard_reason_t reason, int send_error)
{
    if (reason == kRawDeviceDiscardOversized)
    {
        state->oversized_packet_total++;
    }
    else if (reason == kRawDeviceDiscardMessageTooLarge)
    {
        state->message_too_large_packet_total++;
    }
    else if (reason == kRawDeviceDiscardPacketLocalSendError)
    {
        state->packet_local_send_error_total++;
    }
    else
    {
        state->transient_send_error_total++;
    }
    if (send_error != 0)
    {
        state->last_discard_error = (uint32_t) send_error;
    }

    log_rate_limiter_report_t report = logRateLimiterRecord(&state->discard_log_limiter, kRawDiscardReportIntervalMs);
    if (! report.should_log)
    {
        return;
    }

    LOGW("RawDevice: discarded %llu packet(s) over %llums "
         "(total=%llu, exceeding kMaxAllowedPacketLength=%u: %llu, EMSGSIZE=%llu, "
         "other packet-local send errors=%llu, transient send errors=%llu, last errno=%u)",
         LLU(report.events),
         LLU(report.elapsed_ms),
         LLU(report.total),
         (unsigned int) kMaxAllowedPacketLength,
         LLU(state->oversized_packet_total),
         LLU(state->message_too_large_packet_total),
         LLU(state->packet_local_send_error_total),
         LLU(state->transient_send_error_total),
         state->last_discard_error);
}

static void rawdeviceReportPendingDiscards(raw_linux_writer_state_t *state)
{
    log_rate_limiter_report_t report = logRateLimiterFlush(&state->discard_log_limiter);
    if (! report.should_log)
    {
        return;
    }

    LOGW("RawDevice: discarded %llu packet(s) before worker output stops "
         "(total=%llu, exceeding kMaxAllowedPacketLength=%u: %llu, EMSGSIZE=%llu, "
         "other packet-local send errors=%llu, transient send errors=%llu, last errno=%u)",
         LLU(report.events),
         LLU(report.total),
         (unsigned int) kMaxAllowedPacketLength,
         LLU(state->oversized_packet_total),
         LLU(state->message_too_large_packet_total),
         LLU(state->packet_local_send_error_total),
         LLU(state->transient_send_error_total),
         state->last_discard_error);
}

static raw_writer_batch_result_t rawLinuxWriteFailed(raw_device_t *rdev)
{
    raw_lifecycle_state_t failed_from;
    const bool fatal = rawLifecycleTransitionToFailed(&rdev->lifecycle, &failed_from) && failed_from == kRawLifecycleUp;
    return (raw_writer_batch_result_t) {.status = fatal ? kRawWriterBatchFailed : kRawWriterBatchContinue};
}

raw_writer_batch_result_t rawLinuxWriteBatch(void *context, worker_t *worker, raw_writer_lane_t *lane, sbuf_t **buffers,
                                             size_t count)
{
    discard                   lane;
    raw_device_t             *rdev  = context;
    raw_linux_writer_state_t *state = &rdev->writer_states[worker->wid];
    assert(count > 0 && count <= kRawWriterBatchPackets);

    if (state->waiting_writable)
    {
        struct pollfd readiness = {.fd = rdev->socket, .events = POLLOUT};
        const int     ready     = poll(&readiness, 1, 0);
        if (ready == 0)
            return (raw_writer_batch_result_t) {.status = kRawWriterBatchBlocked};
        if (ready < 0 && errno == EINTR)
            return (raw_writer_batch_result_t) {.status = kRawWriterBatchContinue};
        if (ready < 0 || (readiness.revents & (POLLERR | POLLHUP | POLLNVAL)) != 0 ||
            (readiness.revents & POLLOUT) == 0)
        {
            LOGE("RawDevice: terminal writable check on device %s: result=%d, events=0x%x, errno=%d",
                 rdev->name,
                 ready,
                 readiness.revents,
                 ready < 0 ? errno : 0);
            return rawLinuxWriteFailed(rdev);
        }
        state->waiting_writable = false;
    }

    struct mmsghdr     messages[kRawWriterBatchPackets];
    struct iovec       iovs[kRawWriterBatchPackets];
    struct sockaddr_in addresses[kRawWriterBatchPackets];
    size_t             prepared = 0;
    for (; prepared < count; ++prepared)
    {
        sbuf_t            *buffer    = buffers[prepared];
        const uint32_t     length    = sbufGetLength(buffer);
        ipv4_packet_view_t packet    = {0};
        const bool         oversized = length > kMaxAllowedPacketLength;
        if (oversized || ! ipv4packetviewParse(sbufGetRawPtr(buffer), length, &packet) ||
            packet.ip_total_length != length)
        {
            /* Never discard a later packet across an unsent prefix. It will
             * reach the front after that prefix has been settled. */
            if (prepared != 0)
                break;
            rawdeviceRecordDiscard(state,
                                   oversized ? kRawDeviceDiscardOversized : kRawDeviceDiscardPacketLocalSendError,
                                   oversized ? 0 : EINVAL);
            bufferpoolReuseBuffer(worker->buffer_pool, buffer);
            return (raw_writer_batch_result_t) {.consumed = 1, .status = kRawWriterBatchContinue};
        }

        addresses[prepared] =
            (struct sockaddr_in) {.sin_family = AF_INET, .sin_addr.s_addr = packet.destination_address};
        iovs[prepared]     = (struct iovec) {.iov_base = (void *) sbufGetRawPtr(buffer), .iov_len = length};
        messages[prepared] = (struct mmsghdr) {.msg_hdr = {.msg_name    = &addresses[prepared],
                                                           .msg_namelen = sizeof(addresses[prepared]),
                                                           .msg_iov     = &iovs[prepared],
                                                           .msg_iovlen  = 1}};
    }

    /* One syscall per callback bounds interruption/error work as well as the
     * successful batch. A partial result leaves the suffix at this worker's
     * FIFO head; no packet from a later submission can overtake it. */
    const int sent = sendmmsg(rdev->socket, messages, (unsigned int) prepared, MSG_DONTWAIT);
    if (sent > 0)
    {
        assert((size_t) sent <= prepared);
        for (int i = 0; i < sent; ++i)
            bufferpoolReuseBuffer(worker->buffer_pool, buffers[i]);
        return (raw_writer_batch_result_t) {.consumed = (size_t) sent, .status = kRawWriterBatchContinue};
    }

    if (sent < 0)
    {
        const int error = errno;
        switch (rawLinuxClassifySendError(error))
        {
        case kRawLinuxSendRetryImmediately:
            return (raw_writer_batch_result_t) {.status = kRawWriterBatchContinue};
        case kRawLinuxSendWaitWritable:
            state->waiting_writable = true;
            return (raw_writer_batch_result_t) {.status = kRawWriterBatchBlocked};
        case kRawLinuxSendDiscardPacket: {
            const rawdevice_discard_reason_t reason = error == EMSGSIZE ? kRawDeviceDiscardMessageTooLarge
                                                      : rawLinuxSendErrorIsResourcePressure(error)
                                                          ? kRawDeviceDiscardTransientSendError
                                                          : kRawDeviceDiscardPacketLocalSendError;
            rawdeviceRecordDiscard(state, reason, error);
            bufferpoolReuseBuffer(worker->buffer_pool, buffers[0]);
            return (raw_writer_batch_result_t) {.consumed = 1, .status = kRawWriterBatchContinue};
        }
        case kRawLinuxSendTerminal:
            LOGE("RawDevice: terminal sendmmsg() failure on device %s: errno %d (%s)",
                 rdev->name,
                 error,
                 strerror(error));
            break;
        }
    }
    else
    {
        LOGE("RawDevice: sendmmsg() made no progress for a non-empty batch");
    }

    return rawLinuxWriteFailed(rdev);
}

static void rawLinuxWriterStop(void *context, wid_t wid)
{
    raw_device_t *rdev = context;
    rawdeviceReportPendingDiscards(&rdev->writer_states[wid]);
}

bool rawdeviceIsUp(const raw_device_t *rdev)
{
    return rdev != NULL && rawLifecycleLoad(&rdev->lifecycle) == kRawLifecycleUp;
}

/* Failure-only TLS sampler: shutdown bursts retain useful evidence without a
 * time read, shared atomic, or any work on the successful writer path. */
static bool rawdeviceShouldLogRefusal(void)
{
    static thread_local uint32_t refusal_count;
    const uint32_t               ordinal = ++refusal_count;

    return ordinal == 1 || (ordinal & (ordinal - 1U)) == 0;
}

bool rawdeviceWrite(raw_device_t *rdev, sbuf_t *buf)
{
    assert(sbufGetLength(buf) >= sizeof(struct iphdr));

    if (UNLIKELY(! rawdeviceIsUp(rdev)))
    {
        if (rawdeviceShouldLogRefusal())
        {
            LOGE("RawDevice: write failed, device is not up");
        }
        return false;
    }

    switch (rawWriterTrySend(&rdev->writer, buf))
    {
    case kRawWriterSendOk:
        return true;
    case kRawWriterSendDown:
        if (rawdeviceShouldLogRefusal())
        {
            LOGE("RawDevice: write failed, device is down");
        }
        return false;
    case kRawWriterSendClosed:
        if (rawdeviceShouldLogRefusal())
        {
            LOGE("RawDevice: write failed, output admission was closed");
        }
        return false;
    case kRawWriterSendFull:
        return false;
    }

    return false;
}

bool rawdeviceBringUp(raw_device_t *rdev)
{
    if (rdev->writer.current != NULL)
    {
        LOGE("RawDevice: previous writer ownership has not been released");
        return false;
    }
    if (! rawLifecycleTransitionDownToStarting(&rdev->lifecycle))
    {
        LOGE("RawDevice: device cannot be started in current lifecycle state");
        return false;
    }

    if (! rawLinuxNotrackRemove(rdev) || ! rawLinuxNotrackInstall(rdev))
        goto rollback;

    rdev->writer_worker_count = getWorkersCount();
    rdev->writer_states       = memoryAllocateZero(rdev->writer_worker_count * sizeof(*rdev->writer_states));
    if (! rawWriterOpen(&rdev->writer, kRawWriteQueueMax, 1, rdev, rawLinuxWriteBatch, rawLinuxWriterStop))
    {
        LOGE("RawDevice: failed to open worker output queues");
        goto rollback;
    }

    if (! rawLifecycleTransitionStartingToUp(&rdev->lifecycle))
        goto rollback;

    LOGD("RawDevice: device %s is now up", rdev->name);
    return true;

rollback:
    discard rawdeviceBringDown(rdev);
    return false;
}

void rawdeviceRequestStop(raw_device_t *rdev)
{
    rawLifecycleTransitionToStopping(&rdev->lifecycle);
    rawWriterCloseRequest(&rdev->writer);
}

bool rawdeviceBringDown(raw_device_t *rdev)
{
    rawdeviceRequestStop(rdev);
    rawWriterCloseWait(&rdev->writer);
    memoryFree(rdev->writer_states);
    rdev->writer_states       = NULL;
    rdev->writer_worker_count = 0;

    /* Every admitted native send has finished before its exemption is removed. */
    if (! rawLinuxNotrackRemove(rdev))
        return false;

    rawLifecycleTransitionStoppingToDown(&rdev->lifecycle);
    LOGD("RawDevice: device %s is now down", rdev->name);
    return true;
}

raw_device_t *rawdeviceCreate(const char *name, uint32_t mark, bool bypass_conntrack, void *userdata)
{
    assert(! bypass_conntrack || mark == 0);
    int rsocket = socket(PF_INET, SOCK_RAW, IPPROTO_RAW);
    if (rsocket < 0)
    {
        LOGE("RawDevice: unable to open a raw socket");
        return NULL;
    }

    if (mark != 0)
    {
        if (setsockopt(rsocket, SOL_SOCKET, SO_MARK, &mark, sizeof(mark)) != 0)
        {
            LOGE("RawDevice:  unable to set raw socket mark to %u", mark);
            close(rsocket);
            return NULL;
        }
    }
    int one = 1;
    if (setsockopt(rsocket, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0)
    {
        LOGE("RawDevice: unable to enable IP_HDRINCL: %s", strerror(errno));
        close(rsocket);
        return NULL;
    }
    int flags = fcntl(rsocket, F_GETFL, 0);
    if (flags < 0)
    {
        LOGE("RawDevice: unable to get raw socket flags: %s", strerror(errno));
        close(rsocket);
        return NULL;
    }
    if (fcntl(rsocket, F_SETFL, flags | O_NONBLOCK) < 0)
    {
        LOGE("RawDevice: unable to set raw socket nonblocking mode: %s", strerror(errno));
        close(rsocket);
        return NULL;
    }

    int sndbuf = kRawSocketSendBuffer;
    if (setsockopt(rsocket, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf)) < 0)
    {
        LOGW("RawDevice: failed to set SO_SNDBUF: %s", strerror(errno));
    }
    rawdeviceLogSocketBufferSize(rsocket, SO_SNDBUF, "SO_SNDBUF");

    discard       getCurrentWorker();
    raw_device_t *rdev     = memoryAllocateZero(sizeof(*rdev));
    rdev->name             = stringDuplicate(name);
    rdev->socket           = rsocket;
    rdev->mark             = mark;
    rdev->bypass_conntrack = bypass_conntrack;
    rdev->userdata         = userdata;
    atomic_init(&rdev->lifecycle, kRawLifecycleDown);
    rawWriterInit(&rdev->writer);

    return rdev;
}

void rawdeviceDestroy(raw_device_t *rdev)
{
    discard rawdeviceBringDown(rdev);
    if (rdev->notrack_rule_pending)
        discard rawLinuxNotrackRemove(rdev);
    /* Producers have quiesced; late scheduled cleanup owns only its generation. */
    rawWriterDestroy(&rdev->writer);
    memoryFree(rdev->name);
    close(rdev->socket);
    memoryFree(rdev);
}

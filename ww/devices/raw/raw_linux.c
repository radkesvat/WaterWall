#include "generic_pool.h"
#include "global_state.h"
#include "loggers/internal_logger.h"
#include "raw.h"
#include "raw_linux_internal.h"
#include "raw_linux_send_policy.h"
#include "wchan.h"
#include "worker.h"
#include "wtime.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/ipv6.h>
#include <netinet/ip.h>
#include <poll.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

enum
{
    kRawWriteChannelQueueMax = 128 * 1024,
    kBatchSize               = 512,
    kRawSocketSendBuffer     = 16 * 1024 * 1024
};

typedef enum rawdevice_discard_reason_e
{
    kRawDeviceDiscardOversized,
    kRawDeviceDiscardMessageTooLarge,
    kRawDeviceDiscardPacketLocalSendError,
    kRawDeviceDiscardTransientSendError
} rawdevice_discard_reason_t;

typedef enum rawdevice_wait_writable_result_e
{
    kRawDeviceWaitWritableReady = 0,
    kRawDeviceWaitWritableStopped,
    kRawDeviceWaitWritableTerminal
} rawdevice_wait_writable_result_t;

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

static void rawdeviceRecordDiscard(raw_device_t *rdev, rawdevice_discard_reason_t reason, int send_error)
{
    unsigned long long now_ms = getTimeOfDayMS();

    rdev->discarded_packet_total++;
    rdev->discarded_packet_suppressed++;
    if (reason == kRawDeviceDiscardOversized)
    {
        rdev->oversized_packet_total++;
    }
    else if (reason == kRawDeviceDiscardMessageTooLarge)
    {
        rdev->message_too_large_packet_total++;
    }
    else if (reason == kRawDeviceDiscardPacketLocalSendError)
    {
        rdev->packet_local_send_error_total++;
    }
    else
    {
        rdev->transient_send_error_total++;
    }
    if (send_error != 0)
    {
        rdev->last_discard_error = (uint32_t) send_error;
    }

    if (rdev->discard_last_report_ms == 0)
    {
        rdev->discard_last_report_ms = now_ms;
        return;
    }

    unsigned long long elapsed_ms = now_ms - rdev->discard_last_report_ms;
    if (elapsed_ms < 1000)
    {
        return;
    }

    LOGW("RawDevice: discarded %llu packet(s) over %llums "
         "(total=%llu, exceeding kMaxAllowedPacketLength=%u: %llu, EMSGSIZE=%llu, "
         "other packet-local send errors=%llu, transient send errors=%llu, last errno=%u)",
         LLU(rdev->discarded_packet_suppressed),
         LLU(elapsed_ms),
         LLU(rdev->discarded_packet_total),
         (unsigned int) kMaxAllowedPacketLength,
         LLU(rdev->oversized_packet_total),
         LLU(rdev->message_too_large_packet_total),
         LLU(rdev->packet_local_send_error_total),
         LLU(rdev->transient_send_error_total),
         rdev->last_discard_error);
    rdev->discarded_packet_suppressed = 0;
    rdev->discard_last_report_ms      = now_ms;
}

static void rawdeviceReportPendingDiscards(raw_device_t *rdev)
{
    if (rdev->discarded_packet_suppressed == 0)
    {
        return;
    }

    LOGW("RawDevice: discarded %llu packet(s) before writer exit "
         "(total=%llu, exceeding kMaxAllowedPacketLength=%u: %llu, EMSGSIZE=%llu, "
         "other packet-local send errors=%llu, transient send errors=%llu, last errno=%u)",
         LLU(rdev->discarded_packet_suppressed),
         LLU(rdev->discarded_packet_total),
         (unsigned int) kMaxAllowedPacketLength,
         LLU(rdev->oversized_packet_total),
         LLU(rdev->message_too_large_packet_total),
         LLU(rdev->packet_local_send_error_total),
         LLU(rdev->transient_send_error_total),
         rdev->last_discard_error);
    rdev->discarded_packet_suppressed = 0;
}

static bool rawdevicePrepareSendMessage(raw_device_t *rdev, sbuf_t *buf, struct mmsghdr *msg, struct iovec *iov,
                                        struct sockaddr_in *addr)
{
    uint32_t packet_len = sbufGetLength(buf);
    if (UNLIKELY(packet_len > kMaxAllowedPacketLength))
    {
        rawdeviceRecordDiscard(rdev, kRawDeviceDiscardOversized, 0);
        bufferpoolReuseBuffer(rdev->writer_buffer_pool, buf);
        return false;
    }

    struct iphdr *ip_header = (struct iphdr *) sbufGetRawPtr(buf);

    memoryZero(addr, sizeof(*addr));
    addr->sin_family      = AF_INET;
    addr->sin_addr.s_addr = ip_header->daddr;

    iov->iov_base = (void *) ip_header;
    iov->iov_len  = packet_len;

    memoryZero(msg, sizeof(*msg));
    msg->msg_hdr.msg_name    = addr;
    msg->msg_hdr.msg_namelen = sizeof(*addr);
    msg->msg_hdr.msg_iov     = iov;
    msg->msg_hdr.msg_iovlen  = 1;
    return true;
}

static void rawdeviceReuseBatchRange(raw_device_t *rdev, sbuf_t **bufs, int begin, int end)
{
    for (int i = begin; i < end; ++i)
    {
        bufferpoolReuseBuffer(rdev->writer_buffer_pool, bufs[i]);
    }
}

static rawdevice_wait_writable_result_t rawdeviceWaitWritable(raw_device_t *rdev)
{
    while (rawLifecycleIsActive(rawLifecycleLoad(&rdev->lifecycle)))
    {
        struct pollfd pfd = {.fd = rdev->socket, .events = POLLOUT};
        int           res = poll(&pfd, 1, 50);

        if (res > 0)
        {
            if ((pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) != 0)
            {
                LOGE("RawDevice: poll() reported terminal writer events 0x%x", pfd.revents);
                return kRawDeviceWaitWritableTerminal;
            }
            if ((pfd.revents & POLLOUT) != 0)
            {
                return kRawDeviceWaitWritableReady;
            }

            LOGE("RawDevice: poll() returned unexpected writer events 0x%x", pfd.revents);
            return kRawDeviceWaitWritableTerminal;
        }
        if (res == 0)
        {
            continue;
        }

        const int poll_error = errno;
        if (poll_error == EINTR)
        {
            continue;
        }

        LOGE("RawDevice: poll() failed while waiting to write: errno %d (%s)", poll_error, strerror(poll_error));
        return kRawDeviceWaitWritableTerminal;
    }

    return kRawDeviceWaitWritableStopped;
}

WTHREAD_ROUTINE(rawLinuxWriteRoutine) // NOLINT
{
    raw_device_t   *rdev = userdata;
    sbuf_t         *buf;
    struct wchan_s *writer_channel = deviceWriterChannelGetConsumerChannel(&rdev->writer_channel);

    struct mmsghdr     msgs[kBatchSize];
    struct iovec       iovs[kBatchSize];
    struct sockaddr_in addrs[kBatchSize];
    sbuf_t            *bufs[kBatchSize];

    while (rawLifecycleIsActive(rawLifecycleLoad(&rdev->lifecycle)))
    {
        if (! chanRecv(writer_channel, (void **) &buf))
        {
            LOGD("RawDevice: routine write will exit due to channel closed");
            break;
        }

        int cnt = 0;
        if (rawdevicePrepareSendMessage(rdev, buf, &msgs[cnt], &iovs[cnt], &addrs[cnt]))
        {
            bufs[cnt] = buf;
            cnt++;
        }

        for (int i = 1; i < kBatchSize; ++i)
        {
            sbuf_t *b2     = NULL;
            bool    closed = false;
            if (! chanTryRecv(writer_channel, (void **) &b2, &closed))
            {
                if (closed)
                {
                    break;
                }
                break;
            }

            if (rawdevicePrepareSendMessage(rdev, b2, &msgs[cnt], &iovs[cnt], &addrs[cnt]))
            {
                bufs[cnt] = b2;
                cnt++;
            }
        }

        if (cnt == 0)
        {
            continue;
        }

        int sent = 0;
        while (sent < cnt)
        {
            if (! rawLifecycleIsActive(rawLifecycleLoad(&rdev->lifecycle)))
            {
                rawdeviceReuseBatchRange(rdev, bufs, sent, cnt);
                goto cleanup;
            }

            int res = sendmmsg(rdev->socket, &msgs[sent], cnt - sent, 0);
            if (res > 0)
            {
                // res messages were consumed
                rawdeviceReuseBatchRange(rdev, bufs, sent, sent + res);
                sent += res;
                continue;
            }

            if (UNLIKELY(res == 0))
            {
                LOGE("RawDevice: sendmmsg() made no progress for a non-empty batch");
                rawdeviceReuseBatchRange(rdev, bufs, sent, cnt);
                goto cleanup;
            }

            const int                     send_error = errno;
            const raw_linux_send_action_t action     = rawLinuxClassifySendError(send_error);

            if (action == kRawLinuxSendRetryImmediately)
            {
                continue;
            }
            if (action == kRawLinuxSendWaitWritable)
            {
                const rawdevice_wait_writable_result_t wait_result = rawdeviceWaitWritable(rdev);
                if (wait_result == kRawDeviceWaitWritableReady)
                {
                    continue;
                }

                rawdeviceReuseBatchRange(rdev, bufs, sent, cnt);
                goto cleanup;
            }
            if (action == kRawLinuxSendDiscardPacket)
            {
                rawdevice_discard_reason_t reason;
                if (send_error == EMSGSIZE)
                {
                    reason = kRawDeviceDiscardMessageTooLarge;
                }
                else if (rawLinuxSendErrorIsResourcePressure(send_error))
                {
                    reason = kRawDeviceDiscardTransientSendError;
                }
                else
                {
                    reason = kRawDeviceDiscardPacketLocalSendError;
                }
                rawdeviceRecordDiscard(rdev, reason, send_error);
                bufferpoolReuseBuffer(rdev->writer_buffer_pool, bufs[sent]);
                sent++;
                continue;
            }

            LOGE("RawDevice: terminal sendmmsg() failure on device %s: errno %d (%s)",
                 rdev->name,
                 send_error,
                 strerror(send_error));
            rawdeviceReuseBatchRange(rdev, bufs, sent, cnt);
            goto cleanup;
        }
    }

cleanup:
    rawdeviceReportPendingDiscards(rdev);
    return 0;
}

static void rawdeviceNoteUnexpectedWriterExit(raw_device_t *rdev)
{
    raw_lifecycle_state_t failed_from;
    if (! rawLifecycleTransitionToFailed(&rdev->lifecycle, &failed_from))
    {
        return;
    }

    LOGE("RawDevice: writer thread for device %s exited unexpectedly; the device is no longer usable", rdev->name);

    /*
     * A STARTING failure is owned by rawdeviceBringUp() and its synchronous
     * rollback. An already published device losing its only writer is fatal to
     * the packet chain, so hand teardown to worker 0 after this routine has
     * released every buffer it owned.
     */
    if (failed_from == kRawLifecycleUp && ! requestProgramShutdown(1))
    {
        abortProgramNow(1);
    }
}

static WTHREAD_ROUTINE(rawdeviceWriterThreadMain) // NOLINT
{
    raw_device_t *rdev = userdata;
    discard       rdev->routine_writer(rdev);
    rawdeviceNoteUnexpectedWriterExit(rdev);
    return 0;
}

bool rawdeviceIsUp(const raw_device_t *rdev)
{
    return rdev != NULL && rawLifecycleLoad(&rdev->lifecycle) == kRawLifecycleUp;
}

bool rawdeviceWrite(raw_device_t *rdev, sbuf_t *buf)
{
    assert(sbufGetLength(buf) > sizeof(struct iphdr));

    if (UNLIKELY(! rawdeviceIsUp(rdev)))
    {
        LOGE("RawDevice: write failed, device is not up");
        return false;
    }

    switch (deviceWriterChannelTrySend(&rdev->writer_channel, buf))
    {
    case kDeviceWriterSendOk:
        return true;
    case kDeviceWriterSendDown:
        LOGE("RawDevice: write failed, device is down");
        return false;
    case kDeviceWriterSendClosed:
        LOGE("RawDevice: write failed, channel was closed");
        return false;
    case kDeviceWriterSendFull:
        LOGE("RawDevice: write failed, ring is full");
        return false;
    }

    return false;
}

bool rawdeviceBringUp(raw_device_t *rdev)
{
    if (rdev->writer_joinable || deviceWriterChannelHasCurrent(&rdev->writer_channel))
    {
        LOGE("RawDevice: previous writer ownership has not been released");
        return false;
    }
    if (! rawLifecycleTransitionDownToStarting(&rdev->lifecycle))
    {
        LOGE("RawDevice: device cannot be started in current lifecycle state");
        return false;
    }

    bufferpoolUpdateAllocationPaddings(rdev->writer_buffer_pool,
                                       bufferpoolGetLargeBufferPadding(getWorkerBufferPool(getWID())),
                                       bufferpoolGetSmallBufferPadding(getWorkerBufferPool(getWID())));

    if (! deviceWriterChannelOpen(&rdev->writer_channel, kRawWriteChannelQueueMax))
    {
        LOGE("RawDevice: failed to open writer channel");
        rawLifecycleTransitionStoppingToDown(&rdev->lifecycle);
        return false;
    }

    // wthread_error_t read_error = threadCreate(&rdev->read_thread, rdev->routine_reader, rdev);

    wthread_error_t error = threadCreate(&rdev->write_thread, rawdeviceWriterThreadMain, rdev);
    if (UNLIKELY(error != kWThreadErrorNone))
    {
        LOGE("RawDevice: failed to create writer thread: error %u (%s)", error, strerror((int) error));
        deviceWriterChannelClose(&rdev->writer_channel);
        discard deviceWriterChannelRetireCurrent(&rdev->writer_channel);
        rawLifecycleTransitionStoppingToDown(&rdev->lifecycle);
        return false;
    }

    rdev->writer_joinable = true;
    if (! rawLifecycleTransitionStartingToUp(&rdev->lifecycle))
    {
        LOGE("RawDevice: writer thread failed during startup");
        goto rollback;
    }

    LOGD("RawDevice: device %s is now up", rdev->name);
    return true;

rollback:
    rawLifecycleTransitionToStopping(&rdev->lifecycle);
    deviceWriterChannelClose(&rdev->writer_channel);

    bool rollback_ok = true;
    if (rdev->writer_joinable)
    {
        if (safeThreadJoin(rdev->write_thread))
        {
            rdev->writer_joinable = false;
            bufferpoolResetThreadOwnership(rdev->writer_buffer_pool);
        }
        else
        {
            LOGE("RawDevice: failed to join writer during startup rollback");
            rollback_ok = false;
        }
    }
    if (! rdev->writer_joinable && ! deviceWriterChannelRetireCurrent(&rdev->writer_channel))
    {
        rollback_ok = false;
    }
    if (rollback_ok)
    {
        rawLifecycleTransitionStoppingToDown(&rdev->lifecycle);
    }
    return false;
}

bool rawdeviceBringDown(raw_device_t *rdev)
{
    if (rawLifecycleLoad(&rdev->lifecycle) == kRawLifecycleDown && ! rdev->writer_joinable &&
        ! deviceWriterChannelHasCurrent(&rdev->writer_channel))
    {
        LOGE("RawDevice: device is already down");
        return true;
    }

    rawLifecycleTransitionToStopping(&rdev->lifecycle);
    deviceWriterChannelClose(&rdev->writer_channel);

    bool bring_down_ok = true;
    if (rdev->writer_joinable)
    {
        if (safeThreadJoin(rdev->write_thread))
        {
            rdev->writer_joinable = false;
            bufferpoolResetThreadOwnership(rdev->writer_buffer_pool);
        }
        else
        {
            LOGE("RawDevice: failed to join writer thread; retaining writer resources");
            bring_down_ok = false;
        }
    }
    if (! rdev->writer_joinable && ! deviceWriterChannelRetireCurrent(&rdev->writer_channel))
    {
        bring_down_ok = false;
    }

    if (bring_down_ok)
    {
        rawLifecycleTransitionStoppingToDown(&rdev->lifecycle);
        LOGD("RawDevice: device %s is now down", rdev->name);
    }

    return bring_down_ok;
}

raw_device_t *rawdeviceCreate(const char *name, uint32_t mark, void *userdata)
{

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
        perror("setsockopt IP_HDRINCL");
        terminateProgram(1);
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

    raw_device_t *rdev = memoryAllocate(sizeof(raw_device_t));

    buffer_pool_t *writer_bpool = bufferpoolCreate(GSTATE.masterpool_buffer_pools_large,
                                                   GSTATE.masterpool_buffer_pools_small,
                                                   RAM_PROFILE,
                                                   bufferpoolGetLargeBufferSize(getWorkerBufferPool(getWID())),
                                                   bufferpoolGetSmallBufferSize(getWorkerBufferPool(getWID()))

    );

    *rdev = (raw_device_t) {.name               = stringDuplicate(name),
                            .routine_writer     = rawLinuxWriteRoutine,
                            .socket             = rsocket,
                            .mark               = mark,
                            .userdata           = userdata,
                            .writer_buffer_pool = writer_bpool,
                            .writer_joinable    = false};
    atomic_init(&rdev->lifecycle, kRawLifecycleDown);
    deviceWriterChannelInit(&rdev->writer_channel);

    return rdev;
}

void rawdeviceDestroy(raw_device_t *rdev)
{

    if (rawLifecycleLoad(&rdev->lifecycle) != kRawLifecycleDown || rdev->writer_joinable ||
        deviceWriterChannelHasCurrent(&rdev->writer_channel))
    {
        if (! rawdeviceBringDown(rdev))
        {
            LOGF("RawDevice: refusing to destroy device while writer ownership remains");
            abortProgramNow(1);
        }
    }
    /*
     * Node destruction runs after all worker and lwIP producer contexts have
     * stopped, so retired queue generations can finally be reclaimed.
     */
    if (! deviceWriterChannelDestroy(&rdev->writer_channel))
    {
        LOGF("RawDevice: refusing to destroy a published writer generation");
        abortProgramNow(1);
    }
    memoryFree(rdev->name);
    bufferpoolDestroy(rdev->writer_buffer_pool);
    close(rdev->socket);
    memoryFree(rdev);
}

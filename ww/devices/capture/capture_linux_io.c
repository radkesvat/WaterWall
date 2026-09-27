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

static void capturedeviceRecordNetfilterDiscard(capture_device_t *cdev)
{
    log_rate_limiter_report_t report =
        logRateLimiterRecord(&cdev->netfilter_discard_log_limiter, kCaptureDiscardReportIntervalMs);
    if (! report.should_log)
    {
        return;
    }

    LOGW("CaptureDevice: discarded %llu truncated or oversized netfilter packet(s) over %llums (total=%llu)",
         LLU(report.events),
         LLU(report.elapsed_ms),
         LLU(report.total));
}

static void capturedeviceReportPendingNetfilterDiscards(capture_device_t *cdev)
{
    log_rate_limiter_report_t report = logRateLimiterFlush(&cdev->netfilter_discard_log_limiter);
    if (! report.should_log)
    {
        return;
    }

    LOGW("CaptureDevice: discarded %llu truncated or oversized netfilter packet(s) before reader exit (total=%llu)",
         LLU(report.events),
         LLU(report.total));
}

WTHREAD_ROUTINE(captureLinuxReadRoutine) // NOLINT
{
    capture_device_t *cdev          = userdata;
    int               reader_socket = -1;
    struct pollfd     fds[2];
    fds[1].fd     = cdev->linux_pipe_fds[0];
    fds[0].events = POLLIN;
    fds[1].events = POLLIN;

    // Readiness is published only after all non-socket polling state is built.
    // The handshake supplies the stable socket reference and the next action is
    // entering the bounded poll loop.
    if (! captureLinuxReaderPublishReady(cdev, &reader_socket))
    {
        return 0;
    }
    fds[0].fd = reader_socket;

    while (atomicLoadExplicit(&(cdev->running), memory_order_relaxed))
    {
        int ret = poll(fds, 2, kCaptureReaderPollTimeoutMs);
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
            // Bounded-timeout tick. This is the guaranteed exit path: if the wake
            // token could not be written, `running == false` is still observed
            // here, so BringDown's join cannot block forever.
            continue;
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
            getsockopt(reader_socket, SOL_SOCKET, SO_ERROR, &socket_error, &err_len);
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
                // Stop may be requested after poll() made the socket readable.
                // Observe it before every packet so one wakeup cannot multiply
                // the verdict deadline across an entire RAM_PROFILE batch.
                if (! atomicLoadExplicit(&cdev->running, memory_order_relaxed))
                {
                    break;
                }

                bool leave_drain_loop = false;
                bufs[queued_count]    = bufferpoolGetSmallBuffer(cdev->reader_buffer_pool);
                bufs[queued_count]    = sbufReserveSpace(bufs[queued_count], kNetfilterReadBufferSize);

                netfilter_packet_result_t packet_result =
                    netfilterGetPacket(cdev, reader_socket, cdev->queue_number, bufs[queued_count]);

                switch (packet_result)
                {
                case kNetfilterPacketReady:
                    // Length was set in netfilterGetPacket via sbufSetLength.
                    queued_count++;
                    break;

                case kNetfilterPacketAccepted:
                    // Capture is not active yet, or shutdown has begun. The
                    // packet was returned to the host stack with NF_ACCEPT and
                    // must never be dispatched through RawSocket.
                    bufferpoolReuseBuffer(cdev->reader_buffer_pool, bufs[queued_count]);
                    continue;

                case kNetfilterPacketDiscarded:
                    capturedeviceRecordNetfilterDiscard(cdev);
                    bufferpoolReuseBuffer(cdev->reader_buffer_pool, bufs[queued_count]);
                    continue;

                case kNetfilterPacketMalformedDiscarded:
                    LOGW("CaptureDevice: discarded a malformed netfilter message or invalid IPv4 packet after "
                         "sending NF_DROP");
                    bufferpoolReuseBuffer(cdev->reader_buffer_pool, bufs[queued_count]);
                    continue;

                case kNetfilterPacketWouldBlock:
                    bufferpoolReuseBuffer(cdev->reader_buffer_pool, bufs[queued_count]);
                    if (queued_count > 0)
                    {
                        deviceFlowAffinityPostBatch(cdev->reader_session, bufs, queued_count);
                        queued_count = 0;
                    }
                    leave_drain_loop = true;
                    break;

                case kNetfilterPacketEof:
                    bufferpoolReuseBuffer(cdev->reader_buffer_pool, bufs[queued_count]);
                    if (queued_count > 0)
                    {
                        deviceFlowAffinityPostBatch(cdev->reader_session, bufs, queued_count);
                        queued_count = 0;
                    }
                    capturedeviceReportPendingNetfilterDiscards(cdev);
                    LOGE("CaptureDevice: Exit read routine due to End Of File");
                    return 0;

                case kNetfilterPacketError:
                default: {
                    int saved_errno = errno;
                    bufferpoolReuseBuffer(cdev->reader_buffer_pool, bufs[queued_count]);
                    if (queued_count > 0)
                    {
                        deviceFlowAffinityPostBatch(cdev->reader_session, bufs, queued_count);
                        queued_count = 0;
                    }
                    LOGW("CaptureDevice: failed to read a packet from netfilter socket, errno is %d (%s)",
                         saved_errno,
                         strerror(saved_errno));
                    capturedeviceReportPendingNetfilterDiscards(cdev);
                    return 0;
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
                deviceFlowAffinityPostBatch(cdev->reader_session, bufs, queued_count);
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

// Return every packet the kernel still holds for this queue to the host stack.
//
// Removing the last iptables rule stops new packets from being enqueued, but
// anything the kernel queued just before that is still waiting for a verdict.
// The reader cannot be relied on to have taken it: its drain is bounded per
// wakeup, and the stop pipe is handled before the queue socket, so it can exit
// with the socket still readable. On the successful-cleanup path the queue
// socket is then left open, so those packets would sit unverdicted until the
// device is destroyed or brought back up.
//
// Called only after the reader thread has been joined, so this owner has
// exclusive use of the descriptor and no synchronization is needed.
// `capture_active` is already false by then, so netfilterGetPacket() issues
// NF_ACCEPT for each packet on its own.
bool capturedeviceDrainResidualQueue(capture_device_t *cdev, int socket_fd, uint64_t deadline_us)
{
    // A standalone buffer rather than one from cdev->reader_buffer_pool: that
    // pool is bound to the reader thread on first use, and this runs on the
    // lifecycle owner's thread. Nothing here is dispatched, so one buffer is
    // reused for the whole drain and released on the way out.
    sbuf_t *buf = sbufCreate(kNetfilterReadBufferSize);

    for (uint32_t drained = 0;; ++drained)
    {
        if ((uint64_t) getHRTimeUs() >= deadline_us)
        {
            errno = ETIMEDOUT;
            LOGW("CaptureDevice: residual acceptance deadline expired for queue %u after %u packet(s)",
                 cdev->queue_number,
                 drained);
            sbufDestroy(buf);
            return false;
        }
        sbufReset(buf);
        buf = sbufReserveSpace(buf, kNetfilterReadBufferSize);

        const netfilter_packet_result_t packet_result =
            netfilterGetPacketUntil(cdev, socket_fd, cdev->queue_number, buf, deadline_us);

        // The drain never dispatches: the reader session is already ended, and a
        // verdict was sent for every result except WouldBlock/Eof/Error.
        if (packet_result == kNetfilterPacketWouldBlock || packet_result == kNetfilterPacketEof)
        {
            // The queue is empty: every packet it still held has been verdicted.
            sbufDestroy(buf);
            return true;
        }

        if (packet_result == kNetfilterPacketError)
        {
            // The rules are gone and the reader is stopped, so nothing can
            // recover the remainder. Report it instead of spinning on the error.
            LOGW("CaptureDevice: stopped draining residual packets from queue %u: %s",
                 cdev->queue_number,
                 strerror(errno));
            sbufDestroy(buf);
            return false;
        }

        // Exactly one receive beyond the packet budget is allowed as the
        // emptiness probe. EAGAIN/Eof above makes a queue containing exactly
        // the budget successful; receiving another packet verdicts it before
        // failing closed and disabling the queue.
        if (drained >= (uint32_t) kNetfilterResidualPacketBudget)
        {
            errno = EOVERFLOW;
            LOGW("CaptureDevice: residual acceptance budget for queue %u ended after %u packet(s)",
                 cdev->queue_number,
                 drained + 1U);
            sbufDestroy(buf);
            return false;
        }
    }
}

#include "devices/device_flow_affinity.h"
#include "devices/device_reader_session.h"
#include "devices/tun/tun_io_error.h"
#include "devices/tun/tun_lifecycle.h"
#ifdef OS_LINUX
#include "devices/tun/tun_linux_gso_limits.h"
#include "devices/tun/tun_linux_gso_write.h"
#include "devices/tun/tun_linux_offload.h"
#endif
#include "generic_pool.h"
#include "global_state.h"
#include "ipv4_packet_view.h"
#include "loggers/internal_logger.h"
#include "loggers/log_rate_limiter.h"
#include "tun.h"
#include "tun_linux_internal.h"
#include "watomic.h"
#include "wplatform.h"
#include "wproc.h"
#include "wthread.h"
#include "wtime.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <net/if.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <poll.h>
#include <sys/ioctl.h>

#ifdef OS_LINUX
#include <linux/if.h>
#include <linux/if_tun.h>
#include <linux/ipv6.h>
#elif defined(OS_BSD)
#include <net/if.h>
#include <net/if_tun.h>
#else
#error "Unsupported OS"
#endif

#include "tun_linux_private.h"

#ifdef OS_LINUX
static_assert((unsigned) kTunWriterBatchPackets <= (unsigned) kTunWriteBatchPackets,
              "worker batch exceeds GSO record capacity");
#endif

static atomic_log_rate_limiter_t tun_write_packet_failure_log;

void tunDeliverPacket(void *device, sbuf_t *buf, wid_t wid)
{
    tun_device_t *tdev = device;
    tdev->read_event_callback(tdev, tdev->userdata, buf, wid);
}

#ifndef OS_LINUX
static atomic_log_rate_limiter_t tun_oversized_read_log;

// Hands whatever the drain cycle has already read to the reader session. Every
// exit from tunDrainPackets() goes through this, so a device error never
// strands packets that were read successfully before it.
static void tunFlushReadBatch(tun_device_t *tdev, sbuf_t **bufs, uint16_t queued_count)
{
    if (queued_count > 0)
    {
        deviceFlowAffinityPostBatchDroppingOverflow(tdev->reader_session, bufs, queued_count);
    }
}

// Drains packets from the TUN device after POLLIN. Every accumulated buffer is
// handed to the reader session before returning, on every path.
static tun_drain_result_t tunDrainPackets(tun_device_t *tdev)
{
    uint16_t queued_count = 0;
    sbuf_t  *bufs[kMaxReadDistributeQueueSize];
    const uint32_t mtu       = tunDeviceMtu(tdev);
    const uint32_t read_size = mtu + 1U;

    for (uint32_t i = 0; i < RAM_PROFILE && queued_count < kMaxReadDistributeQueueSize; ++i)
    {
        bufs[queued_count] = bufferpoolGetSmallBuffer(tdev->reader_buffer_pool);
        bufs[queued_count] = sbufReserveSpace(bufs[queued_count], read_size);

        int nread;
        for (;;)
        {
            nread = (int) read(tdev->handle, sbufGetMutablePtr(bufs[queued_count]), read_size);
            if (UNLIKELY(nread < 0 && errno == EINTR))
            {
                continue;
            }
            break;
        }

        if (UNLIKELY(nread == 0))
        {
            bufferpoolReuseBuffer(tdev->reader_buffer_pool, bufs[queued_count]);
            tunFlushReadBatch(tdev, bufs, queued_count);
            return kTunDrainEndOfStream;
        }

        if (nread < 0)
        {
            // errno is only meaningful right here: recycling the buffer and the
            // loggers below can both overwrite it.
            const int saved_errno = errno;
            bufferpoolReuseBuffer(tdev->reader_buffer_pool, bufs[queued_count]);
            tunFlushReadBatch(tdev, bufs, queued_count);

            if (tunIoErrnoIsTransient(saved_errno))
            {
                // No more packets for now; end this cycle and go back to poll().
                return kTunDrainAgain;
            }

            /*
             * Anything else (EIO, EBADF, ENODEV, ENXIO, ...) means this handle
             * will not produce packets again. Returning "keep polling" here made
             * the reader spin on a permanently readable dead fd while every
             * packet vanished, so the loss is reported instead.
             */
            LOGE("TunDevice: unrecoverable read error on device %s, errno is %d (%s)",
                 tdev->name,
                 saved_errno,
                 strerror(saved_errno));
            return kTunDrainDeviceError;
        }

        if (TUN_LOG_EVERYTHING)
        {
            LOGD("TunDevice: read %d bytes from device %s", nread, tdev->name);
        }

        sbufSetLength(bufs[queued_count], nread);

        if (UNLIKELY(sbufGetLength(bufs[queued_count]) > mtu))
        {
            if (atomicLogRateLimiterShouldLog(&tun_oversized_read_log, kTunPacketFailureLogIntervalMs))
            {
                LOGW("TunDevice: discarded oversized input on %s (%u bytes, device MTU %u)",
                     tdev->name,
                     sbufGetLength(bufs[queued_count]),
                     mtu);
            }
            bufferpoolReuseBuffer(tdev->reader_buffer_pool, bufs[queued_count]);
            continue;
        }

        queued_count++;
    }

    // Distribute all accumulated packets in one batch
    tunFlushReadBatch(tdev, bufs, queued_count);

    return kTunDrainAgain;
}

static void tunLogReaderPollError(tun_device_t *tdev, short revents)
{
    int       socket_error = 0;
    socklen_t err_len      = sizeof(socket_error);
    getsockopt(tdev->handle, SOL_SOCKET, SO_ERROR, &socket_error, &err_len);
    LOGE("TunDevice: Exit read routine due to socket error event: %s%s%s, socket error: %d (%s)",
         (revents & POLLERR) ? "POLLERR " : "",
         (revents & POLLHUP) ? "POLLHUP " : "",
         (revents & POLLNVAL) ? "POLLNVAL " : "",
         socket_error,
         strerror(socket_error));
}

// Routine to read from TUN device
WTHREAD_ROUTINE(routineReadFromTun)
{
    tun_device_t *tdev = userdata;

    struct pollfd fds[3];
    fds[0].fd         = tdev->handle;
    fds[1].fd         = tdev->linux_pipe_fds[0];
    fds[0].events     = POLLIN;
    fds[1].events     = POLLIN;
    nfds_t poll_count = 2;

    while (tunLifecycleIsActive(tunLifecycleLoad(&tdev->lifecycle)))
    {
        int ret = poll(fds, poll_count, kTunReaderStopPollMs);

        if (ret < 0)
        {
            if (errno == EINTR)
            {
                continue; // Interrupted by signal, just retry
            }
            LOGE("TunDevice: Exit read routine due to poll failed with error %d (%s)", errno, strerror(errno));
            break;
        }

        if (ret == 0)
        {
            continue;
        }

        if (fds[1].revents & POLLIN)
        {
            char    drain_byte;
            ssize_t drain_res = read(tdev->linux_pipe_fds[0], &drain_byte, 1);
            discard drain_res;
            LOGW("TunDevice: Exit read routine due to pipe event");
            break;
        }

        // Check for socket errors
        if (UNLIKELY((fds[0].revents & (POLLERR | POLLHUP | POLLNVAL)) != 0))
        {
            tunLogReaderPollError(tdev, fds[0].revents);
            break;
        }

        if (fds[0].revents & POLLIN)
        {
            tun_drain_result_t drain_res;
            drain_res = tunDrainPackets(tdev);
            if (drain_res != kTunDrainAgain)
            {
                // The device is gone. Leaving the loop is what lets the thread
                // wrapper publish FAILED and request the orderly shutdown.
                LOGE("TunDevice: Exit read routine due to %s",
                     drain_res == kTunDrainEndOfStream ? "End Of File" : "an unrecoverable device read error");
                break;
            }
            continue;
        }

        // If we get here, poll returned > 0 but none of our expected events occurred
        LOGE("TunDevice: Exit read routine due to unexpected poll events - fd[0].revents=0x%x, fd[1].revents=0x%x",
             fds[0].revents,
             fds[1].revents);
        break;
    }

    return 0;
}

#endif

/* False ends the writer. A short packet write is never replayed as a suffix. */
static bool tunWriteResult(tun_device_t *tdev, ssize_t written, size_t expected, int write_errno)
{
    if (written > 0)
    {
        if (UNLIKELY((size_t) written != expected) &&
            atomicLogRateLimiterShouldLog(&tun_write_packet_failure_log, kTunPacketFailureLogIntervalMs))
        {
            LOGW("TunDevice: discarded a packet after a short device write (%zd of %zu bytes)", written, expected);
        }
        return true;
    }
    if (UNLIKELY(written == 0))
    {
        LOGW("TunDevice: Exit write routine due to End Of File");
        return false;
    }
    if (tunIoErrnoIsTransient(write_errno) || tunWriteErrnoIsPacketLocal(write_errno))
    {
        if (atomicLogRateLimiterShouldLog(&tun_write_packet_failure_log, kTunPacketFailureLogIntervalMs))
        {
            LOGW("TunDevice: discarded a packet, writing to device %s failed with errno %d (%s)",
                 tdev->name,
                 write_errno,
                 strerror(write_errno));
        }
        return true;
    }
    if (write_errno == EMSGSIZE)
    {
        LOGF("TunDevice: This is related to the MTU size, please set a correct value for TunDevice 'device-mtu'");
    }
    LOGE("TunDevice: Exit write routine due to an unrecoverable write error on device %s, errno %d (%s)",
         tdev->name,
         write_errno,
         strerror(write_errno));
    return false;
}

/* Consumes exactly this packet, including validation refusal and device failure. */
static bool tunWriteOrdinary(tun_device_t *tdev, buffer_pool_t *pool, sbuf_t *buf, int fd)
{
    if (UNLIKELY(tunDeviceMtu(tdev) < sbufGetLength(buf)))
    {
        if (atomicLogRateLimiterShouldLog(&tun_write_packet_failure_log, kTunPacketFailureLogIntervalMs))
        {
            LOGW("TunDevice: discarded a packet -> size %d exceeds device MTU %u",
                 sbufGetLength(buf),
                 tunDeviceMtu(tdev));
        }
        bufferpoolReuseBuffer(pool, buf);
        return true;
    }
    const size_t packet_length   = sbufGetLength(buf);
    const size_t expected_length = packet_length + (tdev->checksum_offload_enabled ? kTunVirtioHeaderSize : 0U);
    ssize_t      written;
    if (tdev->checksum_offload_enabled)
    {
        uint8_t metadata[kTunVirtioHeaderSize] = {0};
#ifdef OS_LINUX
        if (tdev->trusted_checksums &&
            ! tunLinuxOffloadEncodeWrite(sbufGetMutablePtr(buf), (uint32_t) packet_length, metadata))
        {
            bufferpoolReuseBuffer(pool, buf);
            return true;
        }
#endif
        struct iovec iov[2] = {
            {.iov_base = metadata, .iov_len = sizeof(metadata)},
            {.iov_base = (void *) sbufGetRawPtr(buf), .iov_len = packet_length},
        };
        do
        {
            written = writev(fd, iov, 2);
        } while (written < 0 && errno == EINTR && tunLifecycleIsActive(tunLifecycleLoad(&tdev->lifecycle)));
    }
    else
    {
        written = write(fd, sbufGetRawPtr(buf), packet_length);
    }
    const int write_errno = written < 0 ? errno : 0;
    bufferpoolReuseBuffer(pool, buf);
    return tunWriteResult(tdev, written, expected_length, write_errno);
}

/* A worker owns each batch and all its buffers until this callback returns.
 * The writer generation gate keeps the native handle and device state alive;
 * different workers can write concurrently without sharing their local pools. */
bool tunWriteBatch(void *context, worker_t *worker, sbuf_t **batch, size_t count)
{
    tun_device_t  *tdev = context;
    buffer_pool_t *pool = worker->buffer_pool;
#ifdef OS_LINUX
    const int fd = tdev->queue_fds[worker->wid % tdev->queue_count];
#else
    const int fd = tdev->handle;
#endif
    size_t offset       = 0;
    bool   keep_running = true;
    while (offset < count && tunLifecycleIsActive(tunLifecycleLoad(&tdev->lifecycle)))
    {
#ifdef OS_LINUX
        tun_linux_gso_write_t record;
        const bool            coalesce =
            tdev->gso_enabled && tdev->trusted_checksums && ! atomicLoadRelaxed(&tdev->gso_write_disabled);
        const unsigned members =
            coalesce ? tunLinuxGsoBuildWrite(batch + offset, (unsigned) (count - offset), tunDeviceMtu(tdev), &record)
                     : 1;
        if (members > 1)
        {
            ssize_t written;
            do
            {
                written = writev(fd, record.iov, (int) record.count);
            } while (written < 0 && errno == EINTR && tunLifecycleIsActive(tunLifecycleLoad(&tdev->lifecycle)));
            const int write_errno = written < 0 ? errno : 0;
            /* EINVAL rejects virtio metadata before packet injection. Only this
             * definitive refusal can replay the unchanged originals. A short,
             * zero or ambiguous write must never duplicate a packet. */
            if (written < 0 && write_errno == EINVAL)
            {
                if (! atomicExchangeExplicit(&tdev->gso_write_disabled, true, memory_order_relaxed))
                    LOGW("TunDevice: %s rejected TCP GSO output; using ordinary packet writes", tdev->name);
                continue;
            }
            for (unsigned i = 0; i < members; ++i)
                bufferpoolReuseBuffer(pool, batch[offset++]);
            keep_running = tunWriteResult(tdev, written, record.length, write_errno);
        }
        else
#endif
        {
            keep_running = tunWriteOrdinary(tdev, pool, batch[offset++], fd);
        }
        if (! keep_running)
            break;
    }
    while (offset < count)
        bufferpoolReuseBuffer(pool, batch[offset++]);
    if (! keep_running)
    {
        tun_lifecycle_state_t failed_from;
        if (tunLifecycleTransitionToFailed(&tdev->lifecycle, &failed_from))
        {
            /* The helper publishes shutdown only after leaving its I/O gate.
             * Startup failures remain owned by BringUp's synchronous rollback. */
            return failed_from != kTunLifecycleUp;
        }
    }
    return true;
}

/* Failure-only TLS sampler. Full is ordinary bounded overload and deliberately
 * silent; Down/Closed keep sparse lifecycle evidence without a shared limiter. */
static bool tundeviceShouldLogRefusal(void)
{
    static thread_local uint32_t refusal_count;
    const uint32_t               ordinal = ++refusal_count;

    return ordinal == 1 || (ordinal & (ordinal - 1U)) == 0;
}

// Write to TUN device
bool tundeviceWrite(tun_device_t *tdev, sbuf_t *buf)
{
#if ! defined(OS_BSD)
    assert(sbufGetLength(buf) >= sizeof(struct iphdr));
#endif

    switch (tunWriterTrySend(&tdev->writer, buf))
    {
    case kTunWriterSendOk:
        return true;
    case kTunWriterSendDown:
        if (tundeviceShouldLogRefusal())
        {
            LOGE("TunDevice: write failed, device is down");
        }
        return false;
    case kTunWriterSendClosed:
        if (tundeviceShouldLogRefusal())
        {
            LOGE("TunDevice: write failed, channel was closed");
        }
        return false;
    case kTunWriterSendFull:
        return false;
    }

    return false;
}

#ifndef OS_LINUX
void tundeviceWorkerQuiesce(tun_device_t *tdev, uint8_t wid)
{
    discard tdev;
    discard wid;
}
#endif

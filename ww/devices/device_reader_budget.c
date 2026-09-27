#include "devices/device_reader_budget.h"
#include "devices/device_reader_dispatch.h"
#include "devices/device_reader_private.h"
#include "global_state.h"
#include "loggers/internal_logger.h"

#ifdef OS_LINUX
#include <poll.h>
#include <sys/eventfd.h>
#include <unistd.h>
#endif

enum
{
    kDeviceReaderCapacityPollMs = 100
};

void deviceReaderSessionSignalOutputCapacity(device_reader_session_t *session)
{
#ifdef OS_LINUX
    if (session->output_wake_fd >= 0 && atomic_exchange_explicit(&session->output_waiting, false, memory_order_acq_rel))
    {
        const uint64_t one = 1;
        for (;;)
        {
            const ssize_t written = write(session->output_wake_fd, &one, sizeof(one));
            if (written == (ssize_t) sizeof(one) || (written < 0 && errno == EAGAIN))
            {
                return;
            }
            if (written < 0 && errno == EINTR)
            {
                continue;
            }
            LOGF("DeviceReaderSession: failed to signal output capacity: %s", strerror(errno));
            abortProgramNow(1);
        }
    }
#else
    discard session;
#endif
}

void deviceReaderSessionReleaseWork(device_reader_session_t *session, size_t exact_charge, unsigned int packets)
{
    assert(session != NULL);
    assert(exact_charge > 0);
    assert(packets > 0);
    const size_t previous_charge =
        atomic_fetch_sub_explicit(&session->output_charge, exact_charge, memory_order_acq_rel);
    const unsigned int previous_count =
        atomic_fetch_sub_explicit(&session->output_packets, packets, memory_order_acq_rel);
    if (UNLIKELY(previous_charge < exact_charge || previous_count < packets))
    {
        LOGF("DeviceReaderSession: output-budget reservation underflow");
        abortProgramNow(1);
    }
    deviceReaderSessionSignalOutputCapacity(session);
}

void deviceReaderSessionReleaseOutput(device_reader_session_t *session, size_t exact_charge)
{
    deviceReaderSessionReleaseWork(session, exact_charge, 1);
}

bool deviceReaderSessionConfigureOutputBudget(device_reader_session_t *session, size_t max_charge, uint32_t max_packets)
{
    assert(session != NULL);
    assert(max_charge > 0 && max_packets > 0);
    assert(session->output_wake_fd < 0);
    assert(atomic_load_explicit(&session->generation, memory_order_relaxed) == 0);
#ifdef OS_LINUX
    const int fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (fd < 0)
    {
        return false;
    }
    session->output_charge_limit = max_charge;
    session->output_packet_limit = max_packets;
    session->output_wake_fd      = fd;
    return true;
#else
    discard session;
    discard max_charge;
    discard max_packets;
    return false;
#endif
}

bool deviceReaderSessionTryReserveWork(device_reader_session_t *session, size_t exact_charge, unsigned int packets)
{
    assert(session != NULL);
    assert(session->output_wake_fd >= 0);
    assert(exact_charge > 0 && exact_charge <= session->output_charge_limit);
    assert(packets > 0 && packets <= session->output_packet_limit);
    if (UNLIKELY(! atomic_load_explicit(&session->producer_admission, memory_order_acquire)))
    {
        return false;
    }

    /* Publish the waiter before observing credits; a foreign-thread release
     * between this point and a failed reservation must leave a wake event.
     * The exchange's acquire half observes a release that completed just
     * before it, so stale credit loads cannot strand an unnotified waiter. */
    discard atomic_exchange_explicit(&session->output_waiting, true, memory_order_acq_rel);

    w_atomic_uint_value_t count = atomic_load_explicit(&session->output_packets, memory_order_relaxed);
    for (;;)
    {
        if (packets > session->output_packet_limit - count)
        {
            return false;
        }
        if (atomic_compare_exchange_weak_explicit(
                &session->output_packets, &count, count + packets, memory_order_acq_rel, memory_order_relaxed))
        {
            break;
        }
    }

    /* The Windows fallback's atomic_size_t stores intptr_t; its CAS expected
     * pointer must match that type as well as its width. C11 uses size_t. */
#if WW_HAVE_C11_ATOMICS
    size_t charge = atomic_load_explicit(&session->output_charge, memory_order_relaxed);
#else
    w_atomic_uint_value_t charge = atomic_load_explicit(&session->output_charge, memory_order_relaxed);
#endif
    for (;;)
    {
        if (exact_charge > session->output_charge_limit - charge)
        {
            const unsigned int previous =
                atomic_fetch_sub_explicit(&session->output_packets, packets, memory_order_acq_rel);
            if (UNLIKELY(previous < packets))
            {
                LOGF("DeviceReaderSession: output-budget packet reservation underflow");
                abortProgramNow(1);
            }
            return false;
        }
        if (atomic_compare_exchange_weak_explicit(
                &session->output_charge, &charge, charge + exact_charge, memory_order_acq_rel, memory_order_relaxed))
        {
            atomic_store_explicit(&session->output_waiting, false, memory_order_release);
            return true;
        }
    }
}

bool deviceReaderSessionTryReserveOutput(device_reader_session_t *session, size_t exact_charge)
{
    return deviceReaderSessionTryReserveWork(session, exact_charge, 1);
}

int deviceReaderSessionOutputWakeFd(const device_reader_session_t *session)
{
    assert(session != NULL);
    return session->output_wake_fd;
}

void deviceReaderSessionDrainOutputWake(device_reader_session_t *session)
{
    assert(session != NULL);
#ifdef OS_LINUX
    if (session->output_wake_fd < 0)
    {
        return;
    }
    uint64_t count;
    for (;;)
    {
        const ssize_t nread = read(session->output_wake_fd, &count, sizeof(count));
        if (nread == (ssize_t) sizeof(count))
        {
            continue;
        }
        if (nread < 0 && errno == EINTR)
        {
            continue;
        }
        if (nread < 0 && errno == EAGAIN)
        {
            return;
        }
        LOGF("DeviceReaderSession: failed to drain output-capacity notification: %s", strerror(errno));
        abortProgramNow(1);
    }
#else
    discard session;
#endif
}

bool deviceReaderSessionWaitReserveWork(device_reader_session_t *session, size_t charge, unsigned int packets,
                                        uint32_t generation)
{
    for (;;)
    {
        if (! atomicLoadExplicit(&session->producer_admission, memory_order_acquire) ||
            ! deviceReaderSessionMatchesGeneration(session, generation))
        {
            return false;
        }
        if (deviceReaderSessionTryReserveWork(session, charge, packets))
        {
            return true;
        }
#ifdef OS_LINUX
        struct pollfd fd     = {.fd = session->output_wake_fd, .events = POLLIN};
        const int     result = poll(&fd, 1, kDeviceReaderCapacityPollMs);
        if (result > 0)
        {
            if (UNLIKELY((fd.revents & (POLLERR | POLLHUP | POLLNVAL)) != 0))
            {
                LOGF("DeviceReaderSession: invalid output-capacity notification descriptor");
                abortProgramNow(1);
            }
            deviceReaderSessionDrainOutputWake(session);
        }
        else if (result < 0 && errno != EINTR)
        {
            LOGE("DeviceReaderSession: output-capacity wait failed: %s", strerror(errno));
            return false;
        }
#else
        return false;
#endif
    }
}

void deviceReaderBudgetDestroy(device_reader_session_t *session)
{
    discard session;
#ifdef OS_LINUX
    if (session->output_wake_fd >= 0)
    {
        close(session->output_wake_fd);
    }
#endif
}

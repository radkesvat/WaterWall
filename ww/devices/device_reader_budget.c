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
    if (! atomic_exchange_explicit(&session->output_waiting, false, memory_order_acq_rel))
    {
        return;
    }
    if (session->capacity_notify != NULL)
    {
        if (quiescenceGateEnter(&session->capacity_notify_gate))
        {
            session->capacity_notify(session->capacity_notify_context);
            quiescenceGateLeave(&session->capacity_notify_gate);
        }
        return;
    }
#ifdef OS_LINUX
    if (session->output_wake_fd >= 0)
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
    mutexLock(&session->output_budget_lock);
    const size_t previous_charge =
        atomic_fetch_sub_explicit(&session->output_charge, exact_charge, memory_order_acq_rel);
    const unsigned int previous_count =
        atomic_fetch_sub_explicit(&session->output_packets, packets, memory_order_acq_rel);
    if (UNLIKELY(previous_charge < exact_charge || previous_count < packets))
    {
        LOGF("DeviceReaderSession: output-budget reservation underflow");
        abortProgramNow(1);
    }
    mutexUnlock(&session->output_budget_lock);
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
    assert(session->output_charge_limit == 0);
    assert(atomic_load_explicit(&session->generation, memory_order_relaxed) == 0);
    if (! mutexTryInit(&session->output_budget_lock))
    {
        return false;
    }
#ifdef OS_LINUX
    const int fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (fd < 0)
    {
        mutexDestroy(&session->output_budget_lock);
        return false;
    }
    session->output_wake_fd = fd;
#endif
    session->output_charge_limit = max_charge;
    session->output_packet_limit = max_packets;
    return true;
}

void deviceReaderSessionConfigureCapacityNotify(device_reader_session_t *session, DeviceReaderCapacityNotifyFn notify,
                                                void *context)
{
    assert(session != NULL && notify != NULL);
    assert(session->output_charge_limit != 0);
    assert(atomic_load_explicit(&session->generation, memory_order_relaxed) == 0);
    assert(session->capacity_notify == NULL);
    session->capacity_notify         = notify;
    session->capacity_notify_context = context;
}

bool deviceReaderSessionTryReserveWork(device_reader_session_t *session, size_t exact_charge, unsigned int packets)
{
    assert(session != NULL);
    assert(session->output_charge_limit != 0);
    assert(exact_charge > 0 && exact_charge <= session->output_charge_limit);
    assert(packets > 0 && packets <= session->output_packet_limit);
    if (UNLIKELY(! atomic_load_explicit(&session->producer_admission, memory_order_acquire)))
    {
        return false;
    }

    /* Admit both dimensions together. A temporary partial reservation could
     * otherwise make a peer sleep even though no accepted work can wake it.
     * Publish refusal while holding the same short lock used by settlement. */
    mutexLock(&session->output_budget_lock);
    const size_t       charge = atomic_load_explicit(&session->output_charge, memory_order_relaxed);
    const unsigned int count  = atomic_load_explicit(&session->output_packets, memory_order_relaxed);
    if (packets > session->output_packet_limit - count || exact_charge > session->output_charge_limit - charge)
    {
        atomic_store_explicit(&session->output_waiting, true, memory_order_release);
        mutexUnlock(&session->output_budget_lock);
        return false;
    }
    atomic_store_explicit(&session->output_charge, charge + exact_charge, memory_order_relaxed);
    atomic_store_explicit(&session->output_packets, count + packets, memory_order_relaxed);
    /* A successful producer must not clear another producer's waiter. */
    mutexUnlock(&session->output_budget_lock);
    return true;
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
    assert(session->capacity_notify == NULL);
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
    if (session->output_charge_limit != 0)
    {
        mutexDestroy(&session->output_budget_lock);
    }
#ifdef OS_LINUX
    if (session->output_wake_fd >= 0)
    {
        close(session->output_wake_fd);
    }
#endif
}

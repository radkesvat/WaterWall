#pragma once

/* Backend-private state. The lifecycle coordinator owns handles, the reader
 * thread, its pool and reader-session owner reference. Reader I/O borrows them
 * until joined; worker writes borrow them through the writer generation gate. Queued offload work owns its input and
 * session credits independently. */
#include "devices/device_reader_session.h"
#include "devices/tun/tun_lifecycle.h"
#include "devices/tun/tun_writer.h"
#include "tun.h"
#include "wthread.h"

enum
{
    kMaxReadDistributeQueueSize    = 512,
    kTunReaderStopPollMs           = 100,
    kTunPacketFailureLogIntervalMs = 5000,
    kTunCommandTimeoutMs           = 7000,
    kTunCommandTerminateGraceMs    = 250,
    kTunCommandMaxOutputBytes      = 64 * 1024,
#ifdef OS_LINUX
    kTunOffloadPacketStorageCapacity = 65536,
    kTunOffloadPendingPacketLimit    = 512,
    kTunOffloadPendingChargeLimit    = 8 * 1024 * 1024,
    kTunOffloadLogIntervalMs         = 5000,
#endif
    kLinuxRouteFlagUp      = 0x1,
    kLinuxRouteFlagGateway = 0x2
};

static_assert(kMaxReadDistributeQueueSize <= UINT16_MAX, "TUN read batch count must fit in the reader session");

struct tun_device_s
{
    char *name;
    int   handle;
    int   linux_pipe_fds[2]; // used for signaling read thread to stop

    void     *userdata;
    wthread_t read_thread;

    wthread_routine routine_reader;

    device_reader_session_t *reader_session;
    buffer_pool_t           *reader_buffer_pool;

    TunReadEventHandle read_event_callback;

    tun_writer_t writer;
    uint16_t     mtu;
    bool         checksum_offload_enabled;
    bool         gso_enabled;
#ifdef OS_LINUX
    bool        trusted_checksums;
    atomic_bool gso_write_disabled;
    /* Allocated before publication so unavailable offload storage can fall back. */
    sbuf_t *offload_scratch;
    /* Output allowance and this chain's padding, captured before publication. */
    size_t               gso_output_charge[UINT8_MAX + 1U];
    uint16_t             offload_output_padding[UINT8_MAX + 1U];
    atomic_uint_fast64_t gso_generated_segments;
    atomic_uint_fast64_t gso_intact_aggregates;
#endif

    atomic_int lifecycle;

    // Whether read_thread holds a started, unjoined thread. This
    // -- not `up` -- decides what bring-down must join, so a device whose thread
    // already exited on its own is still torn down completely. Owner-thread only.
    bool reader_joinable;
    bool reader_generation_open;
    // The most recent configuration mutation may have completed before its
    // supervisor lost control. The immediate policy caller consumes this flag.
    bool command_outcome_unknown;
    bool dns_outcome_unknown;
    bool dns_cleanup_needed;
#ifdef OS_LINUX
    bool                       interface_preexisting;
    struct tun_dns_snapshot_s *dns_snapshot;
#endif
};

static inline uint16_t tunDeviceMtu(const tun_device_t *tdev)
{
    return tdev->mtu;
}

bool tunSetMtuByName(const char *name, uint16_t mtu);
bool tunSetStateByName(const char *name, bool up);
void tunDeliverPacket(void *device, sbuf_t *buf, wid_t wid);
WTHREAD_ROUTINE(routineReadFromTun);
bool tunWriteBatch(void *context, worker_t *worker, sbuf_t **buffers, size_t count);
#ifdef OS_LINUX
bool tunConfigureWorkerOffload(tun_device_t *tdev);
bool tunConfigureWorkerGso(tun_device_t *tdev);
/* Final destruction releases snapshot storage after the policy owner attempts cleanup. */
void tunLinuxDnsDropSnapshot(tun_device_t *tdev);
#endif

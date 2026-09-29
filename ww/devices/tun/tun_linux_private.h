#pragma once

/* Backend-private state. The lifecycle coordinator owns handles, joinable
 * threads, pools and the reader-session owner reference. I/O borrows them until
 * joined. Queued GSO work owns its aggregate and session credits independently. */
#include "devices/device_reader_session.h"
#include "devices/device_writer_channel.h"
#include "devices/tun/tun_lifecycle.h"
#include "tun.h"
#include "wthread.h"

enum
{
    kTunWriteChannelQueueMax       = 128 * 1024,
    kMaxReadDistributeQueueSize    = 512,
    kTunReaderStopPollMs           = 100,
    kTunPacketFailureLogIntervalMs = 5000,
    kTunCommandTimeoutMs           = 7000,
    kTunCommandTerminateGraceMs    = 250,
    kTunCommandMaxOutputBytes      = 64 * 1024,
#ifdef OS_LINUX
    kTunGsoPacketStorageCapacity = 65536,
    kTunGsoPendingPacketLimit    = 512,
    kTunGsoPendingChargeLimit    = 8 * 1024 * 1024,
    kTunGsoLogIntervalMs         = 5000,
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
    wthread_t write_thread;

    wthread_routine routine_reader;
    wthread_routine routine_writer;

    device_reader_session_t *reader_session;
    buffer_pool_t           *reader_buffer_pool;
    buffer_pool_t           *writer_buffer_pool;

    TunReadEventHandle read_event_callback;

    device_writer_channel_t writer_channel;
    uint16_t                mtu;
    bool                    gso_enabled;
#ifdef OS_LINUX
    bool trusted_checksums;
    /* Allocated before publication so unavailable GSO storage can fall back. */
    sbuf_t *gso_scratch;
    /* Output allowance and this chain's padding, captured before publication. */
    size_t               gso_output_charge[UINT8_MAX + 1U];
    uint16_t             gso_output_padding[UINT8_MAX + 1U];
    atomic_uint_fast64_t gso_generated_segments;
    atomic_uint_fast64_t gso_intact_aggregates;
#endif

    atomic_int lifecycle;

    // Whether read_thread / write_thread hold a started, unjoined thread. These
    // -- not `up` -- decide what bring-down must join, so a device whose thread
    // already exited on its own is still torn down completely. Owner-thread only.
    bool reader_joinable;
    bool writer_joinable;
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
WTHREAD_ROUTINE(routineWriteToTun);
#ifdef OS_LINUX
bool tunConfigureWorkerGso(tun_device_t *tdev);
/* Final destruction releases snapshot storage after the policy owner attempts cleanup. */
void tunLinuxDnsDropSnapshot(tun_device_t *tdev);
#endif

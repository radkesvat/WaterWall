#pragma once

#include <errno.h>
#include <stdbool.h>

/*
 * Shared POSIX device-I/O error policy for the TUN reader and writer threads.
 *
 * These routines run on their own threads and are the only readers/writers of
 * the device handle. When one of them returns, tundeviceNoteUnexpectedThreadExit()
 * publishes FAILED and hands the shutdown decision to worker 0. That only works
 * if a routine actually returns on a device that is gone: an error the routine
 * swallows with `continue` keeps a dead device advertised as usable while every
 * packet is silently discarded, which is strictly worse than exiting, because a
 * supervisor can restart a process that exits but cannot notice one that spins.
 *
 * So the policy is a whitelist: retry only what is known to be recoverable,
 * drop only what is known to be a property of one packet, and treat everything
 * else as the device being lost.
 */

/*
 * Errors that say "not right now" rather than "this device is broken".
 *
 * EINTR/EAGAIN/EWOULDBLOCK are the ordinary non-blocking and signal cases.
 * ENOBUFS/ENOMEM are transient kernel allocation pressure; a burst of traffic
 * must not be able to turn a temporary allocation failure into a process exit.
 */
static inline bool tunIoErrnoIsTransient(int io_errno)
{
    switch (io_errno)
    {
    case EINTR:
    case EAGAIN:
#if defined(EWOULDBLOCK) && EWOULDBLOCK != EAGAIN
    case EWOULDBLOCK:
#endif
    case ENOBUFS:
    case ENOMEM:
        return true;
    default:
        return false;
    }
}

/*
 * Write errors that condemn one packet rather than the device.
 *
 * The kernel TUN driver rejects a malformed frame with EINVAL - a payload too
 * short to hold an IP header, or an unrecognised IP version. Packets reaching
 * the writer come from remote peers, so this is reachable with attacker-chosen
 * bytes and must stay a per-packet drop: making it fatal would hand any peer a
 * one-packet process kill.
 *
 * EMSGSIZE is deliberately NOT in this set. The writer already drops anything
 * larger than the configured MTU before calling write(), so EMSGSIZE means the
 * configured MTU exceeds the device's real MTU - an operator misconfiguration
 * that will reject traffic forever, not a property of one packet.
 */
static inline bool tunWriteErrnoIsPacketLocal(int io_errno)
{
    return io_errno == EINVAL;
}

// Outcome of one read-drain cycle, so the reader loop cannot silently ignore a
// device error the way an "int" return did.
typedef enum tun_drain_result_e
{
    kTunDrainAgain = 0,   // Nothing more to read for now; keep polling.
    kTunDrainEndOfStream, // The device reported end of stream.
    kTunDrainDeviceError  // Unrecoverable; the reader must leave its loop.
} tun_drain_result_t;

#pragma once

#include "wlibc.h"

/*
 * TUN loop-guard
 * --------------
 * When a TunDevice installs itself as the system's default route (full-route /
 * system-route mode), every outbound packet of the machine is steered into the
 * TUN -- including Waterwall's *own* upstream sockets (TcpConnector /
 * UdpConnector, possibly living in a different chain). Those packets would then
 * be read back from the TUN and re-sent by Waterwall, forming a routing loop.
 *
 * The loop-guard prevents this without any manual endpoint configuration:
 *  - it snapshots the original default gateway/interface (before the TUN routes
 *    are installed),
 *  - it watches this process's own network flows (via WinDivert's FLOW layer on
 *    Windows),
 *  - for each endpoint that would otherwise be routed into the TUN it installs a
 *    host (/32 or /128) bypass route via the original gateway, and removes it
 *    again when the flow closes or expires.
 *
 * The interface is cross-platform; only Windows currently has an implementation.
 * On every other platform (and on Windows builds without WinDivert) the functions
 * are no-ops so callers need no #ifdefs.
 */

typedef struct tun_loopguard_s tun_loopguard_t;

/**
 * @brief Start protecting this process's own traffic from the TUN.
 *
 * Must be called *after* the TUN device exists but *before* the TUN system
 * routes are installed, so the original default gateway can be captured.
 *
 * @param tun_luid_value The TUN interface LUID value (NET_LUID.Value on Windows).
 *                       0 if unknown; the guard then cannot distinguish TUN-bound
 *                       endpoints and stays inactive.
 * @return A guard handle, or NULL on unsupported platforms / on failure (treated
 *         by callers as "no protection", which is non-fatal).
 */
tun_loopguard_t *tunLoopGuardStart(uint64_t tun_luid_value);

/**
 * @brief Stop the guard and remove every bypass route it installed.
 * @param guard Handle returned by tunLoopGuardStart() (NULL is accepted).
 */
void tunLoopGuardStop(tun_loopguard_t *guard);

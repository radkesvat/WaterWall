#pragma once
#include "wwapi.h"

WW_EXPORT node_t nodeUserControllerGet(void);

/**
 * @brief Bring an already-open line under per-user limit enforcement, on demand.
 *
 * This performs the same admission the UserController normally does at upstream
 * `Init` (check connection/IP/traffic/expiry/enabled limits, reserve a connection
 * + IP slot, and start sweep-tracking the line), but at an arbitrary later point.
 *
 * It exists for nodes that authenticate a user *after* the line first traversed
 * the UserController, so enforcement could not happen at line start. The line
 * passes through unmanaged at first; once the node resolves the peer to a user it
 * records it with `lineAddUser()` and calls this function to apply the limits.
 *
 * The canonical case is a `WireGuardDevice` doing database-backed peer auth. Its
 * next side is packet lines (one per worker), so it cannot place a UserController
 * after itself the way `Socks5Server`/`TrojanServer` do; instead it inserts the
 * UserController on its prev side and promotes the per-peer line here:
 *
 *     UdpStatelessSocket -> UserController -> WireGuardDevice -> TunDevice
 *
 * Behavior (mirrors upstream `Init`):
 *   - line already managed                -> kUserAdmissionOk (idempotent; no second reservation)
 *   - line carries no valid user handle   -> kUserAdmissionOk (left as an unmanaged passthrough)
 *   - admitted                            -> line becomes managed + sweep-tracked, returns kUserAdmissionOk
 *   - rejected (disabled/expired/limited) -> the matching kUserAdmission* code; line stays UNMANAGED
 *
 * On any non-OK result the line is left untouched and unmanaged: this function
 * never sends a finish and never destroys line state. The caller owns the
 * rejection and must close/drop the line itself; it must not treat a non-OK line
 * as admitted. A non-OK call reserves nothing, so it is safe to retry later.
 *
 * Must be called on the line's owner worker (`lineGetWID(l) == getWID()`), and
 * only on a line that has traversed this UserController instance (so its
 * UserController line state already exists). Do not call it on packet lines.
 *
 * @param t UserController tunnel instance (the caller keeps this from creation).
 * @param l Line to promote.
 * @return user_admission_result_t admission outcome.
 */
WW_EXPORT user_admission_result_t usercontrollerTunnelTryManageLine(tunnel_t *t, line_t *l);

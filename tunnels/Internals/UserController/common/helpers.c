#include "structure.h"

#include "loggers/network_logger.h"

void usercontrollerTunnelstateDestroy(usercontroller_tstate_t *ts)
{
    // auth_client_node / auth_client_tunnel are borrowed references owned by the node manager.
    if (ts->worker_states != NULL)
    {
        for (wid_t wid = 0; wid < ts->worker_count; ++wid)
        {
            memoryFree(ts->worker_states[wid].lines);
        }
        memoryFree(ts->worker_states);
    }
    memoryZeroAligned32(ts, tunnelGetCorrectAlignedStateSize(sizeof(*ts)));
}

const char *usercontrollerAdmissionReason(user_admission_result_t result)
{
    switch (result)
    {
    case kUserAdmissionOk:
        return "ok";
    case kUserAdmissionDisabled:
        return "user disabled";
    case kUserAdmissionExpired:
        return "user expired";
    case kUserAdmissionTrafficLimited:
        return "traffic quota reached";
    case kUserAdmissionConnectionLimited:
        return "connection limit reached";
    case kUserAdmissionIpLimited:
        return "ip limit reached";
    case kUserAdmissionInvalid:
    default:
        return "user unavailable";
    }
}

static void usercontrollerLogUserContext(tunnel_t *t, line_t *l, const usercontroller_lstate_t *ls,
                                         const char *action, const char *reason)
{
    usercontroller_tstate_t *ts = tunnelGetState(t);

    if (! ts->verbose || ls == NULL)
    {
        LOGW("UserController: %s: %s", action, reason != NULL ? reason : "unknown");
        return;
    }

    if (! userHandleIsValid(&ls->handle))
    {
        LOGW("UserController: %s on worker %u: %s (invalid user handle: user-id=%" PRIu64 ", generation=%" PRIu64
             ", ip-key-type=%u)",
             action,
             l != NULL ? (unsigned int) lineGetWID(l) : (unsigned int) getWID(),
             reason != NULL ? reason : "unknown",
             ls->handle.user_id,
             ls->handle.generation,
             (unsigned int) ls->ip_key.type);
        return;
    }

    LOGW("UserController: %s on worker %u: %s (user-id=%" PRIu64 ", generation=%" PRIu64 ", ip-key-type=%u)",
         action,
         l != NULL ? (unsigned int) lineGetWID(l) : (unsigned int) getWID(),
         reason != NULL ? reason : "unknown",
         ls->handle.user_id,
         ls->handle.generation,
         (unsigned int) ls->ip_key.type);
}

void usercontrollerLogAdmissionRejected(tunnel_t *t, line_t *l, const usercontroller_lstate_t *ls,
                                        user_admission_result_t result)
{
    usercontrollerLogUserContext(t, l, ls, "rejected new connection", usercontrollerAdmissionReason(result));
}

void usercontrollerLogActiveClose(tunnel_t *t, line_t *l, const usercontroller_lstate_t *ls, const char *reason)
{
    usercontrollerLogUserContext(t, l, ls, "closing active connection", reason);
}

uint64_t usercontrollerLocalTimeMS(void)
{
    return getHRTimeUs() / 1000ULL;
}

// Convert the connecting peer's IP into the lwIP-independent key the user object uses for IP-count
// limits. Returns false (and leaves *out as a "no IP" key) when the line has no usable source IP.
bool usercontrollerBuildIpKey(line_t *l, user_ip_key_t *out)
{
    memoryZero(out, sizeof(*out));

    const address_context_t *src = lineGetSourceAddressContext(l);
    if (! addresscontextIsIp(src))
    {
        return false;
    }

    const ip_addr_t *ip = &src->ip_address;
    if (ip->type == IPADDR_TYPE_V4)
    {
        out->type = 4;
        memoryCopy(out->bytes, &ip->u_addr.ip4.addr, sizeof(ip->u_addr.ip4.addr));
    }
    else
    {
        out->type = 6;
        memoryCopy(out->bytes, ip->u_addr.ip6.addr, sizeof(ip->u_addr.ip6.addr));
    }
    return true;
}

static usercontroller_worker_state_t *usercontrollerGetWorkerState(tunnel_t *t, wid_t wid)
{
    usercontroller_tstate_t *ts = tunnelGetState(t);
    if (UNLIKELY(ts->worker_states == NULL || wid >= ts->worker_count))
    {
        return NULL;
    }

    return &ts->worker_states[wid];
}

static bool usercontrollerWorkerReserveLine(usercontroller_worker_state_t *ws)
{
    if (ws->line_count < ws->line_capacity)
    {
        return true;
    }

    size_t new_capacity = ws->line_capacity == 0 ? 16 : ws->line_capacity * 2U;
    if (UNLIKELY(new_capacity < ws->line_capacity || new_capacity > SIZE_MAX / sizeof(*ws->lines)))
    {
        return false;
    }

    line_t **new_lines = memoryReAllocate(ws->lines, new_capacity * sizeof(*new_lines));
    if (UNLIKELY(new_lines == NULL))
    {
        return false;
    }

    memoryZero(new_lines + ws->line_capacity, (new_capacity - ws->line_capacity) * sizeof(*new_lines));
    ws->lines         = new_lines;
    ws->line_capacity = new_capacity;
    return true;
}

bool usercontrollerRegisterLine(tunnel_t *t, line_t *l, usercontroller_lstate_t *ls)
{
    if (ls->registered)
    {
        return true;
    }

    usercontroller_worker_state_t *ws = usercontrollerGetWorkerState(t, lineGetWID(l));
    if (UNLIKELY(ws == NULL || ! usercontrollerWorkerReserveLine(ws)))
    {
        return false;
    }

    lineLock(l);
    ws->lines[ws->line_count] = l;
    ws->line_count += 1U;
    ls->registered = true;
    return true;
}

static bool usercontrollerWorkerRemoveLine(usercontroller_worker_state_t *ws, line_t *l)
{
    for (size_t i = 0; i < ws->line_count; ++i)
    {
        if (ws->lines[i] == l)
        {
            ws->line_count -= 1U;
            ws->lines[i] = ws->lines[ws->line_count];
            ws->lines[ws->line_count] = NULL;
            return true;
        }
    }

    return false;
}

void usercontrollerUnregisterLine(tunnel_t *t, line_t *l, usercontroller_lstate_t *ls)
{
    if (! ls->registered)
    {
        return;
    }

    usercontroller_worker_state_t *ws = usercontrollerGetWorkerState(t, lineGetWID(l));
    if (UNLIKELY(ws == NULL || ! usercontrollerWorkerRemoveLine(ws, l)))
    {
        LOGW("UserController: sweep registry lost a tracked line reference");
    }

    ls->registered = false;
    lineUnlock(l);
}

void usercontrollerWorkerClearRegistry(tunnel_t *t, wid_t wid)
{
    usercontroller_worker_state_t *ws = usercontrollerGetWorkerState(t, wid);
    if (ws == NULL)
    {
        return;
    }

    while (ws->line_count > 0)
    {
        ws->line_count -= 1U;
        line_t *line = ws->lines[ws->line_count];
        ws->lines[ws->line_count] = NULL;

        if (lineIsAlive(line))
        {
            usercontroller_lstate_t *ls = lineGetState(line, t);
            ls->registered = false;
        }

        lineUnlock(line);
    }
}

// Account payload bytes against the user's upload/download quota, mapping the physical flow direction
// to the user's perspective based on where the line started.
//
// "Upload" is traffic leaving the user toward the far side; "download" is traffic arriving at the user.
// The user sits on the side the line was initiated from:
//   - started_from_next == false (forward, prev-initiated): upstream payload is the user's upload.
//   - started_from_next == true  (reverse, next-initiated):  upstream payload is the user's download.
// So a line started from the next side flips the mapping, which is exactly the
// TunDevice -> WireGuardDevice -> UserController -> UdpStatelessSocket case.
//
// Returns true when accounting says the user is now over quota / disabled / expired and the line must
// be torn down (the caller recycles the buffer and closes the line).
bool usercontrollerAccountDirectional(tunnel_t *t, usercontroller_lstate_t *ls, uint64_t bytes, bool upstream_payload)
{
    usercontroller_tstate_t *ts = tunnelGetState(t);

    bool     is_upload = (upstream_payload != ls->started_from_next);
    uint64_t up        = is_upload ? bytes : 0;
    uint64_t down      = is_upload ? 0 : bytes;

    return authenticationclientUserAccountTraffic(ts->auth_client_tunnel, &ls->handle, up, down,
                                                  usercontrollerLocalTimeMS());
}

// Shared admission path. Promotes an unmanaged line to managed using the user currently recorded on
// it, reserving a connection + IP slot and starting sweep-tracking. Used both by upstream Init and by
// the public usercontrollerTunnelTryManageLine() API for nodes that authenticate mid-connection.
//
// Never sends a finish and never destroys line state: on any non-OK result the line is simply left
// unmanaged so the caller can reject it however it wants. Idempotent for already-managed lines, and a
// no-op (kUserAdmissionOk) for lines that carry no user, exactly like Init's passthrough behavior.
user_admission_result_t usercontrollerTunnelTryManageLine(tunnel_t *t, line_t *l)
{
    assert(lineGetWID(l) == getWID());

    usercontroller_lstate_t *ls = lineGetState(l, t);

    // Already enforced: do not admit/reserve twice.
    if (ls->managed)
    {
        return kUserAdmissionOk;
    }

    // Only lines that carry a valid authenticated user are subject to limits. Anonymous/no-auth lines
    // (or a caller that promotes before authentication) stay unmanaged passthroughs.
    const user_handle_t *current = lineGetCurrentUser(l);
    if (current == NULL || ! userHandleIsValid(current))
    {
        return kUserAdmissionOk;
    }

    usercontroller_tstate_t *ts = tunnelGetState(t);

    ls->handle        = *current;
    ls->authenticated = true;
    usercontrollerBuildIpKey(l, &ls->ip_key);

    user_admission_result_t result = authenticationclientUserTryAdmitConnection(
        ts->auth_client_tunnel, &ls->handle, &ls->ip_key, usercontrollerLocalTimeMS());

    if (result != kUserAdmissionOk)
    {
        // Reserved nothing. Every later path gates on `managed`, so the handle/ip_key filled in above
        // are inert until the caller rejects the line or a later call retries.
        return result;
    }

    ls->managed = true;
    if (UNLIKELY(! usercontrollerRegisterLine(t, l, ls)))
    {
        LOGW("UserController: failed to register live enforcement state; rejecting connection");
        authenticationclientUserReleaseConnection(ts->auth_client_tunnel, &ls->handle, &ls->ip_key);
        ls->managed = false;
        return kUserAdmissionInvalid;
    }

    return kUserAdmissionOk;
}

void usercontrollerSweepTimerCallback(wtimer_t *timer)
{
    tunnel_t *t = weventGetUserdata(timer);
    if (t == NULL || isApplicationTerminating())
    {
        return;
    }

    usercontroller_tstate_t      *ts  = tunnelGetState(t);
    usercontroller_worker_state_t *ws = usercontrollerGetWorkerState(t, getWID());
    if (ws == NULL)
    {
        return;
    }

    size_t i = 0;
    while (i < ws->line_count)
    {
        line_t *line = ws->lines[i];
        if (UNLIKELY(! lineIsAlive(line)))
        {
            ws->line_count -= 1U;
            ws->lines[i] = ws->lines[ws->line_count];
            ws->lines[ws->line_count] = NULL;
            lineUnlock(line);
            continue;
        }

        usercontroller_lstate_t *ls = lineGetState(line, t);
        if (! ls->managed || ls->closing)
        {
            i += 1U;
            continue;
        }

        if (authenticationclientUserShouldClose(ts->auth_client_tunnel, &ls->handle, usercontrollerLocalTimeMS()))
        {
            usercontrollerLogActiveClose(t, line, ls, "disabled, expired, traffic quota reached, or user removed");
            usercontrollerCloseLine(t, line, kUserControllerCloseInternal);
            continue;
        }

        i += 1U;
    }
}

static void usercontrollerReleaseAccounting(tunnel_t *t, line_t *l, usercontroller_lstate_t *ls)
{
    if (! ls->managed)
    {
        return;
    }

    usercontroller_tstate_t *ts = tunnelGetState(t);
    if (ls->registered)
    {
        usercontrollerUnregisterLine(t, l, ls);
    }
    ls->managed = false;
    authenticationclientUserReleaseConnection(ts->auth_client_tunnel, &ls->handle, &ls->ip_key);
}

// Single teardown path. Releases this user's reserved connection slot, destroys local line state,
// then propagates the real Waterwall finish in the correct directions. The `origin` alone decides
// which side(s) we may finish, which is what keeps us from reflecting a finish back toward the side
// that already finished us:
//
//   kUserControllerCloseFromPrev : prev finished us -> close next only, never touch prev
//   kUserControllerCloseFromNext : next finished us -> close prev only, never touch next
//   kUserControllerCloseInternal : our decision     -> close upstream first, then downstream
//
// We never send protocol bytes here, so the only re-entrancy boundary is the finish propagation
// itself, which Waterwall guarantees is non re-entrant. lineLock keeps the line memory valid until
// we return; `closing` collapses any re-entrant teardown into a no-op.
void usercontrollerCloseLine(tunnel_t *t, line_t *l, usercontroller_close_origin_t origin)
{
    usercontroller_lstate_t *ls = lineGetState(l, t);

    if (ls->closing)
    {
        return;
    }

    bool close_next = origin != kUserControllerCloseFromNext;
    bool close_prev = origin != kUserControllerCloseFromPrev;

    ls->closing = true;
    lineLock(l);

    usercontrollerReleaseAccounting(t, l, ls);

    usercontrollerLinestateDestroy(ls);

    if (close_next && lineIsAlive(l))
    {
        tunnelNextUpStreamFinish(t, l);
    }

    if (close_prev && lineIsAlive(l))
    {
        tunnelPrevDownStreamFinish(t, l);
    }

    lineUnlock(l);
}

#include "internal.h"
#include "loggers/network_logger.h"

const char *vmessserverReasonName(vmessserver_reason_t reason)
{
    static const char *const names[kVmessServerReasonCount] = {"unset",
                                                               "normal_close",
                                                               "authentication_mismatch",
                                                               "authentication_unavailable",
                                                               "expired_authid",
                                                               "replay_or_capacity",
                                                               "malformed_header",
                                                               "body_authentication",
                                                               "length_authentication",
                                                               "command_denied",
                                                               "security_denied",
                                                               "handshake_timeout",
                                                               "admission_refused",
                                                               "udp_oversize",
                                                               "malformed_packetaddr",
                                                               "destination_capacity",
                                                               "strict_exhaustion"};
    assert(reason < kVmessServerReasonCount);
    return names[reason];
}

void vmessserverDrop(vmessserver_lstate_t *ls, vmessserver_reason_t reason)
{
    vmessserver_tstate_t *ts = tunnelGetState(ls->tunnel);
    atomicAddU64(&ts->stats.reasons[reason], 1);
    if (! ts->verbose)
        return;
    uint64_t now = getHRTimeUs() / 1000U;
    uint64_t due = atomicLoadU64Relaxed(&ts->stats.next_log_ms);
    if (now >= due && atomicCompareExchangeU64Explicit(
                          &ts->stats.next_log_ms, &due, now + 1000, memory_order_relaxed, memory_order_relaxed))
        LOGD("VmessServer: reason=%s command=%u security=%u packetaddr=%u",
             vmessserverReasonName(reason),
             ls->request.command,
             ls->request.security,
             ls->packetaddr);
}

void vmessserverReason(vmessserver_lstate_t *ls, vmessserver_reason_t reason)
{
    /* Backends have independent lifetimes but share one logical association's
     * terminal result. Ordinary backend expiry does not terminate the carrier. */
    if (ls->line_kind == kVmessServerLineKindClient && ls->terminal_reason == kVmessServerReasonUnset)
    {
        ls->terminal_reason = reason;
        vmessserverDrop(ls, reason);
    }
}

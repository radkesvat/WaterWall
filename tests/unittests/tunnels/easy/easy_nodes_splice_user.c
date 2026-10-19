/*
 * Covers: easy nodes splice user; the explicit inputs, callbacks and expected results below define this
 * suite.
 * Setup: Auxiliary translation unit; linked into its owning suite with the same feature/seam
 * definitions. The suite driver owns initialization and teardown.
 * Cases: testUserControllerSplice
 * Checks: Exact return/byte/order and resource-count oracles in the explicit case bodies.
 * Limits: Platform/feature branches remain conditional. Component fixtures do not establish host-network
 * or application-throughput behavior.
 * CTest: waterwall.easy_nodes_splice_unit
 */
#include "UserController/structure.h"
#include "easy_nodes_splice_fixture.h"

static uint64_t        upload, download;
static unsigned        account_calls, releases;
static bool            reject;
static easy_fixture_t *user_fixture;

static void userReverseFinish(tunnel_t *t, line_t *l)
{
    ++user_fixture->finishes;
    if (t == user_fixture->next)
    {
        lineDestroy(l);
        user_fixture->line = NULL;
    }
}
bool __wrap_authenticationclientUserObservePayload(tunnel_t *t, const user_handle_t *handle, uint64_t up, uint64_t down,
                                                   uint64_t now);
user_bandwidth_result_t  __wrap_authenticationclientUserBandwidthPreview(tunnel_t *t, const user_handle_t *handle,
                                                                         user_bandwidth_direction_t direction,
                                                                         uint64_t ticket, uint64_t bytes, bool datagram);
user_delivery_decision_t __wrap_authenticationclientUserCommitDelivery(tunnel_t *t, const user_handle_t *handle,
                                                                       user_bandwidth_direction_t direction,
                                                                       uint64_t ticket, uint64_t bytes, bool datagram,
                                                                       bool more);
void                     __wrap_authenticationclientUserReleaseConnection(tunnel_t *t, const user_handle_t *handle,
                                                                          const user_ip_key_t *ip);
bool __wrap_authenticationclientUserObservePayload(tunnel_t *t, const user_handle_t *handle, uint64_t up, uint64_t down,
                                                   uint64_t now)
{
    discard t;
    discard handle;
    discard now;
    discard up;
    discard down;
    return reject;
}
user_bandwidth_result_t __wrap_authenticationclientUserBandwidthPreview(tunnel_t *t, const user_handle_t *handle,
                                                                        user_bandwidth_direction_t direction,
                                                                        uint64_t ticket, uint64_t bytes, bool datagram)
{
    discard t;
    discard handle;
    discard direction;
    discard ticket;
    discard datagram;
    return (user_bandwidth_result_t) {.decision = kUserDeliveryForward, .grant = bytes};
}
user_delivery_decision_t __wrap_authenticationclientUserCommitDelivery(tunnel_t *t, const user_handle_t *handle,
                                                                       user_bandwidth_direction_t direction,
                                                                       uint64_t ticket, uint64_t bytes, bool datagram,
                                                                       bool more)
{
    discard t;
    discard handle;
    discard ticket;
    discard datagram;
    discard more;
    if (direction == kUserBandwidthUpload)
        upload += bytes;
    else
        download += bytes;
    ++account_calls;
    return kUserDeliveryForward;
}
void __wrap_authenticationclientUserReleaseConnection(tunnel_t *t, const user_handle_t *handle, const user_ip_key_t *ip)
{
    discard t;
    discard handle;
    discard ip;
    ++releases;
}
void testUserControllerSplice(bool splice)
{
    for (unsigned reverse = 0; reverse < 2; ++reverse)
    {
        for (unsigned managed = 0; managed < 2; ++managed)
        {
            easy_fixture_t f;
            easySetup(&f, tunnelCreate(NULL, sizeof(usercontroller_tstate_t), sizeof(usercontroller_lstate_t)));
            if (reverse)
            {
                // Reverse Init describes a next-side creator. Match the exact
                // line's ownership instead of keeping the default prev owner.
                user_fixture   = &f;
                f.prev->fnFinD = userReverseFinish;
                f.next->fnFinU = userReverseFinish;
            }
            usercontroller_lstate_t *ls = lineGetState(f.line, f.node);
            usercontrollerLinestateInitialize(ls, reverse);
            ls->payload_mode = kUserControllerPayloadStream;
            usercontrollerBandwidthInitialize(f.node, f.line);
            ls->managed = managed;
            upload = download = account_calls = releases = 0;
            reject                                       = false;
            sbuf_t *buf                                  = easyPayload(splice);
            easyExpect(&f, buf, "prebody", 7, 3);
            usercontrollerTunnelUpStreamPayload(f.node, f.line, buf);
            easyRequire(f.expected == NULL && f.upstream == 1, "user upstream forwarding");
            easyRequire(upload == (managed && ! reverse ? 7 : 0) && download == (managed && reverse ? 7 : 0),
                        "upstream logical accounting");
            buf = easyPayload(splice);
            easyExpect(&f, buf, "prebody", 7, 3);
            usercontrollerTunnelDownStreamPayload(f.node, f.line, buf);
            easyRequire(f.expected == NULL && f.downstream == 1, "user downstream forwarding");
            easyRequire(upload == (managed ? 7 : 0) && download == (managed ? 7 : 0) && account_calls == managed * 2,
                        "downstream logical accounting");
            if (managed)
            {
                reject = true;
                buf    = easyPayload(splice);
                easyWatch(buf);
                if (reverse)
                    usercontrollerTunnelDownStreamPayload(f.node, f.line, buf);
                else
                    usercontrollerTunnelUpStreamPayload(f.node, f.line, buf);
                easyRequireDisposed();
                easyRequire(f.line == NULL && f.finishes == 2 && releases == 1,
                            "rejection must dispose then close/release once");
            }
            easyTeardown(&f);
        }
    }
}

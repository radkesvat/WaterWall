/* CTest: waterwall.tunnels_abort_runtime_unit (Release).
 * Constructor validation makes rejected KCP geometry impossible. Corrupt that
 * already-validated geometry and require the shared driver's hard fatal guard.
 * The sentinel pool is never accessed before ikcp_setmtu rejects the geometry.
 */
#include "KcpCommon/session.h"
#include "tunnels_abort_runtime_cases.h"

static void discardWire(void *user, sbuf_t *packet)
{
    discard user;
    discard packet;
}

int tunnelsAbortKcpClientMtuCase(void)
{
    const tou_config_t    config               = {.send_mtu               = 10,
                                                  .kcp_nodelay            = true,
                                                  .kcp_interval_ms        = 10,
                                                  .kcp_resend             = 2,
                                                  .kcp_send_window        = 128,
                                                  .kcp_recv_window        = 128,
                                                  .close_drain_timeout_ms = 30000,
                                                  .pool                   = (buffer_pool_t *) (uintptr_t) 1};
    const tou_callbacks_t callbacks            = {.emit = discardWire};
    const uint8_t         nonce[kTouNonceSize] = {1};
    discard               touSessionCreate(&config, &callbacks, NULL, true, nonce, nonce, NULL);
    return 0;
}

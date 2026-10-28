/* Node-level fallback FIFO, scheduling, reentry and Finish lifetime regressions.
 * The shared cases and their explicit byte/callback/ownership assertions live in
 * fallback_replay_server_suite.h. CTest:
 * waterwall.vlessserver_fallback_finish_lifetime_unit. */
#include "VlessServer/internal.h"

typedef vlessserver_tstate_t fallback_server_tstate_t;
typedef vlessserver_lstate_t fallback_server_lstate_t;
#define kFallbackServerLineKindClient         kVlessServerLineKindClient
#define kFallbackServerMaxPendingBytes        kVlessServerMaxPendingBytes
#define fallbackServerLinestateInitialize     vlessserverLinestateInitialize
#define fallbackServerStartFallback           vlessserverStartFallback
#define fallbackServerSendFallbackPayload     vlessserverSendFallbackPayload
#define fallbackServerTunnelUpStreamPayload   vlessserverTunnelUpStreamPayload
#define fallbackServerTunnelUpStreamFinish    vlessserverTunnelUpStreamFinish
#define fallbackServerTunnelDownStreamPayload vlessserverTunnelDownStreamPayload
#define fallbackServerTunnelDownStreamEst     vlessserverTunnelDownStreamEst
#define fallbackServerTunnelDownStreamPause   vlessserverTunnelDownStreamPause
#define fallbackServerTunnelDownStreamResume  vlessserverTunnelDownStreamResume
#define fallbackServerTunnelDownStreamFinish  vlessserverTunnelDownStreamFinish

#include "fixtures/protocols/fallback_replay_server_suite.h"

int main(void)
{
    fallbackReplayRunServerSuite();
    printf("vlessserver_fallback_finish_lifetime_test: all cases passed\n");
    return 0;
}

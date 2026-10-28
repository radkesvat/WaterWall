/* Node-level fallback FIFO, scheduling, reentry and Finish lifetime regressions.
 * The shared cases and their explicit byte/callback/ownership assertions live in
 * fallback_replay_server_suite.h. CTest:
 * waterwall.vmessserver_fallback_finish_lifetime_unit. */
#include "VmessServer/internal.h"

typedef vmessserver_tstate_t fallback_server_tstate_t;
typedef vmessserver_lstate_t fallback_server_lstate_t;
#define kFallbackServerLineKindClient         kVmessServerLineKindClient
#define kFallbackServerMaxPendingBytes        kVmessServerMaxPendingBytes
#define fallbackServerLinestateInitialize     vmessserverLinestateInitialize
#define fallbackServerStartFallback           vmessserverStartFallback
#define fallbackServerSendFallbackPayload     vmessserverSendFallbackPayload
#define fallbackServerTunnelUpStreamPayload   vmessserverTunnelUpStreamPayload
#define fallbackServerTunnelUpStreamFinish    vmessserverTunnelUpStreamFinish
#define fallbackServerTunnelDownStreamPayload vmessserverTunnelDownStreamPayload
#define fallbackServerTunnelDownStreamEst     vmessserverTunnelDownStreamEst
#define fallbackServerTunnelDownStreamPause   vmessserverTunnelDownStreamPause
#define fallbackServerTunnelDownStreamResume  vmessserverTunnelDownStreamResume
#define fallbackServerTunnelDownStreamFinish  vmessserverTunnelDownStreamFinish

#include "fixtures/protocols/fallback_replay_server_suite.h"

int main(void)
{
    fallbackReplayRunServerSuite();
    printf("vmessserver_fallback_finish_lifetime_test: all cases passed\n");
    return 0;
}

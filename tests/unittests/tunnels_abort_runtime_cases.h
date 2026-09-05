#pragma once

/*
 * Shared contract between the tunnels_abort_runtime_test dispatcher and the
 * per-tunnel fixture translation units.
 *
 * Each case runs exactly one production call that must not return. The process
 * result is therefore the whole assertion: the CMake runner requires an exact
 * result of 1 (abortProgramNow(1)) and rejects a signal, an access violation,
 * a zero exit, and every reserved setup-failure code below.
 *
 * A case function only ever returns when the test itself could not reach the
 * production invariant, so returning 0 means "the production call returned"
 * and is a test failure.
 */
enum
{
    kAbortCaseUsageError         = 120,
    kAbortCaseUnknownName        = 121,
    kAbortCaseAllocationFailed   = 122,
    kAbortCaseInvalidWorkerCount = 123
};

/*
 * Tunnel-specific fixtures live in their own translation units so that only one
 * tunnel's structure.h is ever visible at a time; the generic kTunnelStateSize
 * and kLineStateSize enumerators exported by those headers would otherwise
 * collide.
 */
int tunnelsAbortUdpStatelessSocketDestroyCase(void);
int tunnelsAbortTcpOverUdpClientMtuCase(void);
int tunnelsAbortTcpOverUdpServerMtuCase(void);
int tunnelsAbortRouterGeoipUnopenedDatabaseCase(void);

int tunnelsAbortTlsServerDrainingInitCase(void);
int tunnelsAbortSocks5ClientUdpAppInitCase(void);
int tunnelsAbortSocks5ClientUdpControlInitCase(void);
int tunnelsAbortSocks5ClientUdpRelayInitCase(void);
int tunnelsAbortTrojanClientUdpInitCase(void);
int tunnelsAbortTrojanServerClosingInitCase(void);
int tunnelsAbortVlessClientUdpInitCase(void);
int tunnelsAbortVlessServerClosingInitCase(void);
int tunnelsAbortRealityServerClosingEstCase(void);
int tunnelsAbortTlsServerClosingEstCase(void);
int tunnelsAbortRouterTargetEstCase(void);
int tunnelsAbortHttpClientUpstreamEstCase(void);
int tunnelsAbortHttpClientDownstreamInitCase(void);

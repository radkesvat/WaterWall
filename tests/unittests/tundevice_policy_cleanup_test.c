/* Exercise actual tunnel policy/start/stop code with inert device operations. */
#ifdef OS_WIN
#include "devices/tun/tun_windows_dns.h"
#endif
#include "loggers/network_logger.h"
#include "structure.h"

static unsigned int deletes[3];
static unsigned int adds[3];
static unsigned int delete_failures;
static unsigned int add_failures;
static bool         route_outcome_unknown;
static unsigned int delete_unknowns;
static unsigned int last_deleted;
static unsigned int clear_calls;
static unsigned int bring_down_calls;
static unsigned int script_calls;
static unsigned int failure_calls;
static int          selected_exit;
static bool         dns_set_ok;
static bool         dns_clear_ok;
static bool         dns_cancelled;
static bool         bring_down_ok;
static bool         partial_dns;
static bool         dns_helper_started;
static bool         last_offload_requested;
static char         route_values[][16] = {"1.0.0.0/8", "2.0.0.0/8", "3.0.0.0/8"};
static char         dns_values[][8]    = {"1.1.1.1", "2.2.2.2"};
static char         inert_script[]     = "inert fixture script";
static char         startup_script[]   = "must not execute after failed startup";

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "FAIL: %s\n", message);
        exit(1);
    }
}

static bool fakeRemoveRoute(tun_device_t *device, const char *cidr, const char *table)
{
    (void) device;
    (void) table;
    unsigned int index = (unsigned int) (cidr[0] - '1');
    require(index < 3, "unexpected route");
    ++deletes[index];
    last_deleted = index;
    return (delete_failures & (1U << index)) == 0;
}

static bool fakeAddRoute(tun_device_t *device, const char *cidr, const char *table)
{
    (void) device;
    (void) table;
    unsigned int index = (unsigned int) (cidr[0] - '1');
    require(index < 3, "unexpected route add");
    ++adds[index];
    return (add_failures & (1U << index)) == 0;
}

static bool fakeSetDns(tun_device_t *device, const char *const *servers, size_t count)
{
    (void) device;
    (void) servers;
    require(count == 2, "expected two resolvers");
    partial_dns = dns_helper_started;
    return dns_set_ok;
}

static bool fakeClearDns(tun_device_t *device)
{
    (void) device;
    ++clear_calls;
    if (dns_clear_ok)
    {
        partial_dns = false;
    }
    return dns_clear_ok;
}

static bool fakeDnsCancelled(const tun_device_t *device)
{
    (void) device;
    return dns_cancelled;
}

static bool fakeDnsNeedsCleanup(const tun_device_t *device)
{
    (void) device;
    return partial_dns;
}

static bool fakeLinuxDnsNeedsCleanup(const tun_device_t *device)
{
    (void) device;
    return partial_dns;
}

static bool fakeLinuxCommandUnknown(const tun_device_t *device)
{
    (void) device;
    return route_outcome_unknown || (delete_unknowns & (1U << last_deleted)) != 0;
}

static bool fakeBringDown(tun_device_t *device)
{
    (void) device;
    ++bring_down_calls;
    return bring_down_ok;
}

static void fakeRecordFailure(int code, application_shutdown_reason_e reason)
{
    require(code != 0 && reason == kApplicationShutdownReasonSubsystemFailure, "bad cleanup failure");
    ++failure_calls;
    if (selected_exit == 0)
    {
        selected_exit = code;
    }
}

static tun_device_t *fakeCreate(const char *name, bool offload, uint16_t mtu, void *userdata, TunReadEventHandle cb,
                                device_fragment_policy_t fragment_policy)
{
    (void) name;
    last_offload_requested = offload;
    (void) mtu;
    (void) userdata;
    (void) cb;
    (void) fragment_policy;
    return (tun_device_t *) (uintptr_t) 1;
}

static bool fakeAssignIp(tun_device_t *device, const char *ip, unsigned int subnet)
{
    (void) device;
    (void) ip;
    (void) subnet;
    return true;
}

static bool fakeDeviceSuccess(tun_device_t *device)
{
    (void) device;
    return true;
}

static bool fakeDisableReversePathFiltering(const char *name)
{
    (void) name;
    return true;
}

static bool fakeBind(tunnel_t *tunnel)
{
    (void) tunnel;
    return true;
}

static cmd_result_t fakeExec(const char *command)
{
    (void) command;
    ++script_calls;
    return (cmd_result_t) {0};
}

void tundeviceOnIPPacketReceived(tun_device_t *device, void *userdata, sbuf_t *buffer, wid_t wid)
{
    (void) device;
    (void) userdata;
    (void) buffer;
    (void) wid;
}

#define tundeviceRemoveRoute               fakeRemoveRoute
#define tundeviceAddRoute                  fakeAddRoute
#define tundeviceSetDnsServers             fakeSetDns
#define tundeviceClearDnsServers           fakeClearDns
#define tundeviceWindowsDnsWasCancelled    fakeDnsCancelled
#define tundeviceWindowsDnsNeedsCleanup    fakeDnsNeedsCleanup
#define tundeviceDnsNeedsCleanup           fakeLinuxDnsNeedsCleanup
#define tundeviceLastCommandOutcomeUnknown fakeLinuxCommandUnknown
#define tundeviceBringDown                 fakeBringDown
#define applicationShutdownRecordFailure   fakeRecordFailure
#define tundeviceCreate                    fakeCreate
#define tundeviceCreateOwned(name, offload, mtu, userdata, cb, policy, ownership)                                      \
    fakeCreate(name, offload, mtu, userdata, cb, policy)
#define tundeviceAssignIP                    fakeAssignIp
#define tundeviceBringUp                     fakeDeviceSuccess
#define tundeviceRequestStop                 fakeDeviceSuccess
#define tundeviceDisableReversePathFiltering fakeDisableReversePathFiltering
#define packettunnelLifecycleAnchorBind      fakeBind
#define execCmd                              fakeExec
#include "../../tunnels/TunDevice/common/dns.c"
#include "../../tunnels/TunDevice/common/routes.c"
#include "../../tunnels/TunDevice/instance/start.c"
#include "../../tunnels/TunDevice/instance/stop.c"

static void resetProbe(void)
{
    memset(deletes, 0, sizeof(deletes));
    memset(adds, 0, sizeof(adds));
    delete_failures = clear_calls = bring_down_calls = script_calls = failure_calls = 0;
    add_failures                                                                    = 0;
    route_outcome_unknown                                                           = false;
    delete_unknowns = last_deleted = 0;
    selected_exit                  = 0;
    dns_set_ok = dns_clear_ok = bring_down_ok = dns_helper_started = true;
    dns_cancelled = partial_dns = false;
    last_offload_requested      = false;
}

static void testRouteInventory(void)
{
    resetProbe();
    char              *routes[] = {route_values[0], route_values[1], route_values[2]};
    tundevice_tstate_t state    = {.tdev                    = (tun_device_t *) (uintptr_t) 1,
                                   .system_route_enabled    = true,
                                   .system_routes           = routes,
                                   .system_route_count      = 3,
                                   .system_routes_installed = 3};
    delete_failures             = 5;
    tundeviceCleanupSystemRoutes(&state);
    require(deletes[0] == 1 && deletes[1] == 1 && deletes[2] == 1, "independent route removals skipped");
    require(state.system_routes_installed == 2 && routes[0][0] == '1' && routes[1][0] == '3',
            "failed routes lost from installed prefix");
    require(state.policy_cleanup_failed && failure_calls == 0, "leaf cleanup claimed shutdown");
    delete_failures = 0;
    tundeviceCleanupSystemRoutes(&state);
    tundeviceCleanupSystemRoutes(&state);
    require(state.system_routes_installed == 0 && deletes[0] == 2 && deletes[1] == 1 && deletes[2] == 2,
            "retry did not settle exactly unresolved routes");
}

#if defined(OS_LINUX) || defined(OS_BSD)
static void testUncertainRouteAddIsNotDeleted(void)
{
    resetProbe();
    char              *routes[] = {route_values[0], route_values[1], route_values[2]};
    tundevice_tstate_t state    = {.tdev                 = (tun_device_t *) (uintptr_t) 1,
                                   .system_route_enabled = true,
                                   .system_routes        = routes,
                                   .system_route_count   = 3};
    add_failures                = 1U << 1;
    route_outcome_unknown       = true;
    require(! tundeviceApplySystemRoutes(&state), "uncertain route add must fail startup");
    require(adds[0] == 1 && adds[1] == 1 && adds[2] == 0, "startup continued after uncertain route add");
    require(deletes[0] == 1 && deletes[1] == 0 && state.system_route_outcome_unknown && state.policy_cleanup_failed,
            "uncertain route was deleted or forgotten");
    require(! tundeviceApplySystemRoutes(&state) && adds[0] == 1 && adds[1] == 1,
            "retry replaced an unresolved route record");
}
#endif

static void testExistingRouteIsNotDeleted(void)
{
    resetProbe();
    char              *routes[] = {route_values[0]};
    tundevice_tstate_t state    = {.tdev                 = (tun_device_t *) (uintptr_t) 1,
                                   .system_route_enabled = true,
                                   .system_routes        = routes,
                                   .system_route_count   = 1};
    add_failures                = 1U;
    require(! tundeviceApplySystemRoutes(&state), "existing route must fail add");
    require(deletes[0] == 0 && ! state.system_route_outcome_unknown, "an unrelated pre-existing route entered cleanup");
}

#if defined(OS_LINUX) || defined(OS_BSD)

static void testUncertainDeletesDoNotBlockOtherRetries(void)
{
    resetProbe();
    char              *routes[] = {route_values[0], route_values[1], route_values[2]};
    tundevice_tstate_t state    = {.tdev                    = (tun_device_t *) (uintptr_t) 1,
                                   .system_route_enabled    = true,
                                   .system_routes           = routes,
                                   .system_route_count      = 3,
                                   .system_routes_installed = 3};
    delete_failures             = 7;
    delete_unknowns             = 6;
    tundeviceCleanupSystemRoutes(&state);
    require(state.system_route_deletes_unknown == 2 && state.system_routes_installed == 3,
            "multiple uncertain deletions lost their identities");
    delete_failures = delete_unknowns = 0;
    tundeviceCleanupSystemRoutes(&state);
    tundeviceCleanupSystemRoutes(&state);
    require(deletes[0] == 2 && deletes[1] == 1 && deletes[2] == 1 && state.system_routes_installed == 2,
            "uncertain deletions blocked an independent retry or were retried themselves");
}

static void testUncertainRouteDeleteIsNotRetried(void)
{
    resetProbe();
    char              *routes[] = {route_values[0], route_values[1]};
    tundevice_tstate_t state    = {.tdev                    = (tun_device_t *) (uintptr_t) 1,
                                   .system_route_enabled    = true,
                                   .system_routes           = routes,
                                   .system_route_count      = 2,
                                   .system_routes_installed = 2};
    delete_failures             = 1U;
    route_outcome_unknown       = true;
    tundeviceCleanupSystemRoutes(&state);
    require(state.system_route_deletes_unknown == 1 && state.system_routes_installed == 1 && deletes[0] == 1 &&
                deletes[1] == 1,
            "uncertain deletion did not retain cleanup status");
    delete_failures = 0;
    tundeviceCleanupSystemRoutes(&state);
    require(deletes[0] == 1, "uncertain deletion was retried against a potentially foreign route");
}
#endif

static void testDnsInventory(void)
{
    resetProbe();
    tundevice_tstate_t state = {
        .tdev = (tun_device_t *) (uintptr_t) 1, .dns_servers = {dns_values[0], dns_values[1]}, .dns_server_count = 2};
    dns_set_ok = dns_clear_ok = false;
    require(! tundeviceApplyDnsSettings(&state) && state.dns_servers_installed && partial_dns,
            "failed partial DNS installation not owned");
    tundeviceCleanupDnsSettings(&state);
    require(state.dns_servers_installed && state.policy_cleanup_failed, "failed DNS deletion forgotten");
    dns_clear_ok = true;
    tundeviceCleanupDnsSettings(&state);
    tundeviceCleanupDnsSettings(&state);
    require(! state.dns_servers_installed && ! partial_dns && clear_calls == 2, "DNS retry not idempotent");
}

static void testUnownedDnsIsNotReverted(void)
{
    resetProbe();
    tundevice_tstate_t state = {
        .tdev = (tun_device_t *) (uintptr_t) 1, .dns_servers = {dns_values[0], dns_values[1]}, .dns_server_count = 2};
    dns_set_ok         = false;
    dns_helper_started = false;
    require(! tundeviceApplyDnsSettings(&state) && ! state.dns_servers_installed,
            "unowned DNS was recorded for cleanup");
    tundeviceCleanupDnsSettings(&state);
    require(clear_calls == 0, "unrelated pre-existing DNS was reverted");
}

static void testOwnerCleanup(void)
{
    resetProbe();
    tunnel_t *tunnel = tunnelCreate(NULL, sizeof(tundevice_tstate_t), 0);
    require(tunnel != NULL, "tunnel allocation");
    tundevice_tstate_t *state    = tunnelGetState(tunnel);
    char               *routes[] = {route_values[0], route_values[1], route_values[2]};
    state->tdev                  = (tun_device_t *) (uintptr_t) 1;
    state->system_routes         = routes;
    state->system_route_enabled  = true;
    state->system_route_count = state->system_routes_installed = 3;
    state->dns_servers_installed                               = true;
    state->pre_down_script                                     = inert_script;
    state->pre_down_pending                                    = true;
    dns_clear_ok = bring_down_ok = false;
    delete_failures              = 5;
    selected_exit                = 47;
    tundeviceTunnelOnQuiesceWait(tunnel, wwLifecycleProcessShutdown());
    require(clear_calls == 1 && bring_down_calls == 1 && deletes[1] == 1, "one failure prevented independent cleanup");
    require(failure_calls == 1 && selected_exit == 47, "cleanup replaced first failure");
    dns_clear_ok = bring_down_ok = true;
    delete_failures              = 0;
    tundeviceTunnelOnQuiesceWait(tunnel, wwLifecycleProcessShutdown());
    require(script_calls == 1 && state->system_routes_installed == 0 && ! state->dns_servers_installed,
            "repeated stop did not preserve cleanup ownership");
    selected_exit = 0;
    tundeviceTunnelOnQuiesceWait(tunnel, wwLifecycleProcessShutdown());
    require(selected_exit == 1, "earlier cleanup failure lost after later successful cleanup");
    tunnelDestroy(tunnel);
}

static void testStartupRollback(bool gso_requested, bool cancelled, bool cleanup_ok, bool helper_started)
{
    resetProbe();
    tunnel_t *tunnel = tunnelCreate(NULL, sizeof(tundevice_tstate_t), 0);
    require(tunnel != NULL, "startup tunnel allocation");
    tundevice_tstate_t *state    = tunnelGetState(tunnel);
    state->gso_requested         = gso_requested;
    state->dns_servers[0]        = dns_values[0];
    state->dns_servers[1]        = dns_values[1];
    state->dns_server_count      = 2;
    state->pre_down_script       = startup_script;
    dns_set_ok                   = false;
    dns_cancelled                = cancelled;
    dns_helper_started           = helper_started;
    dns_clear_ok                 = cleanup_ok;
    ww_startup_context_t context = {0};
    wwStartupContextBegin(&context);
    tundeviceTunnelOnStart(tunnel);
    ww_startup_result_t result = wwStartupContextEnd(&context);
#ifdef OS_LINUX
    require(last_offload_requested == gso_requested, "Linux GSO request was not forwarded to the TUN backend");
#else
    require(! last_offload_requested, "unsupported platform requested TUN GSO");
#endif
#ifdef OS_WIN
    require(wwStartupSucceeded(result) == (cancelled && (cleanup_ok || ! helper_started)),
            "wrong cancellation/failure startup result");
#else
    require(! wwStartupSucceeded(result), "failed DNS setup must fail startup");
#endif
    require(state->tdev != NULL && clear_calls == (helper_started ? 1U : 0U) && bring_down_calls == 1,
            "startup partial policy skipped cleanup or lost device before owner teardown");
    require(state->dns_servers_installed == (helper_started && ! cleanup_ok) && failure_calls == 0,
            "startup cleanup lost ownership or claimed controller");
    dns_clear_ok = true;
    tundeviceTunnelOnQuiesceWait(tunnel, wwLifecycleStartupRollback());
    require(script_calls == 0 && ! state->dns_servers_installed, "rollback ran script or failed retry");
    tunnelDestroy(tunnel);
}

int main(void)
{
    logger_t *logger = loggerCreate();
    require(logger != NULL, "logger allocation");
    setNetworkLogger(logger);
    testRouteInventory();
#if defined(OS_LINUX) || defined(OS_BSD)
    testUncertainRouteAddIsNotDeleted();
    testUncertainRouteDeleteIsNotRetried();
    testUncertainDeletesDoNotBlockOtherRetries();
#endif
    testExistingRouteIsNotDeleted();
    testDnsInventory();
    testUnownedDnsIsNotReverted();
    testOwnerCleanup();
    testStartupRollback(true, false, false, true);
    testStartupRollback(false, true, true, true);
    testStartupRollback(true, true, false, true);
    testStartupRollback(false, true, false, false);
    networkloggerDestroy();
    puts("TunDevice policy cleanup tests passed");
    return 0;
}

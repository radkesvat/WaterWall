/* Exercise actual tunnel policy/start/stop code with inert device operations. */
#include "devices/tun/tun_windows_dns.h"
#include "loggers/network_logger.h"
#include "structure.h"

static unsigned int deletes[3];
static unsigned int delete_failures;
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
    return (delete_failures & (1U << index)) == 0;
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

static tun_device_t *fakeCreate(const char *name, bool offload, uint16_t mtu, void *userdata, TunReadEventHandle cb)
{
    (void) name;
    (void) offload;
    (void) mtu;
    (void) userdata;
    (void) cb;
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

#define tundeviceRemoveRoute                                              fakeRemoveRoute
#define tundeviceSetDnsServers                                            fakeSetDns
#define tundeviceClearDnsServers                                          fakeClearDns
#define tundeviceWindowsDnsWasCancelled                                   fakeDnsCancelled
#define tundeviceWindowsDnsNeedsCleanup                                   fakeDnsNeedsCleanup
#define tundeviceBringDown                                                fakeBringDown
#define applicationShutdownRecordFailure                                  fakeRecordFailure
#define tundeviceCreate                                                   fakeCreate
#define tundeviceCreateOwned(name, offload, mtu, userdata, cb, ownership) fakeCreate(name, offload, mtu, userdata, cb)
#define tundeviceAssignIP                                                 fakeAssignIp
#define tundeviceBringUp                                                  fakeDeviceSuccess
#define tundeviceRequestStop                                              fakeDeviceSuccess
#define packettunnelLifecycleAnchorBind                                   fakeBind
#define execCmd                                                           fakeExec
#include "../../tunnels/TunDevice/common/dns.c"
#include "../../tunnels/TunDevice/common/routes.c"
#include "../../tunnels/TunDevice/instance/start.c"
#include "../../tunnels/TunDevice/instance/stop.c"

static void resetProbe(void)
{
    memset(deletes, 0, sizeof(deletes));
    delete_failures = clear_calls = bring_down_calls = script_calls = failure_calls = 0;
    selected_exit                                                                   = 0;
    dns_set_ok = dns_clear_ok = bring_down_ok = dns_helper_started = true;
    dns_cancelled = partial_dns = false;
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

static void testStartupRollback(bool cancelled, bool cleanup_ok, bool helper_started)
{
    resetProbe();
    tunnel_t *tunnel = tunnelCreate(NULL, sizeof(tundevice_tstate_t), 0);
    require(tunnel != NULL, "startup tunnel allocation");
    tundevice_tstate_t *state    = tunnelGetState(tunnel);
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
    require(wwStartupSucceeded(result) == (cancelled && (cleanup_ok || ! helper_started)),
            "wrong cancellation/failure startup result");
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
    testDnsInventory();
    testOwnerCleanup();
    testStartupRollback(false, false, true);
    testStartupRollback(true, true, true);
    testStartupRollback(true, false, true);
    testStartupRollback(true, false, false);
    networkloggerDestroy();
    puts("TunDevice policy cleanup tests passed");
    return 0;
}

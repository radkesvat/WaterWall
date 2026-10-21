/* Manual payload-mode parsing, preparation refusal, creator/destination resolution,
 * both Init orientations, immutable saved framing and late authenticated promotion.
 * The fixture owns normal lines; UserController borrows them. No network traffic.
 * CTest: waterwall.usercontroller_payload_mode_unit. */
#include "UserController/structure.h"
#include "global_state.h"
#include "test_assert.h"

#define require(condition, message) TEST_REQUIRE(TEST_FAILURE_EXIT, condition, message)

static node_t                        auth_node;
static tunnel_t                     *observed_controller;
static usercontroller_payload_mode_t expected_mode, resolved_mode;
static unsigned                      resolver_calls, init_calls, admissions, releases;
static unsigned                      prev_finishes, next_finishes;
static tunnel_t                     *owner_endpoint;

typedef enum mode_source_e
{
    kFixedMode,
    kCreatorMode,
    kDestinationMode
} mode_source_t;

node_t                 *__wrap_nodemanagerGetConfigNodeByName(node_manager_config_t *config, const char *name);
user_admission_result_t __wrap_authenticationclientUserTryAdmitConnection(tunnel_t *t, const user_handle_t *handle,
                                                                          const user_ip_key_t *ip, uint64_t now);
void                    __wrap_authenticationclientUserReleaseConnection(tunnel_t *t, const user_handle_t *handle,
                                                                         const user_ip_key_t *ip);

node_t *__wrap_nodemanagerGetConfigNodeByName(node_manager_config_t *config, const char *name)
{
    discard config;
    return stringCompare(name, "auth-client") == 0 ? &auth_node : NULL;
}

user_admission_result_t __wrap_authenticationclientUserTryAdmitConnection(tunnel_t *t, const user_handle_t *handle,
                                                                          const user_ip_key_t *ip, uint64_t now)
{
    discard ip;
    discard now;
    require(t == auth_node.instance && handle->user_id == 42, "promotion lost authenticated identity");
    ++admissions;
    return kUserAdmissionOk;
}

void __wrap_authenticationclientUserReleaseConnection(tunnel_t *t, const user_handle_t *handle, const user_ip_key_t *ip)
{
    discard ip;
    require(t == auth_node.instance && handle->user_id == 42, "release changed authenticated identity");
    ++releases;
}

static usercontroller_payload_mode_t resolve(tunnel_t *owner, line_t *line)
{
    require(owner == auth_node.instance && lineIsOnCurrentWorker(line), "resolver lacks its owner worker context");
    ++resolver_calls;
    return resolved_mode;
}

static void initialized(tunnel_t *t, line_t *line)
{
    discard                        t;
    const usercontroller_lstate_t *ls = lineGetState(line, observed_controller);
    require(ls->payload_mode == expected_mode, "neighbor Init observed no saved payload mode");
    ++init_calls;
}

static void finished(tunnel_t *t, line_t *line)
{
    if (t == observed_controller->prev)
        ++prev_finishes;
    else
        ++next_finishes;
    if (t == owner_endpoint)
    {
        const unsigned char *state = lineGetState(line, observed_controller);
        for (size_t i = 0; i < observed_controller->lstate_size; ++i)
            require(state[i] == 0, "mode rejection left partial controller state");
        lineDestroy(line);
    }
}

static tunnel_t *createController(node_t *node, const char *mode_json)
{
    char settings[256];
    snprintf(settings, sizeof(settings), "{\"auth-client-node-name\":\"auth-client\"%s}", mode_json);
    *node = (node_t) {.node_settings_json = cJSON_Parse(settings)};
    require(node->node_settings_json != NULL, "parse fixture settings");
    tunnel_t *controller = usercontrollerTunnelCreate(node);
    return controller;
}

static void destroyController(node_t *node, tunnel_t *controller)
{
    if (controller != NULL)
        usercontrollerTunnelDestroy(controller, wwLifecycleStartupRollback());
    cJSON_Delete(node->node_settings_json);
}

static bool prepare(tunnel_t *controller)
{
    ww_startup_context_t scope = {0};
    wwStartupContextBegin(&scope);
    usercontrollerTunnelOnPrepair(controller);
    return wwStartupSucceeded(wwStartupContextEnd(&scope));
}

static void testConfigurationRefusals(void)
{
    const char *invalid[] = {",\"payload-mode\":null",
                             ",\"payload-mode\":true",
                             ",\"payload-mode\":0",
                             ",\"payload-mode\":\"\"",
                             ",\"payload-mode\":\"udp\"",
                             ",\"payload-mode\":\"dest_ctx->tcp/udp\"",
                             ",\"payload-mode\":\"Stream\""};
    for (unsigned i = 0; i < ARRAY_SIZE(invalid); ++i)
    {
        node_t    node;
        tunnel_t *controller = createController(&node, invalid[i]);
        require(controller == NULL, "invalid payload mode accepted by constructor");
        destroyController(&node, controller);
    }
    node_t    node;
    tunnel_t *controller = createController(&node, "");
    require(controller != NULL, "internal creator must be able to bind mode after construction");
    require(! prepare(controller), "missing manual mode accepted at preparation");
    destroyController(&node, controller);

    const char *configured_modes[] = {",\"payload-mode\":\"stream\"",
                                      ",\"payload-mode\":\"datagram\"",
                                      ",\"payload-mode\":\"dest_context->protocol\""};
    for (unsigned i = 0; i < ARRAY_SIZE(configured_modes); ++i)
    {
        controller = createController(&node, configured_modes[i]);
        require(controller != NULL, "valid configured mode rejected");
        usercontrollerSetPayloadModeResolver(controller, auth_node.instance, resolve);
        require(! prepare(controller), "conflicting configured mode and creator resolver accepted");
        destroyController(&node, controller);
    }
}

static void testSavedMode(bool reverse, mode_source_t source, usercontroller_payload_mode_t mode)
{
    node_t      node;
    const char *setting    = source == kCreatorMode                 ? ""
                             : source == kDestinationMode           ? ",\"payload-mode\":\"dest_context->protocol\""
                             : mode == kUserControllerPayloadStream ? ",\"payload-mode\":\"stream\""
                                                                    : ",\"payload-mode\":\"datagram\"";
    tunnel_t   *controller = createController(&node, setting);
    require(controller != NULL, "valid mode controller construction");
    if (source == kCreatorMode)
        usercontrollerSetPayloadModeResolver(controller, auth_node.instance, resolve);
    require(prepare(controller), "valid mode source rejected at prepare");
    tunnel_t *prev = tunnelCreate(NULL, 0, 0), *next = tunnelCreate(NULL, 0, 0);
    require(prev != NULL && next != NULL, "endpoint fixture allocation");
    prev->fnInitD = next->fnInitU = initialized;
    prev->fnFinD = next->fnFinU = finished;
    tunnelBind(prev, controller);
    tunnelBind(controller, next);
    tunnel_chain_t *chain      = tunnelchainCreate(1);
    chain->sum_line_state_size = controller->lstate_size;
    controller->chain          = chain;
    tunnelchainFinalize(chain);
    line_t *line = lineCreate(tunnelchainGetLinePools(chain), 0);
    bool    tcp =
        source == kDestinationMode ? mode == kUserControllerPayloadStream : mode == kUserControllerPayloadDatagram;
    lineGetDestinationAddressContext(line)->proto_tcp = tcp;
    lineGetDestinationAddressContext(line)->proto_udp = ! tcp;
    observed_controller                               = controller;
    owner_endpoint                                    = NULL;
    expected_mode = resolved_mode = mode;
    resolver_calls = init_calls = admissions = releases = prev_finishes = next_finishes = 0;
    if (reverse)
        tunnelDownStreamInit(controller, line);
    else
        tunnelUpStreamInit(controller, line);
    usercontroller_lstate_t *ls = lineGetState(line, controller);
    require(init_calls == 1 && resolver_calls == (unsigned) (source == kCreatorMode) &&
                ls->started_from_next == reverse,
            "Init direction or resolver count changed");
    require(! ls->managed && ls->payload_mode == mode && admissions == 0, "anonymous Init lost saved mode");
    resolved_mode =
        mode == kUserControllerPayloadStream ? kUserControllerPayloadDatagram : kUserControllerPayloadStream;
    lineGetDestinationAddressContext(line)->proto_tcp  = ! lineGetDestinationAddressContext(line)->proto_tcp;
    lineGetDestinationAddressContext(line)->proto_udp  = ! lineGetDestinationAddressContext(line)->proto_udp;
    lineGetDestinationAddressContext(line)->proto_icmp = true;
    const user_handle_t handle                         = {.generation = 1, .user_id = 42};
    lineAddUser(line, &handle, NULL, NULL);
    require(usercontrollerTunnelTryManageLine(controller, line) == kUserAdmissionOk && ls->managed,
            "late authenticated promotion failed");
    require(ls->payload_mode == mode && resolver_calls == (unsigned) (source == kCreatorMode) && admissions == 1,
            "late promotion or mutable destination changed saved framing");
    if (reverse)
        tunnelDownStreamFin(controller, line);
    else
        tunnelUpStreamFin(controller, line);
    require(lineIsAlive(line) && releases == 1, "borrower destroyed line or failed to release promotion");
    lineDestroy(line);
    tunnelchainDestroy(chain);
    tunnelDestroy(prev);
    tunnelDestroy(next);
    destroyController(&node, controller);
}

static void testRejectedDestination(bool reverse, unsigned protocols)
{
    node_t    node;
    tunnel_t *controller = createController(&node, ",\"payload-mode\":\"dest_context->protocol\"");
    require(controller != NULL && prepare(controller), "destination-mode controller preparation");
    tunnel_t *prev = tunnelCreate(NULL, 0, 0), *next = tunnelCreate(NULL, 0, 0);
    require(prev != NULL && next != NULL, "endpoint fixture allocation");
    prev->fnInitD = next->fnInitU = initialized;
    prev->fnFinD = next->fnFinU = finished;
    tunnelBind(prev, controller);
    tunnelBind(controller, next);
    tunnel_chain_t *chain      = tunnelchainCreate(1);
    chain->sum_line_state_size = controller->lstate_size;
    controller->chain          = chain;
    tunnelchainFinalize(chain);
    line_t            *line = lineCreate(tunnelchainGetLinePools(chain), 0);
    address_context_t *dest = lineGetDestinationAddressContext(line);
    dest->proto_tcp         = (protocols & 1U) != 0;
    dest->proto_udp         = (protocols & 2U) != 0;
    dest->proto_icmp        = (protocols & 4U) != 0;
    dest->proto_packet      = (protocols & 8U) != 0;
    // A valid source protocol must not replace absent/unsupported destination metadata.
    addresscontextSetOnlyProtocol(lineGetSourceAddressContext(line), IPPROTO_TCP);
    const user_handle_t handle = {.generation = 1, .user_id = 42};
    lineAddUser(line, &handle, NULL, NULL);
    observed_controller = controller;
    owner_endpoint      = reverse ? next : prev;
    resolver_calls = init_calls = admissions = releases = prev_finishes = next_finishes = 0;
    // Rejection may synchronously destroy the owner's line; retain only its allocation for checks.
    lineRef(line);
    if (reverse)
        tunnelDownStreamInit(controller, line);
    else
        tunnelUpStreamInit(controller, line);
    require(! lineIsAlive(line), "rejected line did not reach its owner");
    require(prev_finishes == (unsigned) ! reverse && next_finishes == (unsigned) reverse,
            "destination-mode rejection notified the uninitialized side");
    require(init_calls == 0 && admissions == 0 && releases == 0 && resolver_calls == 0,
            "invalid destination admitted a user or forwarded Init");
    usercontroller_tstate_t *ts = tunnelGetState(controller);
    require(ts->worker_states[0].line_count == 0, "invalid destination acquired a sweep reference");
    lineUnref(line);
    owner_endpoint = NULL;
    tunnelchainDestroy(chain);
    tunnelDestroy(prev);
    tunnelDestroy(next);
    destroyController(&node, controller);
}

int main(void)
{
    testCaseSet("usercontroller_payload_mode_test");
    static char            off[]        = "OFF";
    ww_construction_data_t data         = {0};
    data.workers_count                  = 1;
    data.ram_profile                    = kRamProfileS1Memory;
    data.mtu_size                       = 1500;
    data.internal_logger_data.log_level = data.core_logger_data.log_level = off;
    data.network_logger_data.log_level = data.dns_logger_data.log_level = off;
    require(wwStartupSucceeded(createGlobalState(data)), "initialize runtime");
    auth_node = (node_t) {.name = (char *) "auth-client", .hash_type = calcHashBytes("AuthenticationClient", 20)};
    auth_node.instance = tunnelCreate(NULL, 0, 0);
    require(auth_node.instance != NULL, "authentication metadata fixture");
    testConfigurationRefusals();
    for (unsigned reverse = 0; reverse < 2; ++reverse)
    {
        for (unsigned source = kFixedMode; source <= kDestinationMode; ++source)
            for (unsigned datagram = 0; datagram < 2; ++datagram)
                testSavedMode(reverse,
                              (mode_source_t) source,
                              datagram ? kUserControllerPayloadDatagram : kUserControllerPayloadStream);
        for (unsigned protocols = 0; protocols < 16; ++protocols)
            if (protocols != 1 && protocols != 2)
                testRejectedDestination(reverse, protocols);
    }
    tunnelDestroy(auth_node.instance);
    worker_t                     *worker  = getWorker(0);
    const ww_lifecycle_context_t *context = wwLifecycleProcessShutdown();
    require(workerInstallApplicationQuiesceRequest(worker, context) != kWorkerQuiesceRequestUnavailable, "quiesce");
    workerPerformQuiesce(worker, context);
    require(workerRequestDrain(worker), "request drain");
    workerPerformDrain(worker, context);
    require(workerRequestTeardown(worker), "request teardown");
    workerPerformTeardown(worker);
    destroyGlobalState();
    puts("UserController explicit and saved payload modes passed");
    return 0;
}

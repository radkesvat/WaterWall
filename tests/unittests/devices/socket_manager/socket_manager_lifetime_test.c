/*
 * Covers: socket manager lifetime; the explicit inputs, callbacks and expected results below define this
 * suite.
 * Setup: The included implementation/API and the deterministic inputs shown below; no integration
 * topology is implied.
 * Cases: registration and construction failures; endpoint sharing, registry growth,
 * setup failure, retirement and delivery settlement.
 * Checks: Assertion labels include: manager mutex acquisition/destruction is unbalanced; real manager
 * create failed; successful create did not publish the singleton; successful create did not acquire
 * exactly one manager mutex
 * Limits: Platform/feature branches remain conditional. Component fixtures do not establish host-network
 * or application-throughput behavior.
 * CTest: waterwall.socket_manager_lifetime_unit
 */
#include "wwapi.h"

#include "test_assert.h"

#define require(condition, message) TEST_REQUIRE(TEST_FAILURE_EXIT, condition, message)

#include "fixtures/assertions.h"
#include "fixtures/worker_lines.h"
#include "socket_manager.h"

/* Drive the private ownership/delivery paths in the real implementation without
 * adding production accessors or a second inventory for these tests. */
#include "socket_manager.c"

static bool         g_fail_endpoint_metadata;
static bool         g_fail_send_buffer;
static int          g_watched_fd = -1;
static unsigned int g_watched_closes;
static unsigned int g_deliveries;
static unsigned int g_idle_drains;

void *__real_memoryAllocateZero(size_t size);
int   __real_setsockopt(int fd, int level, int name, const void *value, socklen_t length);
int   __real_close(int fd);
void *__wrap_memoryAllocateZero(size_t size);
int   __wrap_setsockopt(int fd, int level, int name, const void *value, socklen_t length);
int   __wrap_close(int fd);

void *__wrap_memoryAllocateZero(size_t size)
{
    if (g_fail_endpoint_metadata && size == sizeof(listener_endpoint_t))
    {
        g_fail_endpoint_metadata = false;
        return NULL;
    }
    return __real_memoryAllocateZero(size);
}

int __wrap_setsockopt(int fd, int level, int name, const void *value, socklen_t length)
{
    if (g_fail_send_buffer && level == SOL_SOCKET && name == SO_SNDBUF)
    {
        g_fail_send_buffer = false;
        errno              = EACCES;
        return -1;
    }
    return __real_setsockopt(fd, level, name, value, length);
}

int __wrap_close(int fd)
{
    if (fd == g_watched_fd)
        ++g_watched_closes;
    return __real_close(fd);
}

static void onUnexpectedDelivery(wevent_t *event)
{
    discard event;
    ++g_deliveries;
}

static void onIdleDrain(local_idle_item_t *item)
{
    discard item;
    ++g_idle_drains;
}

static bool     g_fail_sync_init;
static bool     g_fail_after_mutex;
static bool     g_fail_filter_publication;
static uint32_t g_sync_acquired;
static uint32_t g_sync_destroyed;
static uint32_t g_unpublished_options_released;

bool socketManagerConstructorTestFailAfterMutex(void);
bool socketManagerRegistrationTestFailPublication(void);
void socketManagerRegistrationTestUnpublishedOptionReleased(void);
void socketManagerRegistrationTestSetStarted(bool started);

bool wSyncInitTestShouldFail(void)
{
    const bool fail  = g_fail_sync_init;
    g_fail_sync_init = false;
    return fail;
}

void wSyncInitTestResourceAcquired(void)
{
    ++g_sync_acquired;
}

void wSyncInitTestResourceDestroyed(void)
{
    ++g_sync_destroyed;
}

bool socketManagerConstructorTestFailAfterMutex(void)
{
    const bool fail    = g_fail_after_mutex;
    g_fail_after_mutex = false;
    return fail;
}

bool socketManagerRegistrationTestFailPublication(void)
{
    const bool fail           = g_fail_filter_publication;
    g_fail_filter_publication = false;
    return fail;
}

void socketManagerRegistrationTestUnpublishedOptionReleased(void)
{
    ++g_unpublished_options_released;
}


static void requireBalanced(void)
{
    require(g_sync_acquired == g_sync_destroyed, "manager mutex acquisition/destruction is unbalanced");
}

static socket_filter_option_t createOwnedFilterOption(bool with_balance_group)
{
    socket_filter_option_t option;
    socketfilteroptionInit(&option);
    option.host           = (char *) "127.0.0.1";
    option.protocol       = IPPROTO_TCP;
    option.port_min       = 4321;
    option.port_max       = 4321;
    option.interface_name = stringDuplicate("loopback-test");
    require(option.interface_name != NULL, "failed to allocate filter interface name");
    if (with_balance_group)
    {
        option.balance_group_name = stringDuplicate("late-registration-test");
        require(option.balance_group_name != NULL, "failed to allocate filter balance-group name");
    }
    require(vec_listener_port_t_push(&option.ports, option.port_min) != NULL,
            "failed to populate owned filter port vector");
    return option;
}

static ww_startup_result_t registerFilterOption(socket_filter_option_t option)
{
    ww_startup_context_t startup = {0};
    wwStartupContextBegin(&startup);
    socketacceptorRegister(NULL, option, NULL);
    return wwStartupContextEnd(&startup);
}

static socket_filter_t endpointFilter(uint8_t protocol, const char *scope)
{
    socket_filter_t filter = {0};
    socketfilteroptionInit(&filter.option);
    filter.option.host           = (char *) "127.0.0.1";
    filter.option.protocol       = protocol;
    filter.option.interface_name = scope == NULL ? NULL : stringDuplicate(scope);
    return filter;
}

static void caseEndpointSharing(twf_worker_env_t *env)
{
    ww_startup_context_t setup = {0};
    wwStartupContextBegin(&setup);
    require(socketmanagerCreate() != NULL, "endpoint fixture manager construction failed");
    endpoint_registry_t *endpoints = &socketmanager_gstate->endpoints;
    socket_filter_t      tcp       = endpointFilter(IPPROTO_TCP, socketOptionBindToDeviceSupported() ? "lo" : NULL);
    listener_endpoint_t *first =
        createTcpListener(env->loop, &tcp, tcp.option.host, 0, endpoints, onAcceptTcpSinglePort);
    require(first != NULL && first->port != 0, "ephemeral endpoint did not record its physical bound port");
    require(weventGetUserdata(first->listen_io) == first, "TCP listener userdata is not its endpoint");
    require(endpointRegistryFind(endpoints, IPPROTO_TCP, &tcp, first->port) == first, "exact endpoint sharing failed");
    listenTcpSinglePort(env->loop, &tcp, tcp.option.host, first->port, endpoints);
    require(endpoint_registry_t_size(endpoints) == 1, "TCP duplicate acquired a second socket owner");
    if (socketOptionBindToDeviceSupported())
    {
        require(first->interface_scope != tcp.option.interface_name, "endpoint borrowed creator scope storage");
        char *scope               = tcp.option.interface_name;
        tcp.option.interface_name = NULL;
        require(endpointRegistryFind(endpoints, IPPROTO_TCP, &tcp, first->port) == NULL,
                "unrestricted physical socket was equated with a scoped endpoint");
        tcp.option.interface_name = scope;
    }
    socketfilteroptionDeInit(&tcp.option);
    if (socketOptionBindToDeviceSupported())
        require(strcmp(first->interface_scope, "lo") == 0, "endpoint scope did not survive creator cleanup");

    socket_filter_t      udp = endpointFilter(IPPROTO_UDP, NULL);
    listener_endpoint_t *datagram =
        createUdpListener(env->loop, &udp, udp.option.host, 0, endpoints, onUdpPacketReceived, false);
    require(datagram != NULL, "UDP endpoint construction failed");
    udpsock_t *socket = datagram->udp_socket;
    require(socket->owner_slot == &datagram->listen_io && socket->io == datagram->listen_io,
            "UDP endpoint lacks one authoritative WIO slot");
    require(weventGetUserdata(socket->io) == datagram, "UDP userdata is not its endpoint");
    listenUdpSinglePort(env->loop, &udp, udp.option.host, datagram->port, endpoints);
    require(endpoint_registry_t_size(endpoints) == 2, "UDP duplicate acquired a second inventory");
    socket_filter_t mapped = endpointFilter(IPPROTO_TCP, socketOptionBindToDeviceSupported() ? "lo" : NULL);
    mapped.option.host     = (char *) "::ffff:127.0.0.1";
    require(endpointRegistryFind(endpoints, IPPROTO_TCP, &mapped, first->port) == NULL,
            "physical sharing ignored distinct socket families for equivalent IPs");
    socketfilteroptionDeInit(&mapped.option);
    socket_filter_t wildcard = endpointFilter(IPPROTO_TCP, NULL);
    wildcard.option.host     = (char *) "0.0.0.0";
    listener_endpoint_t *broad =
        createTcpListener(env->loop, &wildcard, wildcard.option.host, 0, endpoints, onAcceptTcpSinglePort);
    require(broad != NULL, "wildcard deferral fixture failed");
    mapped             = endpointFilter(IPPROTO_TCP, NULL);
    mapped.option.host = (char *) "::ffff:127.0.0.1";
    require(tcpBindDefersToExisting(endpoints, &mapped, broad->port), "mapped IPv4 filter lost wildcard deferral");
    socketfilteroptionDeInit(&mapped.option);
    socketfilteroptionDeInit(&wildcard.option);
    udp.option.send_buffer_size = 4096;
    ensureUdpSharedEndpointCompatible(datagram, &udp, udp.option.host, datagram->port);
    require(datagram->send_buffer_size == 0, "UDP sharing changed first-socket buffer settings");
    udp.option.fwmark = 0;
    require(wwStartupSucceeded(wwStartupContextEnd(&setup)), "initial endpoint setup failed");
    ww_startup_context_t startup = {0};
    wwStartupContextBegin(&startup);
    ensureUdpSharedEndpointCompatible(datagram, &udp, udp.option.host, datagram->port);
    require(! wwStartupSucceeded(wwStartupContextEnd(&startup)), "UDP mark conflict was accepted");
    wwStartupContextBegin(&setup);
    udp.option.fwmark = -1;

    workerMessagesCleanupPending(&env->worker);
    socketmanagerQuiesceWorker(0);
    socketfilteroptionDeInit(&udp.option);
    socketmanagerDestroy();
    require(wwStartupSucceeded(wwStartupContextEnd(&setup)), "endpoint sharing setup failed");
}

static void caseEndpointRegistryGrowth(twf_worker_env_t *env)
{
    ww_startup_context_t setup = {0};
    wwStartupContextBegin(&setup);
    require(socketmanagerCreate() != NULL, "registry growth manager construction failed");
    endpoint_registry_t *endpoints = &socketmanager_gstate->endpoints;
    socket_filter_t      tcp       = endpointFilter(IPPROTO_TCP, socketOptionBindToDeviceSupported() ? "lo" : NULL);
    socket_filter_t      udp       = endpointFilter(IPPROTO_UDP, NULL);
    listener_endpoint_t *first =
        createTcpListener(env->loop, &tcp, tcp.option.host, 0, endpoints, onAcceptTcpSinglePort);
    listener_endpoint_t *datagram =
        createUdpListener(env->loop, &udp, udp.option.host, 0, endpoints, onUdpPacketReceived, false);
    require(first != NULL && datagram != NULL, "registry growth endpoints failed");
    udpsock_t *socket = datagram->udp_socket;

    /* Force collection reallocations after WIO userdata and the UDP owner slot
     * have escaped. Each ephemeral bind is exclusive and uses no fixed host port. */
    for (int i = 0; i < 32; ++i)
        require(createTcpListener(env->loop, &tcp, tcp.option.host, 0, endpoints, onAcceptTcpSinglePort) != NULL,
                "endpoint growth bind failed");
    require(*endpoint_registry_t_at(endpoints, 0) == first && *endpoint_registry_t_at(endpoints, 1) == datagram,
            "endpoint objects moved during registry growth");
    require(weventGetUserdata(first->listen_io) == first && socket->owner_slot == &datagram->listen_io,
            "registry growth invalidated callback or owner pointers");

    workerMessagesCleanupPending(&env->worker);
    socketmanagerQuiesceWorker(0);
    socketfilteroptionDeInit(&tcp.option);
    socketfilteroptionDeInit(&udp.option);
    socketmanagerDestroy();
    require(wwStartupSucceeded(wwStartupContextEnd(&setup)), "registry growth setup failed");
}

static void caseEndpointSetupFailure(twf_worker_env_t *env)
{
    ww_startup_context_t setup = {0};
    wwStartupContextBegin(&setup);
    require(socketmanagerCreate() != NULL, "setup failure manager construction failed");
    endpoint_registry_t *endpoints = &socketmanager_gstate->endpoints;
    socket_filter_t      tcp       = endpointFilter(IPPROTO_TCP, NULL);
    socket_filter_t      udp       = endpointFilter(IPPROTO_UDP, NULL);
    listener_endpoint_t *first =
        createTcpListener(env->loop, &tcp, tcp.option.host, 0, endpoints, onAcceptTcpSinglePort);
    listener_endpoint_t *datagram =
        createUdpListener(env->loop, &udp, udp.option.host, 0, endpoints, onUdpPacketReceived, false);
    require(first != NULL && datagram != NULL, "setup failure baseline endpoints failed");
    require(wwStartupSucceeded(wwStartupContextEnd(&setup)), "setup failure baseline failed");

    isize_t count                = endpoint_registry_t_size(endpoints);
    g_fail_endpoint_metadata     = true;
    ww_startup_context_t startup = {0};
    wwStartupContextBegin(&startup);
    require(createUdpListener(env->loop, &udp, udp.option.host, 0, endpoints, onUdpPacketReceived, false) == NULL,
            "endpoint metadata failure was ignored");
    require(! wwStartupSucceeded(wwStartupContextEnd(&startup)), "metadata failure did not fail startup");
    wwStartupContextBegin(&setup);
    require(endpoint_registry_t_size(endpoints) == count && ! wioIsClosed(first->listen_io) &&
                ! wioIsClosed(datagram->listen_io),
            "metadata failure lost earlier successful ownership");
    require(createTcpListener(env->loop, &tcp, (char *) "192.0.2.200", 0, endpoints, onAcceptTcpSinglePort) == NULL,
            "unassigned bind unexpectedly succeeded");
    require(endpoint_registry_t_size(endpoints) == count, "failed bind published a phantom endpoint");

    workerMessagesCleanupPending(&env->worker);
    socketmanagerQuiesceWorker(0);
    socketfilteroptionDeInit(&tcp.option);
    socketfilteroptionDeInit(&udp.option);
    socketmanagerDestroy();
    require(wwStartupSucceeded(wwStartupContextEnd(&setup)), "endpoint setup failure cleanup failed");
}

static void caseEndpointRetirement(twf_worker_env_t *env)
{
    ww_startup_context_t setup = {0};
    wwStartupContextBegin(&setup);
    require(socketmanagerCreate() != NULL, "retirement manager construction failed");
    endpoint_registry_t *endpoints = &socketmanager_gstate->endpoints;
    socket_filter_t      udp       = endpointFilter(IPPROTO_UDP, NULL);
    listener_endpoint_t *datagram =
        createUdpListener(env->loop, &udp, udp.option.host, 0, endpoints, onUdpPacketReceived, false);
    require(datagram != NULL, "retirement endpoint failed");
    listenUdpSinglePort(env->loop, &udp, udp.option.host, datagram->port, endpoints);
    require(endpoint_registry_t_size(endpoints) == 1, "retirement duplicate acquired a second inventory");
    udpsock_t *socket = datagram->udp_socket;
    g_idle_drains     = 0;

    local_idle_table_t *table = udpsockGetWorkerIdleTable(socket);
    require(localidletableCreateItem(table, 123, NULL, onIdleDrain, 1000) != NULL, "UDP inventory fixture failed");
    g_watched_fd     = socket->listener_fd;
    g_watched_closes = 0;
    wioClose(socket->io);
    require(udpsockIsRetired(socket) && socket->io == NULL && datagram->listen_io == NULL,
            "UDP close failed to retire and clear authoritative slots");
    socketmanagerCloseListenersForLoop(env->loop);
    socketmanagerCloseListenersForLoop(env->loop);
    require(g_watched_closes == 1, "shared UDP endpoint closed more than once");
    g_watched_fd = -1;
    socketmanagerDrainUdpIdleForWorker(0);
    socketmanagerDrainUdpIdleForWorker(0);
    require(g_idle_drains == 1 && socket->idle_tables[0] == NULL, "shared UDP inventory drained more than once");

    /* A queued ingress that loses the retirement race must settle its buffer
     * without entering a listener or borrowing a foreign pool. */
    udp_payload_t *payload = threadsafegenericpoolGetItem(socketmanager_gstate->udp_pools[0]);
    *payload               = (udp_payload_t) {.sock = socket, .wid = 0, .buf = bufferpoolGetLargeBuffer(env->pool)};
    runUdpPayloadCallback(&env->worker, &(socket_filter_t) {.cb = onUnexpectedDelivery}, payload, NULL);
    require(g_deliveries == 0, "retired UDP ingress entered a listener");
    twfRequireNoLeakedBuffers();

    workerMessagesCleanupPending(&env->worker);
    socketmanagerQuiesceWorker(0);
    socketfilteroptionDeInit(&udp.option);
    socketmanagerDestroy();
    require(wwStartupSucceeded(wwStartupContextEnd(&setup)), "endpoint retirement setup failed");
}

static void caseDeliverySettlement(twf_worker_env_t *env)
{
    ww_startup_context_t setup = {0};
    wwStartupContextBegin(&setup);
    require(socketmanagerCreate() != NULL, "delivery fixture manager construction failed");
    socket_filter_option_t option;
    socketfilteroptionInit(&option);
    option.host     = (char *) "127.0.0.1";
    option.protocol = IPPROTO_TCP;
    option.port_min = option.port_max = 443;
    option.send_buffer_size           = 4096;
    option.balance_group_name         = stringDuplicate("delivery-test");
    socketacceptorRegister(NULL, option, onUnexpectedDelivery);
    socket_filter_t *chosen = *filters_t_at(&socketmanager_gstate->filters[1], 0);
    computeFilterBindEndpoint(chosen);
    require(chosen->balance_table != NULL, "manager did not create private balancing state");
    listener_endpoint_t endpoint = {0};
    listener_arrival_t  input    = {.endpoint = &endpoint, .protocol = IPPROTO_TCP, .local_port = 443};
    require(ipaddr_aton("127.0.0.1", &input.local_addr) != 0, "local IP fixture failed");
    require(ipaddr_aton("192.0.2.1", &input.peer_addr) != 0, "peer IP fixture failed");
    wio_t *io = wioCreateSocket(env->loop, "192.0.2.1", 1234, WIO_TYPE_TCP, WIO_CLIENT_SIDE);
    require(io != NULL, "accepted WIO fixture failed");
    weventSetUserData(io, &endpoint);
    g_watched_fd       = wioGetFD(io);
    g_watched_closes   = 0;
    g_fail_send_buffer = true;
    distributeTcpSocket(io, 443, &input.local_addr);
    require(! g_fail_send_buffer && g_watched_closes == 1 && g_deliveries == 0,
            "TCP option failure did not close exactly once without delivery");
    hash_t key = socketManagerArrivalBalanceHash(&input, kDispatchTierExact);
    require(idletableGetIdleItemByHash(0, chosen->balance_table, key) == NULL,
            "TCP option failure committed a new sticky target");
    g_watched_fd = -1;

    /* Real posting APIs exercise immediate rejection and accepted cancellation. */
    for (int queued = 0; queued < 2; ++queued)
    {
        if (queued)
            require(workerMessagesOpenAdmission(&env->worker), "message admission did not reopen");
        io = wioCreateSocket(env->loop, "192.0.2.1", 1234, WIO_TYPE_TCP, WIO_CLIENT_SIDE);
        require(io != NULL, "dispatch WIO fixture failed");
        g_watched_fd     = wioGetFD(io);
        g_watched_closes = 0;
        distributeSocket(io, chosen, 443);
        if (queued)
        {
            require(g_watched_closes == 0, "queued WIO was settled before cancellation");
            workerMessagesCloseAdmission(&env->worker);
            workerMessagesCleanupPending(&env->worker);
        }
        require(g_watched_closes == 1 && g_deliveries == 0, "TCP dispatch did not settle once on refusal/cancellation");
        g_watched_fd = -1;

        if (queued)
            require(workerMessagesOpenAdmission(&env->worker), "UDP admission did not reopen");
        udpsock_t socket = {0};
        atomic_init(&socket.retired, false);
        udp_payload_t payload = {.sock = &socket, .wid = 0, .buf = bufferpoolGetLargeBuffer(env->pool)};
        postUdpPayload(payload, chosen);
        if (queued)
        {
            workerMessagesCloseAdmission(&env->worker);
            workerMessagesCleanupPending(&env->worker);
        }
        twfRequireNoLeakedBuffers();
        require(g_deliveries == 0, "UDP canceled dispatch entered a listener");
    }
    socketmanagerQuiesceWorker(0);
    socketmanagerDestroy();
    require(wwStartupSucceeded(wwStartupContextEnd(&setup)), "delivery settlement setup failed");
}

int main(void)
{
    testCaseSet("socket_manager_lifetime_test");
    worker_t workers[2];
    memoryZero(workers, sizeof(workers));
    workers[0].wid            = 0;
    workers[0].has_event_loop = true;
    workers[1].wid            = 1;

    GSTATE.flag_initialized = true;
    GSTATE.workers          = workers;
    GSTATE.workers_count    = ARRAY_SIZE(workers) - 1U;
    GSTATE.ram_profile      = 1;
    testWorkerBindWID(0);

    require(socketmanagerCreate() != NULL, "real manager create failed");
    require(socketmanagerGet() != NULL, "successful create did not publish the singleton");
    require(g_sync_acquired == 1 && g_sync_destroyed == 0,
            "successful create did not acquire exactly one manager mutex");

    socketManagerRegistrationTestSetStarted(true);
    require(! wwStartupSucceeded(registerFilterOption(createOwnedFilterOption(true))),
            "late filter registration did not fail startup");
    socketManagerRegistrationTestSetStarted(false);
    require(g_unpublished_options_released == 1, "late filter registration did not release its transferred option");

    g_fail_filter_publication = true;
    require(! wwStartupSucceeded(registerFilterOption(createOwnedFilterOption(false))),
            "refused filter publication did not fail startup");
    require(g_unpublished_options_released == 2, "refused filter publication did not release its copied option");

    require(wwStartupSucceeded(registerFilterOption(createOwnedFilterOption(false))),
            "valid filter registration failed");
    require(g_unpublished_options_released == 2, "successful filter registration released manager-owned options early");

    socketmanagerDestroy();
    require(socketmanagerGet() == NULL, "destroy did not clear the singleton");
    requireBalanced();

    require(socketmanagerCreate() != NULL, "manager was not recreatable after destroy");
    socketmanagerDestroy();
    require(g_sync_acquired == 2 && g_sync_destroyed == 2,
            "create/destroy/create did not balance manager mutex resources");

    g_fail_sync_init = true;
    require(socketmanagerCreate() == NULL, "manager accepted a refused mutex construction");
    require(socketmanagerGet() == NULL, "mutex failure published the singleton");
    require(g_sync_acquired == 2 && g_sync_destroyed == 2,
            "mutex failure acquired or destroyed a nonexistent resource");

    g_fail_after_mutex = true;
    require(socketmanagerCreate() == NULL, "manager accepted the first post-mutex constructor failure");
    require(socketmanagerGet() == NULL, "post-mutex failure published the singleton");
    require(g_sync_acquired == 3 && g_sync_destroyed == 3,
            "post-mutex failure did not destroy its acquired resource exactly once");

    require(socketmanagerCreate() != NULL, "post-mutex failure made the manager non-retryable");
    socketmanagerDestroy();
    require(g_sync_acquired == 4 && g_sync_destroyed == 4, "final manager retry leaked its synchronization resource");

    testWorkerUnbindWID();
    GSTATE.flag_initialized = false;
    GSTATE.workers          = NULL;
    GSTATE.workers_count    = 0;

    twf_worker_env_t env;
    twfWorkerEnvSetup(&env, 8192, 0);
    mutexInit(&env.worker.control_mutex);
    require(workerMessagesInit(&env.worker), "message queue construction failed");
    require(globalstateInitializeSecureRandom() && frandGlobalInit(), "random fixture initialization failed");
    frandInit();
    testCaseSet("socket_manager_endpoint_sharing");
    caseEndpointSharing(&env);
    testCaseSet("socket_manager_endpoint_registry_growth");
    caseEndpointRegistryGrowth(&env);
    testCaseSet("socket_manager_endpoint_setup_failure");
    caseEndpointSetupFailure(&env);
    testCaseSet("socket_manager_endpoint_retirement");
    caseEndpointRetirement(&env);
    testCaseSet("socket_manager_delivery_settlement");
    caseDeliverySettlement(&env);
    workerMessagesDestroy(&env.worker);
    mutexDestroy(&env.worker.control_mutex);
    frandThreadCleanup();
    frandGlobalCleanup();
    twfWorkerEnvTeardown(&env);
    requireBalanced();

    puts("socket_manager_lifetime_test: all cases passed");
    return 0;
}

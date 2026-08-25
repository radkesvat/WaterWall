#include "UdpListener/structure.h"

#include "managers/socket_manager.h"
#include "socket_filter_option.h"

enum
{
    kAclCopyItems = 12,
};

static uint32_t g_fail_reserve_on_copy;

#if defined(OS_LINUX)
static uint32_t g_registration_calls;
static uint32_t g_option_deinit_calls;
static uint32_t g_tunnel_destroy_calls;
static uint32_t g_registered_whitelist_size;
static uint32_t g_registered_blacklist_size;
static bool     g_registered_has_interface;

void __real_socketfilteroptionDeInit(socket_filter_option_t *option);
void __real_tunnelDestroy(tunnel_t *t);
void __wrap_socketfilteroptionDeInit(socket_filter_option_t *option);
void __wrap_tunnelDestroy(tunnel_t *t);
void __wrap_socketacceptorRegister(tunnel_t *tunnel, socket_filter_option_t option, onAccept callback);

void __wrap_socketfilteroptionDeInit(socket_filter_option_t *option)
{
    ++g_option_deinit_calls;
    __real_socketfilteroptionDeInit(option);
}

void __wrap_tunnelDestroy(tunnel_t *t)
{
    ++g_tunnel_destroy_calls;
    __real_tunnelDestroy(t);
}

void __wrap_socketacceptorRegister(tunnel_t *tunnel, socket_filter_option_t option, onAccept callback)
{
    discard tunnel;
    discard callback;

    ++g_registration_calls;
    g_registered_whitelist_size = (uint32_t) vec_ipmask_t_size(&option.white_list);
    g_registered_blacklist_size = (uint32_t) vec_ipmask_t_size(&option.black_list);
    g_registered_has_interface  = option.interface_name != NULL;

    /* The real SocketManager consumes these fields after registration. This
     * narrow replacement mirrors that transfer without publishing a global
     * filter during a constructor-only unit test. */
    socketfilteroptionDeInit(&option);
}
#endif

bool udplistenerTestFailAclCopyReserve(void)
{
    if (g_fail_reserve_on_copy == 0)
    {
        return false;
    }

    --g_fail_reserve_on_copy;
    return g_fail_reserve_on_copy == 0;
}

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "%s\n", message);
        exit(1);
    }
}

static ipmask_t parseMask(const char *text)
{
    ipmask_t mask = {0};
    require(parseIPWithSubnetMask(text, &mask.ip, &mask.mask) == 4, "failed to parse IPv4 ACL mask");
    return mask;
}

static ip_addr_t parseIp(const char *text)
{
    ip_addr_t ip = {.type = IPADDR_TYPE_V4};
    require(ip4AddrAddressToNetwork(text, &ip.u_addr.ip4) != 0, "failed to parse IPv4 address");
    return ip;
}

static void appendMasks(vec_ipmask_t *list, const char *prefix)
{
    for (uint32_t i = 0; i < kAclCopyItems; ++i)
    {
        char text[32] = {0};
        snprintf(text, sizeof(text), "%s.%u.0/24", prefix, (unsigned int) i);
        require(vec_ipmask_t_push(list, parseMask(text)) != NULL, "failed to populate ACL source vector");
    }
}

static void requireMasksEqual(const vec_ipmask_t *actual, const vec_ipmask_t *expected, const char *message)
{
    require(vec_ipmask_t_size(actual) == vec_ipmask_t_size(expected), message);
    for (isize_t i = 0; i < vec_ipmask_t_size(expected); ++i)
    {
        require(memoryCompare(vec_ipmask_t_at(actual, i), vec_ipmask_t_at(expected, i), sizeof(ipmask_t)) == 0,
                message);
    }
}

static cJSON *createListenerSettings(bool populate_white, bool populate_black)
{
    cJSON *settings = cJSON_CreateObject();
    require(settings != NULL, "failed to allocate listener settings JSON");
    cJSON_AddStringToObject(settings, "address", "127.0.0.1");
    cJSON_AddNumberToObject(settings, "port", 25123);
    cJSON_AddStringToObject(settings, "interface", "acl-copy-test");

    const char *names[]    = {"whitelist", "blacklist"};
    const char *prefixes[] = {"192.0", "198.51"};
    const bool  enabled[]  = {populate_white, populate_black};
    for (size_t list_index = 0; list_index < ARRAY_SIZE(names); ++list_index)
    {
        if (! enabled[list_index])
        {
            continue;
        }

        cJSON *list = cJSON_AddArrayToObject(settings, names[list_index]);
        require(list != NULL, "failed to allocate ACL settings list");
        for (uint32_t item = 0; item < kAclCopyItems; ++item)
        {
            char text[32] = {0};
            snprintf(text, sizeof(text), "%s.%u.0/24", prefixes[list_index], (unsigned int) item);
            cJSON_AddItemToArray(list, cJSON_CreateString(text));
        }
    }

    return settings;
}

static void testEmptyAclCopiesKeepInitializedStorage(void)
{
    socket_filter_option_t option;
    socketfilteroptionInit(&option);
    ipmask_t *const original_white = option.white_list.data;
    ipmask_t *const original_black = option.black_list.data;

    vec_ipmask_t empty = vec_ipmask_t_init();
    require(udplistenerTestCopyIpMaskList(&option.white_list, &empty), "empty whitelist copy failed");
    require(udplistenerTestCopyIpMaskList(&option.black_list, &empty), "empty blacklist copy failed");

    require(option.white_list.data == original_white, "empty whitelist copy replaced initialized storage");
    require(option.black_list.data == original_black, "empty blacklist copy replaced initialized storage");
    require(vec_ipmask_t_size(&option.white_list) == 0, "empty whitelist copy changed size");
    require(vec_ipmask_t_size(&option.black_list) == 0, "empty blacklist copy changed size");

    vec_ipmask_t_drop(&empty);
    socketfilteroptionDeInit(&option);
}

static void testAclCopiesGrowAndPreserveMatching(void)
{
    socket_filter_option_t option;
    socketfilteroptionInit(&option);

    vec_ipmask_t white = vec_ipmask_t_init();
    vec_ipmask_t black = vec_ipmask_t_init();
    appendMasks(&white, "192.0");
    appendMasks(&black, "198.51");

    require(udplistenerTestCopyIpMaskList(&option.white_list, &white), "grown whitelist copy failed");
    require(udplistenerTestCopyIpMaskList(&option.black_list, &black), "grown blacklist copy failed");
    require(vec_ipmask_t_capacity(&option.white_list) >= kAclCopyItems,
            "grown whitelist did not reserve complete source capacity");
    require(vec_ipmask_t_capacity(&option.black_list) >= kAclCopyItems,
            "grown blacklist did not reserve complete source capacity");
    requireMasksEqual(&option.white_list, &white, "grown whitelist content changed during copy");
    requireMasksEqual(&option.black_list, &black, "grown blacklist content changed during copy");
    require(socketManagerIpMatchesAcl(parseIp("192.0.7.1"), &option.white_list),
            "grown copied whitelist no longer matches its later entry");
    require(socketManagerIpMatchesAcl(parseIp("198.51.11.1"), &option.black_list),
            "grown copied blacklist no longer matches its later entry");

    socketfilteroptionDeInit(&option);
    vec_ipmask_t_drop(&white);
    vec_ipmask_t_drop(&black);
}

static void testAclCopyReserveFailureIsAtomic(void)
{
    socket_filter_option_t option;
    socketfilteroptionInit(&option);

    vec_ipmask_t source = vec_ipmask_t_init();
    appendMasks(&source, "203.0");

    g_fail_reserve_on_copy = 1;
    require(! udplistenerTestCopyIpMaskList(&option.white_list, &source), "injected ACL reserve failure was accepted");
    require(vec_ipmask_t_size(&option.white_list) == 0, "injected ACL reserve failure left a partial destination ACL");

    require(udplistenerTestCopyIpMaskList(&option.white_list, &source),
            "ACL copy did not remain retryable after reserve failure");
    requireMasksEqual(&option.white_list, &source, "ACL retry after reserve failure copied the wrong entries");

    socketfilteroptionDeInit(&option);
    vec_ipmask_t_drop(&source);
}

#if defined(OS_LINUX)
static worker_t g_workers[2];

static void installCreateWorkerContext(void)
{
    memoryZero(g_workers, sizeof(g_workers));
    g_workers[0].wid            = 0;
    g_workers[0].has_event_loop = true;
    g_workers[1].wid            = 1;

    GSTATE.flag_initialized = true;
    GSTATE.workers          = g_workers;
    GSTATE.workers_count    = ARRAY_SIZE(g_workers);
    testWorkerBindWID(0);
}

static void uninstallCreateWorkerContext(void)
{
    testWorkerUnbindWID();
    GSTATE.flag_initialized = false;
    GSTATE.workers          = NULL;
    GSTATE.workers_count    = 0;
}

static void resetCreateCounters(void)
{
    g_registration_calls        = 0;
    g_option_deinit_calls       = 0;
    g_tunnel_destroy_calls      = 0;
    g_registered_whitelist_size = 0;
    g_registered_blacklist_size = 0;
    g_registered_has_interface  = false;
    g_fail_reserve_on_copy      = 0;
}

static void testCreateRollsBackBothAclCopyFailureOrders(void)
{
    installCreateWorkerContext();

    for (uint32_t fail_copy = 1; fail_copy <= 2; ++fail_copy)
    {
        resetCreateCounters();
        g_fail_reserve_on_copy = fail_copy;

        cJSON *settings = createListenerSettings(true, true);
        node_t node     = {.node_settings_json = settings};
        require(udplistenerTunnelCreate(&node) == NULL, "ACL copy failure unexpectedly constructed UdpListener");
        require(g_registration_calls == 0, "ACL copy failure registered a partial SocketManager filter");
        require(g_option_deinit_calls == 1, "ACL copy failure did not release its unpublished filter option once");
        require(g_tunnel_destroy_calls == 1, "ACL copy failure did not destroy its unpublished listener once");
        cJSON_Delete(settings);
    }

    uninstallCreateWorkerContext();
}

static void testCreateDestroyEmptyAndPopulatedAcls(void)
{
    installCreateWorkerContext();

    for (uint32_t populated = 0; populated <= 1; ++populated)
    {
        resetCreateCounters();

        cJSON    *settings = createListenerSettings(populated != 0, populated != 0);
        node_t    node     = {.node_settings_json = settings};
        tunnel_t *t        = udplistenerTunnelCreate(&node);
        require(t != NULL, "valid ACL settings failed to construct UdpListener");
        require(g_registration_calls == 1, "valid ACL settings did not transfer one SocketManager option");
        require(g_option_deinit_calls == 1,
                "registered SocketManager option was not released exactly once by test owner");
        require(g_registered_has_interface, "registered option lost its duplicated interface string");
        require(g_registered_whitelist_size == (populated ? kAclCopyItems : 0),
                "registered whitelist count is incomplete");
        require(g_registered_blacklist_size == (populated ? kAclCopyItems : 0),
                "registered blacklist count is incomplete");

        udplistenerTunnelDestroy(t, wwLifecycleStartupRollback());
        require(g_tunnel_destroy_calls == 1, "valid listener destroy did not release its tunnel once");
        cJSON_Delete(settings);
    }

    uninstallCreateWorkerContext();
}
#endif

int main(void)
{
    testEmptyAclCopiesKeepInitializedStorage();
    testAclCopiesGrowAndPreserveMatching();
    testAclCopyReserveFailureIsAtomic();
#if defined(OS_LINUX)
    testCreateRollsBackBothAclCopyFailureOrders();
    testCreateDestroyEmptyAndPopulatedAcls();
#endif

    puts("udplistener_acl_copy_test: all cases passed");
    return 0;
}

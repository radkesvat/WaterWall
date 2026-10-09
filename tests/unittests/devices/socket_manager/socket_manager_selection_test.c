/*
 * Covers: the production shared TCP/UDP selector, independent of transport delivery.
 * Setup: real worker-zero loop, idle tables and random source; private logical filters.
 * Cases: interface eligibility, address tiers/mapped IPs, ACLs/ports/ties, mixed
 * balancing, first group/candidate limit, pending commit, expiry and stale targets.
 * Limits: physical binding and asynchronous ownership belong to the lifetime and
 * two-veth integration suites. CTest: waterwall.socket_manager_selection_unit.
 */
#include "fixtures/assertions.h"
#include "socket_manager_internal.h"
#include "wfrand.h"
#include "wwapi.h"

static ip_addr_t addr(const char *text)
{
    ip_addr_t value = {0};
    twfRequire(ipaddr_aton(text, &value) != 0, "test IP did not parse");
    return value;
}

static socket_filter_t filter(uint8_t protocol, const char *host, const char *scope)
{
    socket_filter_t value = {0};
    socketfilteroptionInit(&value.option);
    value.option.protocol       = protocol;
    value.option.port_min       = 443;
    value.option.port_max       = 443;
    value.option.interface_name = scope == NULL ? NULL : stringDuplicate(scope);
    value.bind_addr             = addr(host);
    value.bind_family           = value.bind_addr.type == IPADDR_TYPE_V6 ? AF_INET6 : AF_INET;
    normalizeIpAddr(&value.bind_addr);
    value.bind_is_wildcard    = ipAddrIsWildcard(&value.bind_addr);
    value.bind_endpoint_ready = true;
    return value;
}

static void add(filters_t filters[kFilterLevels], int level, socket_filter_t *value)
{
    twfRequire(filters_t_push(&filters[level], value) != NULL, "filter publication failed");
}

static void drop(filters_t filters[kFilterLevels])
{
    for (int level = 0; level < kFilterLevels; ++level)
        filters_t_drop(&filters[level]);
}

static void acl(vec_ipmask_t *list, const char *text)
{
    ipmask_t range = {0};
    twfRequire(parseIPWithSubnetMask(text, &range.ip, &range.mask) != IPADDR_TYPE_ANY, "test CIDR did not parse");
    twfRequire(vec_ipmask_t_push(list, range) != NULL, "test ACL allocation failed");
}

static listener_arrival_t arrival(listener_endpoint_t *endpoint, uint8_t protocol)
{
    return (listener_arrival_t) {.endpoint   = endpoint,
                                 .protocol   = protocol,
                                 .local_port = 443,
                                 .peer_addr  = addr("192.0.2.42"),
                                 .local_addr = addr("198.51.100.1")};
}

static void caseScope(uint8_t protocol)
{
    if (! socketOptionBindToDeviceSupported())
        return;
    filters_t           filters[kFilterLevels] = {0};
    listener_endpoint_t endpoint               = {.interface_scope = (char *) "eth0"};
    listener_arrival_t  input                  = arrival(&endpoint, protocol);
    socket_filter_t     wrong                  = filter(protocol, "0.0.0.0", "eth1");
    socket_filter_t     right                  = filter(protocol, "0.0.0.0", "eth0");
    socket_filter_t     unrestricted           = filter(protocol, "0.0.0.0", NULL);
    add(filters, 3, &wrong);
    add(filters, 1, &right);
    twfRequire(socketManagerSelect(filters, 0, &input).filter == &right, "higher-priority wrong scope won");
    endpoint.interface_scope = NULL;
    twfRequire(socketManagerSelect(filters, 0, &input).filter == NULL, "unknown scope satisfied a device restriction");
    endpoint.interface_scope = (char *) "eth0";
    add(filters, 2, &unrestricted);
    twfRequire(socketManagerSelect(filters, 0, &input).filter == &unrestricted, "scope introduced a new priority tier");
    filters_t_clear(&filters[2]);
    filters_t_clear(&filters[1]);
    add(filters, 1, &unrestricted);
    add(filters, 1, &right);
    twfRequire(socketManagerSelect(filters, 0, &input).filter == &unrestricted,
               "registration tie ignored unrestricted filter");
    drop(filters);
    socketfilteroptionDeInit(&wrong.option);
    socketfilteroptionDeInit(&right.option);
    socketfilteroptionDeInit(&unrestricted.option);
}

static void caseTiersAndPorts(uint8_t protocol)
{
    filters_t           filters[kFilterLevels] = {0};
    listener_endpoint_t endpoint               = {.port = 9000}; /* redirect's physical port */
    listener_arrival_t  input                  = arrival(&endpoint, protocol);
    socket_filter_t     dual                   = filter(protocol, "::", NULL);
    socket_filter_t     wildcard               = filter(protocol, "0.0.0.0", NULL);
    socket_filter_t     exact                  = filter(protocol, "::ffff:198.51.100.1", NULL);
    add(filters, 3, &dual);
    add(filters, 2, &wildcard);
    add(filters, 0, &exact);
    twfRequire(socketManagerSelect(filters, 0, &input).filter == &exact, "address tier lost to ACL/port priority");
    input.local_addr = addr("::ffff:198.51.100.1");
    input.peer_addr  = addr("::ffff:192.0.2.42");
    twfRequire(socketManagerSelect(filters, 0, &input).filter == &exact, "mapped arrival did not normalize");
    exact.option.port_min = exact.option.port_max = 444;
    twfRequire(socketManagerSelect(filters, 0, &input).filter == &wildcard, "dual wildcard won before family wildcard");
    wildcard.option.port_min = 400;
    wildcard.option.port_max = 500;
    twfRequire(vec_listener_port_t_push(&wildcard.option.ports, 444) != NULL, "port-list allocation failed");
    twfRequire(socketManagerSelect(filters, 0, &input).filter == &dual, "port list incorrectly fell back to range");
    twfRequire(vec_listener_port_t_push(&wildcard.option.ports, 443) != NULL, "port-list allocation failed");
    acl(&wildcard.option.white_list, "::ffff:192.0.2.0/120");
    acl(&wildcard.option.black_list, "192.0.2.99/32");
    twfRequire(socketManagerSelect(filters, 0, &input).filter == &wildcard, "mapped ACL or explicit port failed");
    input.peer_addr = addr("192.0.2.99");
    twfRequire(socketManagerSelect(filters, 0, &input).filter == &dual, "blacklist did not exclude whitelisted peer");
    input.peer_addr = addr("192.0.3.1");
    twfRequire(socketManagerSelect(filters, 0, &input).filter == &dual, "whitelist accepted another subnet");
    input.local_addr = addr("2001:db8::1");
    twfRequire(socketManagerSelect(filters, 0, &input).filter == &dual, "IPv6 family wildcard did not match");
    dual.option.protocol = protocol == IPPROTO_TCP ? IPPROTO_UDP : IPPROTO_TCP;
    twfRequire(socketManagerSelect(filters, 0, &input).filter == NULL, "protocol mismatch was selectable");
    drop(filters);
    socketfilteroptionDeInit(&dual.option);
    socketfilteroptionDeInit(&wildcard.option);
    socketfilteroptionDeInit(&exact.option);
}

static void caseBalancing(wloop_t *loop, uint8_t protocol)
{
    filters_t           filters[kFilterLevels] = {0};
    listener_endpoint_t endpoint               = {0};
    listener_arrival_t  input                  = arrival(&endpoint, protocol);
    idle_table_t       *first_group            = idleTableCreate(loop);
    idle_table_t       *other_group            = idleTableCreate(loop);
    socket_filter_t     first                  = filter(protocol, "0.0.0.0", NULL);
    socket_filter_t     second                 = filter(protocol, "0.0.0.0", NULL);
    socket_filter_t     other                  = filter(protocol, "0.0.0.0", NULL);
    socket_filter_t     immediate              = filter(protocol, "0.0.0.0", NULL);
    first.balance_table = second.balance_table = first_group;
    other.balance_table                        = other_group;
    add(filters, 2, &first);
    add(filters, 2, &other);
    add(filters, 1, &second);
    add(filters, 0, &immediate);
    twfRequire(socketManagerSelect(filters, 0, &input).filter == &immediate,
               "accumulated balanced candidates suppressed an unbalanced match");
    filters_t_clear(&filters[0]);
    listener_selection_t choice = socketManagerSelect(filters, 0, &input);
    twfRequire(choice.filter == &first || choice.filter == &second, "selector crossed the first balance group");
    twfRequire(choice.pending_sticky, "random choice did not carry a pending commit");
    twfRequire(idletableGetIdleItemByHash(0, first_group, choice.sticky_key) == NULL,
               "selector committed before transport setup succeeded");
    socketManagerCommitSelection(0, &choice);
    idle_item_t *item = idletableGetIdleItemByHash(0, first_group, choice.sticky_key);
    twfRequire(item != NULL && item->userdata == choice.filter, "commit did not record selected target");
    twfRequire(atomic_load(&item->expire_at_ms) == wloopNowMonotonicMS(loop) + kDefaultBalanceInterval,
               "default sticky interval changed");
    first.option.balance_group_interval = 120000;
    listener_selection_t cached         = socketManagerSelect(filters, 0, &input);
    twfRequire(cached.filter == choice.filter && ! cached.pending_sticky, "cached-hit short circuit changed");
    twfRequire(atomic_load(&item->expire_at_ms) == wloopNowMonotonicMS(loop) + 120000,
               "cached refresh did not use scanning filter interval");
    add(filters, 3, &immediate);
    twfRequire(socketManagerSelect(filters, 0, &input).filter == &immediate,
               "cache overrode earlier unbalanced filter");
    drop(filters);
    idletableDestroy(first_group);
    idletableDestroy(other_group);
    socketfilteroptionDeInit(&first.option);
    socketfilteroptionDeInit(&second.option);
    socketfilteroptionDeInit(&other.option);
    socketfilteroptionDeInit(&immediate.option);
}

static void caseCachedRevalidation(wloop_t *loop, uint8_t protocol)
{
    filters_t           filters[kFilterLevels] = {0};
    listener_endpoint_t endpoint               = {.interface_scope = (char *) "eth0"};
    listener_arrival_t  input                  = arrival(&endpoint, protocol);
    idle_table_t       *table                  = idleTableCreate(loop);
    socket_filter_t     good                   = filter(protocol, "0.0.0.0", NULL);
    socket_filter_t     bad                    = filter(protocol, "0.0.0.0", NULL);
    good.balance_table = bad.balance_table = table;
    add(filters, 1, &good);
    const hash_t key = socketManagerArrivalBalanceHash(&input, kDispatchTierWildcardFamily);
    for (int reason = 0; reason < 5; ++reason)
    {
        if (reason == 0 && ! socketOptionBindToDeviceSupported())
            continue;
        bad.option.interface_name = reason == 0 ? stringDuplicate("eth1") : NULL;
        bad.option.protocol       = reason == 1 ? (protocol == IPPROTO_TCP ? IPPROTO_UDP : IPPROTO_TCP) : protocol;
        bad.option.port_min = bad.option.port_max = reason == 2 ? 444 : 443;
        bad.bind_is_wildcard                      = reason != 3;
        if (reason == 4)
            acl(&bad.option.black_list, "192.0.2.0/24");
        twfRequire(idletableCreateItem(table, key, &bad, NULL, 0, 1000) != NULL, "incompatible cache injection failed");
        listener_selection_t choice = socketManagerSelect(filters, 0, &input);
        twfRequire(choice.filter == &good && choice.pending_sticky,
                   "incompatible cached target escaped eligibility revalidation");
        socketManagerCommitSelection(0, &choice); /* duplicate-key refusal retains delivery */
        twfRequire(socketManagerSelect(filters, 0, &input).filter == &good,
                   "commit refusal changed delivery eligibility");
        twfRequire(idletableRemoveIdleItemByHash(0, table, key), "cache removal failed");
        memoryFree(bad.option.interface_name);
        bad.option.interface_name = NULL;
    }
    drop(filters);
    idletableDestroy(table);
    socketfilteroptionDeInit(&good.option);
    socketfilteroptionDeInit(&bad.option);
}

static void caseCandidateLimit(wloop_t *loop)
{
    filters_t           filters[kFilterLevels] = {0};
    listener_endpoint_t endpoint               = {0};
    listener_arrival_t  input                  = arrival(&endpoint, IPPROTO_TCP);
    idle_table_t       *table                  = idleTableCreate(loop);
    socket_filter_t     candidates[kMaxBalanceSelections + 1];
    for (size_t i = 0; i < ARRAY_SIZE(candidates); ++i)
    {
        candidates[i]               = filter(IPPROTO_TCP, "0.0.0.0", NULL);
        candidates[i].balance_table = table;
        add(filters, 1, &candidates[i]);
    }
    for (int attempt = 0; attempt < 16; ++attempt)
    {
        socket_filter_t *choice = socketManagerSelect(filters, 0, &input).filter;
        twfRequire(choice >= candidates && choice < candidates + kMaxBalanceSelections, "candidate limit changed");
    }
    /* Historical cached hits are not subject to the random candidate cap. */
    hash_t key = socketManagerArrivalBalanceHash(&input, kDispatchTierWildcardFamily);
    twfRequire(idletableCreateItem(table, key, &candidates[kMaxBalanceSelections], NULL, 0, 1000) != NULL,
               "cached target injection failed");
    twfRequire(socketManagerSelect(filters, 0, &input).filter == &candidates[kMaxBalanceSelections],
               "candidate cap suppressed eligible cached target");
    drop(filters);
    idletableDestroy(table);
    for (size_t i = 0; i < ARRAY_SIZE(candidates); ++i)
        socketfilteroptionDeInit(&candidates[i].option);
}

static void caseKeyIsolation(void)
{
    listener_endpoint_t a     = {.interface_scope = (char *) "eth0"};
    listener_endpoint_t b     = {.interface_scope = (char *) "eth1"};
    listener_arrival_t  input = arrival(&a, IPPROTO_TCP);
    hash_t              key   = socketManagerArrivalBalanceHash(&input, kDispatchTierWildcardFamily);
    input.endpoint            = &b;
    twfRequire(socketManagerArrivalBalanceHash(&input, kDispatchTierWildcardFamily) != key,
               "scope did not isolate identical-address stickiness");
    input.endpoint = &a;
    input.protocol = IPPROTO_UDP;
    twfRequire(socketManagerArrivalBalanceHash(&input, kDispatchTierWildcardFamily) != key,
               "protocol did not isolate stickiness");
    input.protocol   = IPPROTO_TCP;
    input.peer_addr  = addr("::ffff:192.0.2.42");
    input.local_addr = addr("::ffff:198.51.100.1");
    twfRequire(socketManagerArrivalBalanceHash(&input, kDispatchTierWildcardFamily) == key,
               "equivalent mapped addresses changed sticky identity");
}

static void caseEffectiveInterfaceAddress(uint8_t protocol)
{
    if (socketOptionBindToDeviceSupported())
        return;
    filters_t           filters[kFilterLevels] = {0};
    listener_endpoint_t endpoint               = {0};
    listener_arrival_t  input                  = arrival(&endpoint, protocol);
    /* A non-device-binding platform resolves the interface to its bind IP.
     * The selector consumes that effective address, not a synthetic device ID. */
    socket_filter_t first  = filter(protocol, "198.51.100.1", "device-a");
    socket_filter_t second = filter(protocol, "198.51.100.2", "device-b");
    add(filters, 3, &second);
    add(filters, 0, &first);
    twfRequire(socketManagerSelect(filters, 0, &input).filter == &first,
               "interface fallback did not match effective bind IP");
    input.local_addr = addr("198.51.100.2");
    twfRequire(socketManagerSelect(filters, 0, &input).filter == &second,
               "interface fallback invented device-scope eligibility");
    drop(filters);
    socketfilteroptionDeInit(&first.option);
    socketfilteroptionDeInit(&second.option);
}

int main(void)
{
    twfSetCase("socket_manager_selection_test");
    worker_t worker         = {.wid = 0, .has_event_loop = true};
    GSTATE.flag_initialized = true;
    GSTATE.workers_count    = 1;
    GSTATE.workers          = &worker;
    testWorkerBindWID(0);
    wloop_t *loop         = wloopCreate(WLOOP_FLAG_AUTO_FREE, NULL, 0);
    worker.loop           = loop;
    GSTATE.shortcut_loops = &loop;
    twfRequire(globalstateInitializeSecureRandom() && frandGlobalInit(), "random initialization failed");
    frandInit();
    for (int i = 0; i < 2; ++i)
    {
        uint8_t protocol = i == 0 ? IPPROTO_TCP : IPPROTO_UDP;
        caseScope(protocol);
        caseEffectiveInterfaceAddress(protocol);
        caseTiersAndPorts(protocol);
        caseBalancing(loop, protocol);
        caseCachedRevalidation(loop, protocol);
    }
    caseCandidateLimit(loop);
    caseKeyIsolation();
    frandThreadCleanup();
    frandGlobalCleanup();
    wloopDestroy(&loop);
    testWorkerUnbindWID();
    GSTATE.flag_initialized = false;
    GSTATE.workers          = NULL;
    GSTATE.shortcut_loops   = NULL;
    GSTATE.workers_count    = 0;
    puts("socket_manager_selection_test: all cases passed");
    return 0;
}

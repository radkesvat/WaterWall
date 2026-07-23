/*
 * Socket listener manager for filtered TCP/UDP accept and worker dispatch.
 */

#include "socket_manager.h"

#include "global_state.h"
#include "local_widle_table.h"
#include "loggers/internal_logger.h"
#include "socket_manager_iptables_recovery.h"
#include "stc/common.h"
#include "threadsafe_generic_pool.h"
#include "tunnel.h"
#include "wevent.h"
#include "widle_table.h"
#include "wloop.h"
#include "wmutex.h"
#include "wproc.h"
#include "wfrand.h"
#include "wthread.h"

#define i_type balancegroup_registry_t // NOLINT
#define i_key  hash_t                  // NOLINT
#define i_val  idle_table_t  *         // NOLINT

#include "stc/hmap.h"

typedef struct socket_filter_s
{

    wio_t                **listen_ios;
    wio_t                 *listen_io;
    size_t                 listen_ios_count;
    udpsock_t            **listen_udp_sockets;
    udpsock_t             *listen_udp_socket;
    size_t                 listen_udp_sockets_count;
    socket_filter_option_t option;
    tunnel_t              *tunnel;
    onAccept               cb;
    bool                   v6_dualstack;

    // Effective bind endpoint used for listen-aware dispatch and endpoint sharing.
    ip_addr_t bind_addr;          // meaningful only when !bind_is_wildcard
    uint8_t   bind_family;        // AF_INET / AF_INET6
    bool      bind_is_wildcard;   // true for 0.0.0.0 / :: / empty host
    bool      bind_endpoint_ready; // computed lazily during listen setup

} socket_filter_t;

#define i_type    filters_t         // NOLINT
#define i_key     socket_filter_t     *// NOLINT
#define i_use_cmp                   // NOLINT
#include "stc/vec.h"

// Endpoints that successfully bound; failed bind attempts are never recorded.
typedef struct listener_endpoint_s
{
    uint8_t     protocol;        // IPPROTO_TCP / IPPROTO_UDP
    uint8_t     family;          // AF_INET / AF_INET6
    bool        is_wildcard;     // wildcard bind (0.0.0.0 / ::)
    ip_addr_t   bind_addr;       // meaningful only when !is_wildcard
    uint16_t    port;            // bound port
    const char *interface_scope; // SO_BINDTODEVICE scope when active, else NULL
    wio_t      *listen_io;       // shared listener socket (for exact-duplicate reuse)
    udpsock_t  *udp_socket;      // shared udp side-data (for exact-duplicate reuse)
    // UDP sharers inherit these options from the physical socket.
    int         fwmark;
    int         send_buffer_size;
    int         recv_buffer_size;
} listener_endpoint_t;

#define i_type endpoint_registry_t, listener_endpoint_t // NOLINT
#include "stc/vec.h"

// NAT redirect rule queued during listener setup and installed after sorting.
typedef struct pending_iptables_rule_s
{
    uint8_t     protocol;    // IPPROTO_TCP / IPPROTO_UDP
    uint8_t     family;      // AF_INET / AF_INET6
    bool        has_dest;    // emit -d <ip> (never for wildcard)
    bool        dual_stack;  // AF_INET6 wildcard (::) that also accepts IPv4-mapped traffic
    char        dest[64];    // destination address text when has_dest
    const char *iface_name;  // emit -i <iface> when set
    uint16_t    port_min;
    uint16_t    port_max;
    uint16_t    to_port;
    int         sort_rank;   // lower installs first (specific+iface < specific < wildcard+iface < wildcard)
} pending_iptables_rule_t;

#define i_type pending_rules_t, pending_iptables_rule_t // NOLINT
#include "stc/vec.h"

typedef struct owned_iptables_chain_s
{
    char name[32];
    bool created;
    bool linked;
} owned_iptables_chain_t;

#define SUPPORT_V6 true

enum
{
    kSoOriginalDest         = 80,
    kFilterLevels           = 4,
    kMaxBalanceSelections   = 64,
    kDefaultBalanceInterval = 60 * 1000
};

typedef struct socket_manager_s
{
    filters_t filters[kFilterLevels];

    threadsafe_generic_pool_t **udp_pools; /* holds udp_payload_t */
    threadsafe_generic_pool_t **tcp_pools; /* holds socket_accept_result_t */

    master_pool_t *mp_udp;
    master_pool_t *mp_tcp;

    wmutex_t                mutex;
    balancegroup_registry_t balance_groups;
    pending_rules_t         pending_rules;
    owned_iptables_chain_t  iptables_v4_chain;
    owned_iptables_chain_t  iptables_v6_chain;
    worker_t               *worker;
    wid_t                   wid;
    uint64_t                iptables_owner_token;
    int                     iptables_owner_lease_fd;

    bool iptables_installed;
    bool ip6tables_installed;
    bool lsof_installed;
    bool iptables_used;
    bool iptables_reconciliation_attempted;
    bool iptables_v4_reconciled;
    bool iptables_v6_reconciled;
    bool iptables_published;
    bool started;
    // Avoid accepted-socket SO_MARK writes unless at least one filter requested them.
    bool any_fwmark;

} socket_manager_state_t;

static socket_manager_state_t *socketmanager_gstate = NULL;

static void distributeTcpSocket(wio_t *io, uint16_t local_port, const ip_addr_t *local_addr);

static void distributeUdpPayload(udp_payload_t pl);

static const char *getSocketBindHost(socket_filter_t *filter, const char *host, char *host_if);

static bool addrMatchesFilter(const socket_filter_t *filter, const ip_addr_t *local_addr, int tier);
static bool processFilterMatch(socket_filter_option_t option, uint16_t local_port, ip_addr_t paddr);
static bool processUdpFilterMatch(socket_filter_option_t option, uint16_t local_port, ip_addr_t paddr);

local_idle_table_t *udpsockGetWorkerIdleTable(udpsock_t *socket)
{
    assert(socket != NULL);
    assert(socket->idle_tables != NULL);

    wid_t wid = getWID();
    assert(wid < getWorkersCount());

    local_idle_table_t *table = socket->idle_tables[wid];
    if (table == NULL)
    {
        table                    = localIdleTableCreate(getWorkerLoop(wid));
        socket->idle_tables[wid] = table;
    }

    return table;
}

/**
 * @brief Allocate UDP listener side-data for a bound socket.
 */
static udpsock_t *createUdpSocketSideData(wio_t *io)
{
    udpsock_t *socket = memoryAllocate(sizeof(*socket));
    assert(socket != NULL);

    socket->idle_tables = memoryAllocateZero(sizeof(*socket->idle_tables) * getWorkersCount());
    assert(socket->idle_tables != NULL);

    socket->io = io;
    return socket;
}

static bool startUdpListener(wio_t *io, wread_cb read_cb)
{
    wioSetCallBackRead(io, read_cb);
    return wioRead(io) == 0;
}

static void runAcceptedSocketCallback(void *worker_ptr, void *arg1, void *arg2, void *arg3);
static void cleanupAcceptedSocketDispatch(void *arg1, void *arg2, void *arg3);
static void runUdpPayloadCallback(void *worker_ptr, void *arg1, void *arg2, void *arg3);
static void cleanupUdpPayloadDispatch(void *arg1, void *arg2, void *arg3);
static void runUdpWriteCallback(void *worker_ptr, void *arg1, void *arg2, void *arg3);
static void cleanupUdpWriteDispatch(void *arg1, void *arg2, void *arg3);

/**
 * @brief Allocate a pooled TCP accept result.
 */
static pool_item_t *allocTcpResultObjectPoolHandle(generic_pool_t *pool)
{
    discard pool;
    return memoryAllocate(sizeof(socket_accept_result_t));
}

/**
 * @brief Free a pooled TCP accept result.
 */
static void destroyTcpResultObjectPoolHandle(pool_item_t *item)
{
    memoryFree(item);
}

/**
 * @brief Allocate a pooled UDP payload wrapper.
 */
static pool_item_t *allocUdpPayloadPoolHandle(generic_pool_t *pool)
{
    discard pool;
    return memoryAllocate(sizeof(udp_payload_t));
}

/**
 * @brief Free a pooled UDP payload wrapper.
 */
static void destroyUdpPayloadPoolHandle(pool_item_t *item)
{
    memoryFree(item);
}

void socketacceptresultDestroy(socket_accept_result_t *sar)
{
    const wid_t wid = sar->wid;

    threadsafegenericpoolReuseItem(socketmanager_gstate->tcp_pools[wid], sar);
}

/**
 * @brief Acquire a UDP payload wrapper from a worker pool.
 */
static udp_payload_t *newUdpPayload(wid_t wid)
{
    udp_payload_t *item = threadsafegenericpoolGetItem(socketmanager_gstate->udp_pools[wid]);
    return item;
}

void udppayloadDestroy(udp_payload_t *upl)
{
    const wid_t wid = upl->wid;

    threadsafegenericpoolReuseItem(socketmanager_gstate->udp_pools[wid], upl);
}

int socketManagerComputeRedirectRuleRank(bool has_specific_dest, bool has_interface)
{
    if (has_specific_dest)
    {
        return has_interface ? 0 : 1;
    }
    return has_interface ? 2 : 3;
}

void socketManagerBuildOwnedChainCommand(char *out, size_t out_len, const char *tool,
                                         socket_manager_iptables_chain_action_t action, const char *chain_name)
{
    switch (action)
    {
    case kSocketManagerIptablesCreateChain:
        snprintf(out, out_len, "%s -w -t nat -N %s", tool, chain_name);
        return;
    case kSocketManagerIptablesAddJump:
        snprintf(out, out_len, "%s -w -t nat -A PREROUTING -j %s", tool, chain_name);
        return;
    case kSocketManagerIptablesDeleteJump:
        snprintf(out, out_len, "%s -w -t nat -D PREROUTING -j %s", tool, chain_name);
        return;
    case kSocketManagerIptablesFlushChain:
        snprintf(out, out_len, "%s -w -t nat -F %s", tool, chain_name);
        return;
    case kSocketManagerIptablesDeleteChain:
        snprintf(out, out_len, "%s -w -t nat -X %s", tool, chain_name);
        return;
    }

    if (out_len > 0)
    {
        out[0] = '\0';
    }
    assert(false);
}

void socketManagerBuildRedirectCommand(char *out, size_t out_len, const char *tool, const char *chain_name,
                                       const char *proto_token, bool has_dest, const char *dest, const char *iface_name,
                                       uint16_t port_min, uint16_t port_max, uint16_t to_port)
{
    char dport[32];
    if (port_min == port_max)
    {
        snprintf(dport, sizeof(dport), "%u", (unsigned int) port_min);
    }
    else
    {
        snprintf(dport, sizeof(dport), "%u:%u", (unsigned int) port_min, (unsigned int) port_max);
    }

    char iface_part[96] = {0};
    if (iface_name != NULL && iface_name[0] != '\0')
    {
        snprintf(iface_part, sizeof(iface_part), " -i %s", iface_name);
    }

    char dest_part[80] = {0};
    if (has_dest && dest != NULL && dest[0] != '\0')
    {
        snprintf(dest_part, sizeof(dest_part), " -d %s", dest);
    }

    snprintf(out,
             out_len,
             "%s -w -t nat -A %s -p %s%s%s --dport %s -j REDIRECT --to-port %u",
             tool,
             chain_name,
             proto_token,
             iface_part,
             dest_part,
             dport,
             (unsigned int) to_port);
}

/**
 * @brief Build an iptables command from a queued redirect rule.
 */
static void buildIptablesCommand(char *out, size_t outlen, const char *tool, const char *proto_token,
                                 const char *chain_name, const pending_iptables_rule_t *rule)
{
    socketManagerBuildRedirectCommand(out,
                                      outlen,
                                      tool,
                                      chain_name,
                                      proto_token,
                                      rule->has_dest,
                                      rule->dest,
                                      rule->iface_name,
                                      rule->port_min,
                                      rule->port_max,
                                      rule->to_port);
}

/**
 * @brief Execute one lifecycle operation for a socket-manager-owned chain.
 */
static bool runOwnedChainCommand(const char *tool, socket_manager_iptables_chain_action_t action,
                                 const owned_iptables_chain_t *chain)
{
    char command[128];
    socketManagerBuildOwnedChainCommand(command, sizeof(command), tool, action, chain->name);
    return execCmd(command).exit_code == 0;
}

/**
 * @brief Create one private NAT chain on first use, without publishing a PREROUTING jump.
 */
static bool createOwnedIptablesChain(const char *tool, owned_iptables_chain_t *chain)
{
    if (! chain->created)
    {
        if (! runOwnedChainCommand(tool, kSocketManagerIptablesCreateChain, chain))
        {
            return false;
        }
        chain->created = true;
    }

    return true;
}

/**
 * @brief Publish one populated private NAT chain.
 */
static bool publishOwnedIptablesChain(const char *tool, owned_iptables_chain_t *chain)
{
    if (chain->linked)
    {
        return true;
    }
    if (! chain->created)
    {
        return false;
    }
    if (! runOwnedChainCommand(tool, kSocketManagerIptablesAddJump, chain))
    {
        return false;
    }
    chain->linked = true;
    return true;
}

/**
 * @brief Remove one private NAT chain without touching any unrelated rule or chain.
 */
static bool cleanupOneOwnedIptablesChain(const char *tool, owned_iptables_chain_t *chain)
{
    bool result = true;

    if (chain->linked)
    {
        const bool jump_removed = runOwnedChainCommand(tool, kSocketManagerIptablesDeleteJump, chain);
        if (! jump_removed)
        {
            return false;
        }
        chain->linked = false;
    }

    if (chain->created)
    {
        const bool chain_flushed = runOwnedChainCommand(tool, kSocketManagerIptablesFlushChain, chain);
        if (! chain_flushed)
        {
            return false;
        }

        const bool chain_deleted = runOwnedChainCommand(tool, kSocketManagerIptablesDeleteChain, chain);
        result                   = chain_deleted && result;
        if (chain_deleted)
        {
            chain->created = false;
        }
    }

    return result;
}

/**
 * @brief Remove every socket-manager-owned IPv4/IPv6 NAT artifact.
 */
static bool cleanupOwnedIptablesChains(bool safe_mode)
{
    if (safe_mode)
    {
        const char msg[] = "SocketManager: removing owned iptables nat rules\n";
        ssize_t    n     = write(STDOUT_FILENO, msg, sizeof(msg) - 1);
        discard n;
    }
    else
    {
        LOGD("SocketManager: removing owned iptables nat rules");
    }

    const bool v4_result = cleanupOneOwnedIptablesChain("iptables", &socketmanager_gstate->iptables_v4_chain);
#if SUPPORT_V6
    const bool v6_result = cleanupOneOwnedIptablesChain("ip6tables", &socketmanager_gstate->iptables_v6_chain);
    return v4_result && v6_result;
#else
    return v4_result;
#endif
}

static bool cleanupOwnedIptablesChainsWithReconcileLock(bool safe_mode)
{
    int lock_fd = -1;
    if (! socketManagerIptablesAcquireReconcileLock(&lock_fd, 5000))
    {
        LOGE("SocketManager: failed to acquire iptables reconciliation lock for cleanup");
        return false;
    }
    const bool result = cleanupOwnedIptablesChains(safe_mode);
    socketManagerIptablesReleaseLease(&lock_fd);
    return result;
}

static bool runRecoveryCleanupOp(const socket_manager_iptables_cleanup_op_t *op, void *userdata)
{
    discard userdata;
    const char *tool = op->family == 4 ? "iptables" : "ip6tables";
    socket_manager_iptables_chain_action_t action = kSocketManagerIptablesDeleteChain;
    switch (op->action)
    {
    case kSocketManagerIptablesCleanupDeleteJump:
        action = kSocketManagerIptablesDeleteJump;
        break;
    case kSocketManagerIptablesCleanupFlushChain:
        action = kSocketManagerIptablesFlushChain;
        break;
    case kSocketManagerIptablesCleanupDeleteChain:
        action = kSocketManagerIptablesDeleteChain;
        break;
    }

    owned_iptables_chain_t chain;
    memoryZero(&chain, sizeof(chain));
    snprintf(chain.name, sizeof(chain.name), "%s", op->chain_name);
    const bool ok = runOwnedChainCommand(tool, action, &chain);
    if (! ok)
    {
        LOGE("SocketManager: failed stale iptables cleanup action %d for %s",
             (int) op->action,
             op->chain_name);
    }
    return ok;
}

typedef struct recovery_probe_leases_s
{
    int    fds[256];
    size_t count;
} recovery_probe_leases_t;

static void releaseRecoveryProbeLeases(recovery_probe_leases_t *leases)
{
    for (size_t i = 0; i < leases->count; ++i)
    {
        socketManagerIptablesReleaseLease(&leases->fds[i]);
    }
    leases->count = 0;
}

static socket_manager_iptables_lease_probe_result_t probeRecoveryOwnerLease(uint64_t token, int *held_fd,
                                                                            void *userdata)
{
    recovery_probe_leases_t *leases = userdata;
    int fd = -1;
    socket_manager_iptables_lease_probe_result_t result = socketManagerIptablesAcquireOwnerLease(token, &fd);
    if (result != kSocketManagerIptablesLeaseAcquired)
    {
        return result;
    }
    if (leases == NULL || leases->count >= sizeof(leases->fds) / sizeof(leases->fds[0]))
    {
        socketManagerIptablesReleaseLease(&fd);
        return kSocketManagerIptablesLeaseError;
    }
    leases->fds[leases->count++] = fd;
    *held_fd = -1;
    return kSocketManagerIptablesLeaseAcquired;
}

static void reconcileIptablesStartup(void)
{
    socketmanager_gstate->iptables_reconciliation_attempted = true;
    socketmanager_gstate->iptables_v4_reconciled            = ! socketmanager_gstate->iptables_installed;
    socketmanager_gstate->iptables_v6_reconciled            = ! socketmanager_gstate->ip6tables_installed;

    const bool do_v4 = socketmanager_gstate->iptables_installed;
    const bool do_v6 = socketmanager_gstate->ip6tables_installed;
    if (! do_v4 && ! do_v6)
    {
        return;
    }

    int lock_fd = -1;
    if (! socketManagerIptablesAcquireReconcileLock(&lock_fd, 5000))
    {
        LOGW("SocketManager: failed to acquire iptables startup recovery lock");
        return;
    }

    socket_manager_iptables_cmd_output_t v4_snapshot;
    socket_manager_iptables_cmd_output_t v6_snapshot;
    memoryZero(&v4_snapshot, sizeof(v4_snapshot));
    memoryZero(&v6_snapshot, sizeof(v6_snapshot));

    bool include_v4 = false;
    bool include_v6 = false;
    if (do_v4)
    {
        include_v4 = socketManagerIptablesRunInspectCommand("iptables", &v4_snapshot);
        socketmanager_gstate->iptables_v4_reconciled = include_v4;
        if (! include_v4)
        {
            LOGW("SocketManager: could not inspect ipv4 iptables nat table for stale WaterWall chains");
        }
    }
    if (do_v6)
    {
        include_v6 = socketManagerIptablesRunInspectCommand("ip6tables", &v6_snapshot);
        socketmanager_gstate->iptables_v6_reconciled = include_v6;
        if (! include_v6)
        {
            LOGW("SocketManager: could not inspect ipv6 iptables nat table for stale WaterWall chains");
        }
    }

    socket_manager_iptables_cleanup_plan_t plan;
    socketManagerIptablesCleanupPlanInit(&plan);
    recovery_probe_leases_t probe_leases;
    memoryZero(&probe_leases, sizeof(probe_leases));
    bool v4_ok = true;
    bool v6_ok = true;
    if (! socketManagerIptablesBuildCleanupPlan(v4_snapshot.output,
                                                include_v4,
                                                v6_snapshot.output,
                                                include_v6,
                                                probeRecoveryOwnerLease,
                                                &probe_leases,
                                                &plan,
                                                &v4_ok,
                                                &v6_ok))
    {
        if (include_v4)
        {
            socketmanager_gstate->iptables_v4_reconciled = v4_ok;
        }
        if (include_v6)
        {
            socketmanager_gstate->iptables_v6_reconciled = v6_ok;
        }
    }

    if (! socketManagerIptablesExecuteCleanupPlan(&plan, runRecoveryCleanupOp, NULL, &v4_ok, &v6_ok))
    {
        if (include_v4)
        {
            socketmanager_gstate->iptables_v4_reconciled = v4_ok;
        }
        if (include_v6)
        {
            socketmanager_gstate->iptables_v6_reconciled = v6_ok;
        }
    }

    releaseRecoveryProbeLeases(&probe_leases);
    socketManagerIptablesCleanupPlanDrop(&plan);
    socketManagerIptablesCmdOutputDrop(&v4_snapshot);
    socketManagerIptablesCmdOutputDrop(&v6_snapshot);
    socketManagerIptablesReleaseLease(&lock_fd);
}

/**
 * @brief Validate a config-derived token before it is interpolated into a shell command.
 */
static bool isSafeIptablesToken(const char *s)
{
    if (s == NULL || s[0] == '\0')
    {
        return false;
    }
    for (const char *p = s; *p != '\0'; ++p)
    {
        const char c = *p;
        const bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' ||
                        c == ':' || c == '/' || c == '-' || c == '_' || c == '%';
        if (! ok)
        {
            return false;
        }
    }
    return true;
}

static bool generateIptablesOwnerToken(void)
{
    uint64_t token = 0;
    if (! secureRandomBytes(&token, sizeof(token)))
    {
        return false;
    }
    socketmanager_gstate->iptables_owner_token = token;
    socketManagerIptablesFormatChainName(token,
                                         4,
                                         socketmanager_gstate->iptables_v4_chain.name,
                                         sizeof(socketmanager_gstate->iptables_v4_chain.name));
    socketManagerIptablesFormatChainName(token,
                                         6,
                                         socketmanager_gstate->iptables_v6_chain.name,
                                         sizeof(socketmanager_gstate->iptables_v6_chain.name));
    return true;
}

static bool acquireIptablesOwnerLease(void)
{
    if (socketmanager_gstate->iptables_owner_lease_fd >= 0)
    {
        return true;
    }

    for (int attempt = 0; attempt < 16; ++attempt)
    {
        if (! generateIptablesOwnerToken())
        {
            LOGE("SocketManager: failed to generate iptables owner token");
            return false;
        }

        int fd = -1;
        socket_manager_iptables_lease_probe_result_t lease =
            socketManagerIptablesAcquireOwnerLease(socketmanager_gstate->iptables_owner_token, &fd);
        if (lease == kSocketManagerIptablesLeaseAcquired)
        {
            socketmanager_gstate->iptables_owner_lease_fd = fd;
            return true;
        }
        if (lease != kSocketManagerIptablesLeaseInUse)
        {
            LOGE("SocketManager: failed to bind iptables owner lease");
            return false;
        }
    }

    LOGE("SocketManager: could not find an unused iptables owner token");
    return false;
}

static bool pendingIptablesNeedsFamily(int family)
{
    const isize count = pending_rules_t_size(&socketmanager_gstate->pending_rules);
    for (isize i = 0; i < count; ++i)
    {
        const pending_iptables_rule_t *rule = pending_rules_t_at(&socketmanager_gstate->pending_rules, i);
        if (family == 4 && (rule->family == AF_INET || rule->dual_stack))
        {
            return true;
        }
        if (family == 6 && rule->family == AF_INET6 && socketmanager_gstate->ip6tables_installed)
        {
            return true;
        }
    }
    return false;
}

static void enforceIptablesReconciliationForPendingRules(void)
{
    if (pendingIptablesNeedsFamily(4) &&
        (! socketmanager_gstate->iptables_reconciliation_attempted || ! socketmanager_gstate->iptables_v4_reconciled))
    {
        LOGF("SocketManager: refusing to install ipv4 iptables rules after failed startup recovery");
        terminateProgram(1);
    }
#if SUPPORT_V6
    if (pendingIptablesNeedsFamily(6) &&
        (! socketmanager_gstate->iptables_reconciliation_attempted || ! socketmanager_gstate->iptables_v6_reconciled))
    {
        LOGF("SocketManager: refusing to install ipv6 iptables rules after failed startup recovery");
        terminateProgram(1);
    }
#endif
}

/**
 * @brief Queue a listener-aware redirect rule for later (sorted) installation.
 */
static void queueIptablesRule(uint8_t protocol, socket_filter_t *filter, uint16_t port_min, uint16_t port_max,
                              uint16_t to_port)
{
    pending_iptables_rule_t rule;
    memoryZero(&rule, sizeof(rule));

    rule.protocol = protocol;
    rule.family   = filter->bind_family;
    rule.port_min = port_min;
    rule.port_max = port_max;
    rule.to_port  = to_port;
    // Dual-stack IPv6 wildcard listeners also need an IPv4 redirect rule.
    rule.dual_stack = (filter->bind_family == AF_INET6 && filter->bind_is_wildcard);
    rule.iface_name =
        (filter->option.interface_name != NULL && filter->option.interface_name[0] != '\0') ? filter->option.interface_name
                                                                                             : NULL;

    if (rule.iface_name != NULL && ! isSafeIptablesToken(rule.iface_name))
    {
        LOGF("SocketManager: unsafe interface name \"%s\" for iptables rule", rule.iface_name);
        terminateProgram(1);
    }

    if (! filter->bind_is_wildcard)
    {
        char        host_if[INET_ADDRSTRLEN] = {0};
        const char *host                     = getSocketBindHost(filter, filter->option.host, host_if);
        if (host != NULL && host[0] != '\0')
        {
            if (! isSafeIptablesToken(host))
            {
                LOGF("SocketManager: unsafe destination host \"%s\" for iptables rule", host);
                terminateProgram(1);
            }
            rule.has_dest = true;
            snprintf(rule.dest, sizeof(rule.dest), "%s", host);
        }
    }

    rule.sort_rank = socketManagerComputeRedirectRuleRank(rule.has_dest, rule.iface_name != NULL);

    pending_rules_t_push(&socketmanager_gstate->pending_rules, rule);
}

/**
 * @brief Install one queued redirect rule into already-created private chains.
 */
static bool installOnePendingRule(const pending_iptables_rule_t *rule)
{
    const char *proto_token = rule->protocol == IPPROTO_TCP ? "TCP" : "UDP";
    char        command[256];

    if (rule->family == AF_INET)
    {
        owned_iptables_chain_t *chain = &socketmanager_gstate->iptables_v4_chain;
        buildIptablesCommand(command, sizeof(command), "iptables", proto_token, chain->name, rule);
        return execCmd(command).exit_code == 0;
    }

#if SUPPORT_V6
    if (rule->family == AF_INET6)
    {
        bool result = true;

        if (rule->dual_stack)
        {
            owned_iptables_chain_t *chain = &socketmanager_gstate->iptables_v4_chain;
            buildIptablesCommand(command, sizeof(command), "iptables", proto_token, chain->name, rule);
            result = execCmd(command).exit_code == 0;
        }

        if (! socketmanager_gstate->ip6tables_installed)
        {
            LOGW("SocketManager: ip6tables not installed, skipping ipv6 redirect rule");
            return result;
        }
        if (! result)
        {
            return false;
        }

        owned_iptables_chain_t *chain = &socketmanager_gstate->iptables_v6_chain;
        buildIptablesCommand(command, sizeof(command), "ip6tables", proto_token, chain->name, rule);
        return execCmd(command).exit_code == 0;
    }
#endif
    return false;
}

/**
 * @brief Install queued redirect rules from most specific to least specific.
 */
static void installPendingIptablesRules(void)
{
    const isize count = pending_rules_t_size(&socketmanager_gstate->pending_rules);
    if (count == 0)
    {
        return;
    }

    enforceIptablesReconciliationForPendingRules();

    int lock_fd = -1;
    if (! socketManagerIptablesAcquireReconcileLock(&lock_fd, 5000))
    {
        LOGF("SocketManager: failed to acquire iptables reconciliation lock for rule publication");
        terminateProgram(1);
    }

    if (! acquireIptablesOwnerLease())
    {
        socketManagerIptablesReleaseLease(&lock_fd);
        terminateProgram(1);
    }

    const bool needs_v4 = pendingIptablesNeedsFamily(4);
    const bool needs_v6 = pendingIptablesNeedsFamily(6);

    if (needs_v4 && ! createOwnedIptablesChain("iptables", &socketmanager_gstate->iptables_v4_chain))
    {
        LOGF("SocketManager: failed to create ipv4 iptables chain %s", socketmanager_gstate->iptables_v4_chain.name);
        socketManagerIptablesReleaseLease(&lock_fd);
        terminateProgram(1);
    }
#if SUPPORT_V6
    if (needs_v6 && ! createOwnedIptablesChain("ip6tables", &socketmanager_gstate->iptables_v6_chain))
    {
        LOGF("SocketManager: failed to create ipv6 iptables chain %s", socketmanager_gstate->iptables_v6_chain.name);
        cleanupOwnedIptablesChains(false);
        socketManagerIptablesReleaseLease(&lock_fd);
        terminateProgram(1);
    }
#endif

    for (int rank = 0; rank <= 3; ++rank)
    {
        for (isize i = 0; i < count; ++i)
        {
            const pending_iptables_rule_t *rule = pending_rules_t_at(&socketmanager_gstate->pending_rules, i);
            if (rule->sort_rank != rank)
            {
                continue;
            }
            if (! installOnePendingRule(rule))
            {
                LOGF("SocketManager: failed to add iptables redirect rule for %s port %u-%u",
                     rule->protocol == IPPROTO_TCP ? "tcp" : "udp",
                     (unsigned int) rule->port_min,
                     (unsigned int) rule->port_max);
                if (! cleanupOwnedIptablesChains(false))
                {
                    LOGE("SocketManager: failed to fully roll back owned iptables rules");
                }
                socketManagerIptablesReleaseLease(&lock_fd);
                terminateProgram(1);
            }
        }
    }

    if (needs_v4 && ! publishOwnedIptablesChain("iptables", &socketmanager_gstate->iptables_v4_chain))
    {
        LOGF("SocketManager: failed to publish ipv4 iptables chain %s", socketmanager_gstate->iptables_v4_chain.name);
        cleanupOwnedIptablesChains(false);
        socketManagerIptablesReleaseLease(&lock_fd);
        terminateProgram(1);
    }
#if SUPPORT_V6
    if (needs_v6 && ! publishOwnedIptablesChain("ip6tables", &socketmanager_gstate->iptables_v6_chain))
    {
        LOGF("SocketManager: failed to publish ipv6 iptables chain %s", socketmanager_gstate->iptables_v6_chain.name);
        cleanupOwnedIptablesChains(false);
        socketManagerIptablesReleaseLease(&lock_fd);
        terminateProgram(1);
    }
#endif

    socketmanager_gstate->iptables_published = needs_v4 || needs_v6;
    socketManagerIptablesReleaseLease(&lock_fd);
    pending_rules_t_clear(&socketmanager_gstate->pending_rules);
}

/**
 * @brief Detect IPv4-mapped IPv6 addresses.
 */
static inline bool needsV4SocketStrategy(const ip6_addr_t addr)
{
    uint16_t segments[8];
    memoryCopy(segments, addr.addr, sizeof(segments));
    return (segments[0] == 0 && segments[1] == 0 && segments[2] == 0 && segments[3] == 0 && segments[4] == 0 &&
            segments[5] == 0xFFFF);
}

/**
 * @brief Compare two normalized IP addresses for exact equality.
 */
static inline bool ipAddrEqualsExact(const ip_addr_t *a, const ip_addr_t *b)
{
    if (a->type != b->type)
    {
        return false;
    }
    if (a->type == IPADDR_TYPE_V4)
    {
        return a->u_addr.ip4.addr == b->u_addr.ip4.addr;
    }
    return (a->u_addr.ip6.addr[0] == b->u_addr.ip6.addr[0] && a->u_addr.ip6.addr[1] == b->u_addr.ip6.addr[1] &&
            a->u_addr.ip6.addr[2] == b->u_addr.ip6.addr[2] && a->u_addr.ip6.addr[3] == b->u_addr.ip6.addr[3]);
}

/**
 * @brief Detect a wildcard (all-zero) IP address.
 */
static inline bool ipAddrIsWildcard(const ip_addr_t *a)
{
    if (a->type == IPADDR_TYPE_V4)
    {
        return a->u_addr.ip4.addr == 0;
    }
    if (a->type == IPADDR_TYPE_V6)
    {
        return (a->u_addr.ip6.addr[0] | a->u_addr.ip6.addr[1] | a->u_addr.ip6.addr[2] | a->u_addr.ip6.addr[3]) == 0;
    }
    return true;
}

/**
 * @brief Collapse an IPv4-mapped IPv6 address to native IPv4.
 */
static inline void normalizeIpAddr(ip_addr_t *addr)
{
    if (addr->type == IPADDR_TYPE_V6 && needsV4SocketStrategy(addr->u_addr.ip6))
    {
        ip4_addr_t v4;
        memoryCopy(&v4, &(addr->u_addr.ip6.addr[3]), sizeof(v4.addr));
        addr->type       = IPADDR_TYPE_V4;
        addr->u_addr.ip4 = v4;
    }
}

/**
 * @brief Convert an ACL range wholly contained in the IPv4-mapped IPv6 prefix to native IPv4.
 */
static inline bool mappedAclRangeToV4(const ipmask_t *range, ip4_addr_t *ip, ip4_addr_t *mask)
{
    if (range->ip.type != IPADDR_TYPE_V6 || range->mask.type != IPADDR_TYPE_V6 ||
        ! needsV4SocketStrategy(range->ip.u_addr.ip6))
    {
        return false;
    }

    const ip6_addr_t *range_mask = &range->mask.u_addr.ip6;
    if (range_mask->addr[0] != UINT32_MAX || range_mask->addr[1] != UINT32_MAX || range_mask->addr[2] != UINT32_MAX)
    {
        return false;
    }

    memoryCopy(ip, &range->ip.u_addr.ip6.addr[3], sizeof(ip->addr));
    memoryCopy(mask, &range_mask->addr[3], sizeof(mask->addr));
    return true;
}

/**
 * @brief Convert an accepted socket address to a normalized IP address for local-address dispatch.
 */
static inline bool sockaddrToNormalizedIpAddr(const sockaddr_u *src, ip_addr_t *dest)
{
    if (! sockaddrToIpAddr(src, dest))
    {
        return false;
    }
    normalizeIpAddr(dest);
    return true;
}

/**
 * @brief Calculate filter priority from ACL and port specificity.
 */
static unsigned int calculateFilterPriority(const socket_filter_option_t option)
{
    unsigned int priority = 0;

    if (option.multiport_backend == kMultiportBackendNone || vec_listener_port_t_size(&option.ports) > 0)
    {
        priority++;
    }
    if (vec_ipmask_t_size(&option.white_list) > 0)
    {
        priority++;
    }
    if (vec_ipmask_t_size(&option.black_list))
    {
        priority++;
    }

    return priority;
}

/**
 * @brief Whether the filter uses an explicit port list.
 */
static bool socketFilterOptionHasPortList(const socket_filter_option_t *option)
{
    return vec_listener_port_t_size(&option->ports) > 0;
}

/**
 * @brief Check if an explicit port list contains a port.
 */
static bool socketFilterOptionPortListContains(const socket_filter_option_t *option, uint16_t port)
{
    for (isize i = 0; i < vec_listener_port_t_size(&option->ports); ++i)
    {
        if (*vec_listener_port_t_at(&option->ports, i) == port)
        {
            return true;
        }
    }
    return false;
}

/**
 * @brief Get or create the idle table backing a balance group.
 */
static idle_table_t *getOrCreateBalanceTable(const char *balance_group_name)
{
    hash_t        name_hash = calcHashBytes(balance_group_name, stringLength(balance_group_name));
    idle_table_t *b_table   = NULL;

    mutexLock(&(socketmanager_gstate->mutex));

    balancegroup_registry_t_iter find_result =
        balancegroup_registry_t_find(&(socketmanager_gstate->balance_groups), name_hash);

    if (find_result.ref == balancegroup_registry_t_end(&(socketmanager_gstate->balance_groups)).ref)
    {
        b_table = idleTableCreate(socketmanager_gstate->worker->loop);
        balancegroup_registry_t_insert(&(socketmanager_gstate->balance_groups), name_hash, b_table);
    }
    else
    {
        b_table = (find_result.ref->second);
    }

    mutexUnlock(&(socketmanager_gstate->mutex));

    return b_table;
}

void socketacceptorRegister(tunnel_t *tunnel, socket_filter_option_t option, onAccept cb)
{
    if (socketmanager_gstate->started)
    {
        LOGF("SocketManager: cannot register after accept thread starts");
        terminateProgram(1);
    }

    socket_filter_t *filter   = memoryAllocate(sizeof(socket_filter_t));
    unsigned int     priority = calculateFilterPriority(option);

    if (option.balance_group_name)
    {
        option.shared_balance_table = getOrCreateBalanceTable(option.balance_group_name);
    }

    *filter = (socket_filter_t) {.tunnel = tunnel, .option = option, .cb = cb, .listen_io = NULL};

    mutexLock(&(socketmanager_gstate->mutex));
    filters_t_push(&(socketmanager_gstate->filters[priority]), filter);
    if (option.fwmark >= 0)
    {
        socketmanager_gstate->any_fwmark = true;
    }
    mutexUnlock(&(socketmanager_gstate->mutex));
}

void socketacceptorUpdateBufferOptions(tunnel_t *tunnel, int send_buffer_size, int recv_buffer_size)
{
    mutexLock(&(socketmanager_gstate->mutex));
    for (size_t i = 0; i < kFilterLevels; ++i)
    {
        c_foreach(filter, filters_t, socketmanager_gstate->filters[i])
        {
            socket_filter_t *f = *filter.ref;
            if (f->tunnel == tunnel)
            {
                f->option.send_buffer_size = send_buffer_size;
                f->option.recv_buffer_size = recv_buffer_size;
            }
        }
    }
    mutexUnlock(&(socketmanager_gstate->mutex));
}

/**
 * @brief Forward an accepted TCP socket to the selected worker.
 */
static void distributeSocket(void *io, socket_filter_t *filter, uint16_t local_port)
{
    wioDetach(io);

    wid_t wid = getNextDistributionWID();

    socket_accept_result_t *result = threadsafegenericpoolGetItem(socketmanager_gstate->tcp_pools[wid]);

    *result = (socket_accept_result_t) {
        .io             = io,
        .tunnel         = filter->tunnel,
        .real_localport = local_port,
        .wid            = wid,
    };

    sendWorkerMessageWithCleanup(wid, runAcceptedSocketCallback, cleanupAcceptedSocketDispatch, filter, result, NULL);
}

/**
 * @brief Run a selected TCP accept callback on its target worker.
 */
static void runAcceptedSocketCallback(void *worker_ptr, void *arg1, void *arg2, void *arg3)
{
    worker_t               *worker = worker_ptr;
    socket_filter_t        *filter = arg1;
    socket_accept_result_t *result = arg2;
    discard                 arg3;

    wevent_t ev = (wevent_t) {.loop = worker->loop, .cb = filter->cb, .userdata = result};
    filter->cb(&ev);
}

/**
 * @brief Release an accepted socket dispatch message if delivery fails.
 */
static void cleanupAcceptedSocketDispatch(void *arg1, void *arg2, void *arg3)
{
    socket_accept_result_t *result = arg2;
    discard                 arg1;
    discard                 arg3;

    if (result != NULL)
    {
        if (result->io != NULL)
        {
            assert((result->io->events & WW_RDWR) == 0);
            assert(! result->io->pending);
            wioFree(result->io);
        }
        socketacceptresultDestroy(result);
    }
}

/**
 * @brief Apply per-filter socket options to an accepted TCP socket.
 */
static bool applyAcceptedTcpSocketOptions(wio_t *io, const socket_filter_option_t *option)
{
    if (option->no_delay)
    {
        tcpNoDelay(wioGetFD(io), 1);
    }

    // Shared listeners may accept for a filter with a different mark; normalize only when marks are in use.
    if (socketmanager_gstate->any_fwmark)
    {
        const int effective_mark = option->fwmark >= 0 ? option->fwmark : 0;
        int       current_mark   = 0;
        const bool have_current  = socketOptionGetFwMark(wioGetFD(io), &current_mark);
        if (! have_current || current_mark != effective_mark)
        {
            if (socketOptionSetFwMark(wioGetFD(io), effective_mark) != 0)
            {
                LOGE("SocketManager: set accepted TCP socket fwmark failed");
                return false;
            }
        }
    }

    if (! socketOptionApplySendBuffer(wioGetFD(io), option->send_buffer_size))
    {
        LOGE("SocketManager: set TCP socket send buffer failed");
        return false;
    }

    if (! socketOptionApplyRecvBuffer(wioGetFD(io), option->recv_buffer_size))
    {
        LOGE("SocketManager: set TCP socket recv buffer failed");
        return false;
    }

    return true;
}

/**
 * @brief Log and close TCP socket when no filter matched.
 */
static void noTcpSocketConsumerFound(wio_t *io)
{
    char localaddrstr[SOCKADDR_STRLEN] = {0};
    char peeraddrstr[SOCKADDR_STRLEN]  = {0};

    LOGE("SocketManager: could not find consumer for Tcp socket FD:%x [%s] <= [%s]",
         wioGetFD(io),
         SOCKADDR_STR(wioGetLocaladdrU(io), localaddrstr),
         SOCKADDR_STR(wioGetPeerAddrU(io), peeraddrstr));
    wioClose(io);
}

bool socketManagerIpMatchesAcl(ip_addr_t addr, const vec_ipmask_t *acl)
{
    normalizeIpAddr(&addr);

    for (isize i = 0; i < vec_ipmask_t_size(acl); ++i)
    {
        const ipmask_t *range = vec_ipmask_t_at(acl, i);

        if (addr.type == IPADDR_TYPE_V4)
        {
            if (range->ip.type == IPADDR_TYPE_V4 && range->mask.type == IPADDR_TYPE_V4 &&
                checkIPRange4(addr.u_addr.ip4, range->ip.u_addr.ip4, range->mask.u_addr.ip4))
            {
                return true;
            }

            ip4_addr_t mapped_ip;
            ip4_addr_t mapped_mask;
            if (mappedAclRangeToV4(range, &mapped_ip, &mapped_mask) &&
                checkIPRange4(addr.u_addr.ip4, mapped_ip, mapped_mask))
            {
                return true;
            }
        }
        if (addr.type == IPADDR_TYPE_V6 && range->ip.type == IPADDR_TYPE_V6 && range->mask.type == IPADDR_TYPE_V6 &&
            checkIPRange6(addr.u_addr.ip6, range->ip.u_addr.ip6, range->mask.u_addr.ip6))
        {
            return true;
        }
    }
    return false;
}

/**
 * @brief Check peer IP against whitelist strategy for dual-stack handling.
 */
static bool checkIpIsWhiteList(const ip_addr_t addr, const socket_filter_option_t option)
{
    return socketManagerIpMatchesAcl(addr, &option.white_list);
}

/**
 * @brief Check peer IP against blacklist strategy for dual-stack handling.
 */
static bool checkIpIsBlackList(const ip_addr_t addr, const socket_filter_option_t option)
{
    return socketManagerIpMatchesAcl(addr, &option.black_list);
}

hash_t socketManagerCombineBalanceLocalHash(hash_t src_hash, const ip_addr_t *local_addr, uint16_t local_port,
                                            int match_tier)
{
    hash_t scope = ipaddrCalcHashNoPort(*local_addr);
    scope ^= (hash_t) local_port + 0x9E3779B97F4A7C15ULL + (scope << 6) + (scope >> 2);
    scope ^= ((hash_t) match_tier + 1U) + 0x9E3779B97F4A7C15ULL + (scope << 6) + (scope >> 2);
    return src_hash ^ (scope + 0x9E3779B97F4A7C15ULL + (src_hash << 6) + (src_hash >> 2));
}

/**
 * @brief Check whether a sticky balance target still matches the current endpoint.
 */
static bool balanceTargetStillMatches(const socket_filter_t *target, uint16_t local_port, const ip_addr_t paddr,
                                      const ip_addr_t *local_addr, int match_tier, bool is_udp)
{
    const socket_filter_option_t opt = target->option;
    const bool                   proto_ok =
        is_udp ? processUdpFilterMatch(opt, local_port, paddr) : processFilterMatch(opt, local_port, paddr);
    return proto_ok && addrMatchesFilter(target, local_addr, match_tier);
}

/**
 * @brief Handle one TCP balance candidate or collect it for random selection.
 */
static bool handleBalancedFilter(socket_filter_t *filter, const socket_filter_option_t option, wio_t *io,
                                 uint16_t local_port, const ip_addr_t *local_addr, int match_tier, hash_t *src_hash,
                                 bool *src_hashed, socket_filter_t **balance_selection_filters,
                                 uint8_t *balance_selection_filters_length, idle_table_t **selected_balance_table)
{
    if (*selected_balance_table != NULL && option.shared_balance_table != *selected_balance_table)
    {
        return false;
    }

    ip_addr_t paddr;
    sockaddrToIpAddr(wioGetPeerAddrU(io), &paddr);

    if (! *src_hashed)
    {
        *src_hash   = socketManagerCombineBalanceLocalHash(ipaddrCalcHashNoPort(paddr), local_addr, local_port,
                                                           match_tier);
        *src_hashed = true;
    }

    idle_item_t *idle_item =
        idletableGetIdleItemByHash(socketmanager_gstate->wid, option.shared_balance_table, *src_hash);

    // Stale or colliding sticky entries must not cross endpoint scopes.
    if (idle_item && balanceTargetStillMatches(idle_item->userdata, local_port, paddr, local_addr, match_tier, false))
    {
        socket_filter_t *target_filter = idle_item->userdata;
        idletableKeepIdleItemForAtleast(option.shared_balance_table,
                                        idle_item,
                                        option.balance_group_interval == 0 ? kDefaultBalanceInterval
                                                                           : option.balance_group_interval);
        if (! applyAcceptedTcpSocketOptions(io, &target_filter->option))
        {
            wioClose(io);
            return true;
        }
        distributeSocket(io, target_filter, local_port);
        return true;
    }

    if (UNLIKELY(*balance_selection_filters_length >= kMaxBalanceSelections))
    {
        LOGW("SocketManager: balance between more than %d tunnels is not supported", kMaxBalanceSelections);
        return false;
    }
    balance_selection_filters[(*balance_selection_filters_length)++] = filter;
    *selected_balance_table                                          = option.shared_balance_table;
    return false;
}

/**
 * @brief Select a TCP balance candidate after a dispatch pass.
 */
static bool finalizeTcpDistribution(socket_filter_t **balance_selection_filters,
                                    uint8_t balance_selection_filters_length, wio_t *io, uint16_t local_port,
                                    hash_t src_hash)
{
    if (balance_selection_filters_length > 0)
    {
        socket_filter_t *filter = balance_selection_filters[fastRand() % balance_selection_filters_length];
        if (! applyAcceptedTcpSocketOptions(io, &filter->option))
        {
            wioClose(io);
            return true;
        }
        idletableCreateItem(filter->option.shared_balance_table,
                            src_hash,
                            filter,
                            NULL,
                            socketmanager_gstate->wid,
                            filter->option.balance_group_interval == 0 ? kDefaultBalanceInterval
                                                                       : filter->option.balance_group_interval);
        distributeSocket(io, filter, local_port);
        return true;
    }
    return false;
}

enum
{
    kDispatchTierExact          = 0, // specific local-address filters
    kDispatchTierWildcardFamily = 1, // wildcard whose family matches the destination family
    kDispatchTierWildcardDual   = 2, // :: dual-stack wildcard serving an IPv4 destination (least specific)
    kDispatchTierCount          = 3
};

bool socketManagerWildcardMatchesTier(bool bind_is_v6_wildcard, bool dest_is_v4, int tier)
{
    if (tier == kDispatchTierWildcardFamily)
    {
        // 0.0.0.0 serves IPv4, :: serves IPv6.
        return dest_is_v4 ? (! bind_is_v6_wildcard) : bind_is_v6_wildcard;
    }
    if (tier == kDispatchTierWildcardDual)
    {
        // :: also serves IPv4, but only after the family-matching tier found no consumer.
        return dest_is_v4 && bind_is_v6_wildcard;
    }
    return false;
}

/**
 * @brief Match a filter against the local destination at one specificity tier.
 */
static bool addrMatchesFilter(const socket_filter_t *filter, const ip_addr_t *local_addr, int tier)
{
    if (tier == kDispatchTierExact)
    {
        if (filter->bind_is_wildcard)
        {
            return false;
        }
        return ipAddrEqualsExact(&filter->bind_addr, local_addr);
    }

    if (! filter->bind_is_wildcard)
    {
        return false;
    }

    return socketManagerWildcardMatchesTier(filter->bind_family == AF_INET6,
                                            local_addr->type == IPADDR_TYPE_V4,
                                            tier);
}

/**
 * @brief Evaluate whether filter matches TCP packet metadata and ACL rules.
 */
static bool processFilterMatch(const socket_filter_option_t option, uint16_t local_port, const ip_addr_t paddr)
{
    if (option.protocol != IPPROTO_TCP)
    {
        return false;
    }

    if (socketFilterOptionHasPortList(&option))
    {
        if (! socketFilterOptionPortListContains(&option, local_port))
        {
            return false;
        }
    }
    else if (option.port_min > local_port || option.port_max < local_port)
    {
        return false;
    }

    if (vec_ipmask_t_size(&option.white_list) > 0)
    {
        if (! checkIpIsWhiteList(paddr, option))
        {
            return false;
        }
    }
    if (vec_ipmask_t_size(&option.black_list) > 0)
    {
        if (checkIpIsBlackList(paddr, option))
        {
            return false;
        }
    }
    return true;
}

/**
 * @brief Try to dispatch an accepted TCP socket at one specificity tier.
 */
static bool distributeTcpSocketPass(wio_t *io, uint16_t local_port, const ip_addr_t *local_addr,
                                    const ip_addr_t paddr, int match_tier)
{
    socket_filter_t *balance_selection_filters[kMaxBalanceSelections];
    uint8_t          balance_selection_filters_length = 0;
    idle_table_t    *selected_balance_table           = NULL;
    hash_t           src_hash                         = 0x0;
    bool             src_hashed                       = false;

    for (int ri = (kFilterLevels - 1); ri >= 0; ri--)
    {
        c_foreach(k, filters_t, socketmanager_gstate->filters[ri])
        {
            socket_filter_t       *filter = *(k.ref);
            socket_filter_option_t option = filter->option;

            if (! processFilterMatch(option, local_port, paddr))
            {
                continue;
            }
            if (! addrMatchesFilter(filter, local_addr, match_tier))
            {
                continue;
            }

            if (option.shared_balance_table)
            {
                if (handleBalancedFilter(filter,
                                         option,
                                         io,
                                         local_port,
                                         local_addr,
                                         match_tier,
                                         &src_hash,
                                         &src_hashed,
                                         balance_selection_filters,
                                         &balance_selection_filters_length,
                                         &selected_balance_table))
                {
                    return true;
                }
            }
            else
            {
                if (! applyAcceptedTcpSocketOptions(io, &filter->option))
                {
                    wioClose(io);
                    return true;
                }
                distributeSocket(io, filter, local_port);
                return true;
            }
        }
    }

    return finalizeTcpDistribution(balance_selection_filters, balance_selection_filters_length, io, local_port,
                                   src_hash);
}

/**
 * @brief Dispatch an accepted TCP socket from exact listener to broadest wildcard.
 */
static void distributeTcpSocket(wio_t *io, uint16_t local_port, const ip_addr_t *local_addr)
{
    ip_addr_t paddr;
    sockaddrToIpAddr(wioGetPeerAddrU(io), &paddr);

    for (int tier = 0; tier < kDispatchTierCount; ++tier)
    {
        if (distributeTcpSocketPass(io, local_port, local_addr, paddr, tier))
        {
            return;
        }
    }

    noTcpSocketConsumerFound(io);
}

/**
 * @brief TCP accept callback for single-port listeners.
 */
static void onAcceptTcpSinglePort(wio_t *io)
{
    sockaddr_u *local_saddr = wioGetLocaladdrU(io);
    ip_addr_t   local_addr;
    if (! sockaddrToNormalizedIpAddr(local_saddr, &local_addr))
    {
        LOGE("SocketManager: could not parse accepted TCP local address");
        wioClose(io);
        return;
    }
    distributeTcpSocket(io, sockaddrPort(local_saddr), &local_addr);
}

/**
 * @brief TCP accept callback for redirected multi-port listeners.
 */
static void onAcceptTcpMultiPort(wio_t *io)
{
#ifdef OS_UNIX
    ip_addr_t paddr;
    if (! sockaddrToIpAddr(wioGetPeerAddrU(io), &paddr))
    {
        LOGE("SocketManger: address parse failure");
        wioClose(io);
        return;
    }

    bool          use_v4_strategy = paddr.type == IPADDR_TYPE_V6 ? needsV4SocketStrategy(paddr.u_addr.ip6) : true;
    unsigned char pbuf[28]        = {0};
    socklen_t     size            = use_v4_strategy ? 16 : 24;

    int level = use_v4_strategy ? IPPROTO_IP : IPPROTO_IPV6;
    if (getsockopt(wioGetFD(io), level, kSoOriginalDest, &(pbuf[0]), &size) < 0)
    {
        char localaddrstr[SOCKADDR_STRLEN] = {0};
        char peeraddrstr[SOCKADDR_STRLEN]  = {0};

        LOGE("SocketManger: multiport failure getting origin port FD:%x [%s] <= [%s]",
             wioGetFD(io),
             SOCKADDR_STR(wioGetLocaladdrU(io), localaddrstr),
             SOCKADDR_STR(wioGetPeerAddrU(io), peeraddrstr));
        wioClose(io);
        return;
    }

    // Recover address + port so redirected sockets still dispatch by listener specificity.
    uint16_t  orig_port = (uint16_t) ((pbuf[2] << 8) | pbuf[3]);
    ip_addr_t local_addr;
    memoryZero(&local_addr, sizeof(local_addr));
    if (use_v4_strategy)
    {
        local_addr.type = IPADDR_TYPE_V4;
        memoryCopy(&local_addr.u_addr.ip4.addr, &pbuf[4], sizeof(local_addr.u_addr.ip4.addr));
    }
    else
    {
        local_addr.type = IPADDR_TYPE_V6;
        memoryCopy(&local_addr.u_addr.ip6.addr, &pbuf[8], sizeof(local_addr.u_addr.ip6.addr));
    }
    normalizeIpAddr(&local_addr);

    distributeTcpSocket(io, orig_port, &local_addr);
#else
    onAcceptTcpSinglePort(io);
#endif
}

/**
 * @brief Pick default multi-port backend from detected capabilities.
 */
static multiport_backend_t getDefaultMultiPortBackend(void)
{
    if (socketmanager_gstate->iptables_installed)
    {
        return kMultiportBackendIptables;
    }
    return kMultiportBackendSockets;
}

/**
 * @brief Resolve interface name to host string.
 */
static bool getInterfaceHostString(const char *if_name, char *host_if)
{
    if (! getInterfaceIpString(if_name, host_if, INET_ADDRSTRLEN))
    {
        LOGF("SocketManager: Could not get interface \"%s\" ip", if_name);
        terminateProgram(1);
        return false;
    }
    return true;
}

/**
 * @brief Choose bind host while preserving device binding when supported.
 */
static const char *getSocketBindHost(socket_filter_t *filter, const char *host, char *host_if)
{
    if (filter->option.interface_name == NULL || socketOptionBindToDeviceSupported())
    {
        return host;
    }

    getInterfaceHostString(filter->option.interface_name, host_if);
    return host_if;
}

/**
 * @brief Compute the normalized bind endpoint used by dispatch and sharing.
 */
static void computeFilterBindEndpoint(socket_filter_t *filter)
{
    if (filter->bind_endpoint_ready)
    {
        return;
    }

    char        host_if[INET_ADDRSTRLEN] = {0};
    const char *host                     = getSocketBindHost(filter, filter->option.host, host_if);

    ip_addr_t addr;
    memoryZero(&addr, sizeof(addr));
    bool    wildcard = false;
    uint8_t family   = AF_INET;

    if (host == NULL || host[0] == '\0')
    {
        wildcard = true;
        family   = AF_INET;
    }
    else
    {
        int parsed = parseIpAddress(host, &addr);
        if (parsed == IPADDR_TYPE_ANY)
        {
            // Listener hosts are expected to be literals; non-literals are kept out of exact matching.
            wildcard = true;
            family   = AF_INET;
        }
        else
        {
            normalizeIpAddr(&addr);
            family   = (addr.type == IPADDR_TYPE_V6) ? AF_INET6 : AF_INET;
            wildcard = ipAddrIsWildcard(&addr);
        }
    }

    filter->bind_addr           = addr;
    filter->bind_family         = family;
    filter->bind_is_wildcard    = wildcard;
    filter->bind_endpoint_ready = true;
}

/**
 * @brief Return the interface component of endpoint identity, when device binding is active.
 */
static const char *filterInterfaceScope(const socket_filter_t *filter)
{
    if (filter->option.interface_name != NULL && filter->option.interface_name[0] != '\0' &&
        socketOptionBindToDeviceSupported())
    {
        return filter->option.interface_name;
    }
    return NULL;
}

/**
 * @brief Compare two interface scopes (NULL-safe).
 */
static bool interfaceScopeEquals(const char *a, const char *b)
{
    if (a == NULL || b == NULL)
    {
        return a == b;
    }
    return strcmp(a, b) == 0;
}

/**
 * @brief Find a bound endpoint with the same protocol, bind address, port, and scope.
 */
static listener_endpoint_t *endpointRegistryFind(endpoint_registry_t *reg, uint8_t protocol,
                                                 socket_filter_t *filter, uint16_t port)
{
    computeFilterBindEndpoint(filter);
    const char *iface = filterInterfaceScope(filter);

    c_foreach(it, endpoint_registry_t, *reg)
    {
        listener_endpoint_t *ep = it.ref;
        if (ep->protocol != protocol || ep->port != port)
        {
            continue;
        }
        if (ep->is_wildcard != filter->bind_is_wildcard)
        {
            continue;
        }
        if (! interfaceScopeEquals(ep->interface_scope, iface))
        {
            continue;
        }
        if (ep->is_wildcard)
        {
            if (ep->family != filter->bind_family)
            {
                continue;
            }
        }
        else if (! ipAddrEqualsExact(&ep->bind_addr, &filter->bind_addr))
        {
            continue;
        }
        return ep;
    }
    return NULL;
}

/**
 * @brief Record a successfully bound endpoint in the registry.
 */
static void endpointRegistryReserve(endpoint_registry_t *reg, uint8_t protocol, socket_filter_t *filter,
                                    uint16_t port, wio_t *io, udpsock_t *udp)
{
    computeFilterBindEndpoint(filter);

    listener_endpoint_t ep;
    memoryZero(&ep, sizeof(ep));
    ep.protocol        = protocol;
    ep.family          = filter->bind_family;
    ep.is_wildcard     = filter->bind_is_wildcard;
    ep.bind_addr       = filter->bind_addr;
    ep.port            = port;
    ep.interface_scope   = filterInterfaceScope(filter);
    ep.listen_io         = io;
    ep.udp_socket        = udp;
    ep.fwmark            = filter->option.fwmark;
    ep.send_buffer_size  = filter->option.send_buffer_size;
    ep.recv_buffer_size  = filter->option.recv_buffer_size;

    endpoint_registry_t_push(reg, ep);
}

/**
 * @brief Reject UDP endpoint sharing when socket-level options cannot be shared.
 */
static void ensureUdpSharedEndpointCompatible(const listener_endpoint_t *ep, const socket_filter_t *filter,
                                              const char *host, uint16_t port)
{
    // UDP replies use the same physical socket, so fwmark must match.
    if (ep->fwmark != filter->option.fwmark)
    {
        LOGF("SocketManager: UDP endpoint %s:[%u] requested with conflicting fwmark (%d vs %d); a shared UDP "
             "socket cannot honor per-listener marks, use distinct ports or a matching fwmark",
             host,
             (unsigned int) port,
             ep->fwmark,
             filter->option.fwmark);
        terminateProgram(1);
    }

    // Buffer mismatch is visible but not a correctness problem.
    if (ep->send_buffer_size != filter->option.send_buffer_size ||
        ep->recv_buffer_size != filter->option.recv_buffer_size)
    {
        LOGW("SocketManager: UDP endpoint %s:[%u] shared by listeners with different socket buffer sizes; the "
             "shared socket keeps the first listener's buffers",
             host,
             (unsigned int) port);
    }
}

/**
 * @brief Validate every existing UDP endpoint that a redirected range would cover.
 */
static void ensureUdpRedirectRangeCompatible(endpoint_registry_t *reg, socket_filter_t *filter, const char *host,
                                             uint16_t port_min, uint16_t port_max)
{
    for (uint32_t p = port_min; p <= port_max; ++p)
    {
        listener_endpoint_t *shared = endpointRegistryFind(reg, IPPROTO_UDP, filter, (uint16_t) p);
        if (shared != NULL)
        {
            ensureUdpSharedEndpointCompatible(shared, filter, host, (uint16_t) p);
        }
    }
}

/**
 * @brief Check whether a bound TCP wildcard already covers a port/scope.
 */
static bool registryHasBoundTcpWildcard(const endpoint_registry_t *reg, uint16_t port, const char *iface_scope,
                                        bool require_v6_wildcard)
{
    c_foreach(it, endpoint_registry_t, *reg)
    {
        const listener_endpoint_t *ep = it.ref;
        if (ep->protocol != IPPROTO_TCP || ! ep->is_wildcard || ep->port != port)
        {
            continue;
        }
        if (require_v6_wildcard && ep->family != AF_INET6)
        {
            continue;
        }
        if (! interfaceScopeEquals(ep->interface_scope, iface_scope))
        {
            continue;
        }
        return true;
    }
    return false;
}

/**
 * @brief Decide if a TCP bind should be served by an already-bound broader listener.
 */
static bool tcpBindDefersToExisting(const endpoint_registry_t *reg, socket_filter_t *filter, uint16_t port)
{
    computeFilterBindEndpoint(filter);
    const char *iface = filterInterfaceScope(filter);

    if (! filter->bind_is_wildcard)
    {
        return registryHasBoundTcpWildcard(reg, port, iface, filter->bind_family == AF_INET6);
    }

    // A 0.0.0.0 wildcard defers only to a bound :: dual-stack wildcard.
    if (filter->bind_family == AF_INET)
    {
        return registryHasBoundTcpWildcard(reg, port, iface, true);
    }
    return false;
}

/**
 * @brief Create TCP listener with configured socket options.
 */
static wio_t *createTcpServerWithSocketOptions(wloop_t *loop, socket_filter_t *filter, char *host, uint16_t port,
                                               void (*callback)(wio_t *))
{
    char        host_if[INET_ADDRSTRLEN] = {0};
    const char *bind_host                = getSocketBindHost(filter, host, host_if);
    return wloopCreateTcpServerWithOptions(
        loop, bind_host, port, callback, filter->option.interface_name, filter->option.fwmark);
}

/**
 * @brief Create UDP listener with configured socket options.
 */
static wio_t *createUdpServerWithSocketOptions(wloop_t *loop, socket_filter_t *filter, char *host, uint16_t port)
{
    char        host_if[INET_ADDRSTRLEN] = {0};
    const char *bind_host                = getSocketBindHost(filter, host, host_if);
    wio_t      *io                       = wloopCreateUdpServerWithBufferOptions(loop,
                                                                                 bind_host,
                                                                                 port,
                                                                                 filter->option.interface_name,
                                                                                 filter->option.fwmark,
                                                                                 filter->option.send_buffer_size,
                                                                                 filter->option.recv_buffer_size);

    if (io == NULL)
    {
        return NULL;
    }

    return io;
}

/**
 * @brief Check whether an entire TCP range is already served by wildcard listeners.
 */
static bool tcpRangeDefersToWildcard(const endpoint_registry_t *reg, socket_filter_t *filter)
{
    computeFilterBindEndpoint(filter);
    const socket_filter_option_t *o = &filter->option;

    if (socketFilterOptionHasPortList(o))
    {
        const isize n = vec_listener_port_t_size(&o->ports);
        if (n == 0)
        {
            return false;
        }
        for (isize i = 0; i < n; ++i)
        {
            if (! tcpBindDefersToExisting(reg, filter, *vec_listener_port_t_at(&o->ports, i)))
            {
                return false;
            }
        }
        return true;
    }

    for (uint32_t p = o->port_min; p <= o->port_max; ++p)
    {
        if (! tcpBindDefersToExisting(reg, filter, (uint16_t) p))
        {
            return false;
        }
    }
    return true;
}

/**
 * @brief Select one listening port used as redirect target for iptables mode.
 */
static uint16_t selectMainPortForIptables(socket_filter_t *filter, wloop_t *loop, char *host, uint16_t port_min,
                                          uint16_t port_max, endpoint_registry_t *reg)
{
    for (int main_port = (int) port_max; main_port >= (int) port_min; --main_port)
    {
        if (endpointRegistryFind(reg, IPPROTO_TCP, filter, (uint16_t) main_port) != NULL)
        {
            continue;
        }

        if (tcpBindDefersToExisting(reg, filter, (uint16_t) main_port))
        {
            continue;
        }

        filter->listen_io =
            createTcpServerWithSocketOptions(loop, filter, host, (uint16_t) main_port, onAcceptTcpMultiPort);
        if (filter->listen_io == NULL)
        {
            continue;
        }

        endpointRegistryReserve(reg, IPPROTO_TCP, filter, (uint16_t) main_port, filter->listen_io, NULL);
        filter->v6_dualstack = wioGetLocaladdr(filter->listen_io)->sa_family == AF_INET6;
        return (uint16_t) main_port;
    }

    LOGF("SocketManager: stopping due to null socket handle");
    terminateProgram(1);
    return 0;
}

/**
 * @brief Validate iptables availability on first use.
 */
static void initializeIptablesIfNeeded(void)
{
    if (! socketmanager_gstate->iptables_installed)
    {
        LOGF("SocketManager: multi port backend \"iptables\" colud not start, error: not installed");
        terminateProgram(1);
    }
#if SUPPORT_V6
    if (! socketmanager_gstate->ip6tables_installed)
    {
        LOGW("SocketManager: ip6tables is not installed, ipv6 nat redirect rules will be skipped");
    }
#endif

    socketmanager_gstate->iptables_used = true;
}

/**
 * @brief Listen TCP on range via iptables redirect backend.
 */
static void listenTcpMultiPortIptables(wloop_t *loop, socket_filter_t *filter, char *host, uint16_t port_min,
                                       endpoint_registry_t *reg, uint16_t port_max)
{
    if (tcpRangeDefersToWildcard(reg, filter))
    {
        LOGI("SocketManager: %s:[%u - %u] shares the wildcard TCP listener (iptables range deferred)",
             host,
             port_min,
             port_max);
        return;
    }

    initializeIptablesIfNeeded();

    uint16_t main_port = selectMainPortForIptables(filter, loop, host, port_min, port_max, reg);

    queueIptablesRule(IPPROTO_TCP, filter, port_min, port_max, main_port);
    LOGI("SocketManager: listening on %s:[%u - %u] >> %d (%s)", host, port_min, port_max, main_port, "TCP");
}

/**
 * @brief Listen TCP on each port in range via socket-per-port backend.
 */
static void listenTcpMultiPortSockets(wloop_t *loop, socket_filter_t *filter, char *host, uint16_t port_min,
                                      endpoint_registry_t *reg, uint16_t port_max)
{
    const int length   = (int) (port_max - port_min + 1);
    filter->listen_ios = (wio_t **) memoryAllocateZero(sizeof(wio_t *) * ((size_t) length + 1));
    int i = 0;

    for (uint32_t p = port_min; p <= port_max; ++p)
    {
        const uint16_t port = (uint16_t) p;

        if (endpointRegistryFind(reg, IPPROTO_TCP, filter, port) != NULL)
        {
            LOGI("SocketManager: %s:[%u] shares an existing TCP listener", host, port);
            continue;
        }

        if (tcpBindDefersToExisting(reg, filter, port))
        {
            LOGI("SocketManager: %s:[%u] shares the wildcard TCP listener", host, port);
            continue;
        }

        wio_t *io = createTcpServerWithSocketOptions(loop, filter, host, port, onAcceptTcpSinglePort);

        if (io == NULL)
        {
            LOGW("SocketManager: could not listen on %s:[%u] , skipped...", host, port);
            continue;
        }
        filter->listen_ios[i] = io;
        endpointRegistryReserve(reg, IPPROTO_TCP, filter, port, io, NULL);
        filter->v6_dualstack = wioGetLocaladdr(io)->sa_family == AF_INET6;

        i++;
        LOGI("SocketManager: listening on %s:[%u] (%s)", host, port, "TCP");
    }
    filter->listen_ios_count = (size_t) i;
}

/**
 * @brief Listen TCP on each explicitly listed port via socket-per-port backend.
 */
static void listenTcpPortListSockets(wloop_t *loop, socket_filter_t *filter, char *host, endpoint_registry_t *reg,
                                     const vec_listener_port_t *ports)
{
    const isize length = vec_listener_port_t_size(ports);
    filter->listen_ios = (wio_t **) memoryAllocateZero(sizeof(wio_t *) * ((size_t) length + 1));
    int i = 0;

    for (isize pi = 0; pi < length; ++pi)
    {
        uint16_t p = *vec_listener_port_t_at(ports, pi);

        if (endpointRegistryFind(reg, IPPROTO_TCP, filter, p) != NULL)
        {
            LOGI("SocketManager: %s:[%u] shares an existing TCP listener", host, p);
            continue;
        }

        if (tcpBindDefersToExisting(reg, filter, p))
        {
            LOGI("SocketManager: %s:[%u] shares the wildcard TCP listener", host, p);
            continue;
        }

        wio_t *io = createTcpServerWithSocketOptions(loop, filter, host, p, onAcceptTcpSinglePort);

        if (io == NULL)
        {
            LOGW("SocketManager: could not listen on %s:[%u] , skipped...", host, p);
            continue;
        }
        filter->listen_ios[i] = io;
        endpointRegistryReserve(reg, IPPROTO_TCP, filter, p, io, NULL);
        filter->v6_dualstack = wioGetLocaladdr(io)->sa_family == AF_INET6;

        i++;
        LOGI("SocketManager: listening on %s:[%u] (%s)", host, p, "TCP");
    }
    filter->listen_ios_count = (size_t) i;
}

/**
 * @brief Listen TCP on single port.
 */
static void listenTcpSinglePort(wloop_t *loop, socket_filter_t *filter, char *host, uint16_t port,
                                endpoint_registry_t *reg)
{
    if (endpointRegistryFind(reg, IPPROTO_TCP, filter, port) != NULL)
    {
        LOGI("SocketManager: %s:[%u] shares an existing TCP listener", host, port);
        return;
    }

    if (tcpBindDefersToExisting(reg, filter, port))
    {
        LOGI("SocketManager: %s:[%u] shares the wildcard TCP listener", host, port);
        return;
    }

    filter->listen_io = createTcpServerWithSocketOptions(loop, filter, host, port, onAcceptTcpSinglePort);

    if (filter->listen_io == NULL)
    {
        LOGF("SocketManager: stopping due to null socket handle");
        terminateProgram(1);
    }
    endpointRegistryReserve(reg, IPPROTO_TCP, filter, port, filter->listen_io, NULL);
    filter->v6_dualstack = wioGetLocaladdr(filter->listen_io)->sa_family == AF_INET6;
    LOGI("SocketManager: listening on %s:[%u] (%s)", host, port, "TCP");
}

/**
 * @brief Build listeners for one TCP filter using its configured multiport backend.
 */
static void listenOneTcpFilter(wloop_t *loop, socket_filter_t *filter, endpoint_registry_t *reg)
{
    computeFilterBindEndpoint(filter);

    if (filter->option.multiport_backend == kMultiportBackendDefault)
    {
        filter->option.multiport_backend = getDefaultMultiPortBackend();
        // TCP keeps socket-per-port behavior unless config explicitly selects iptables.
        filter->option.multiport_backend = kMultiportBackendSockets;
    }

    socket_filter_option_t option   = filter->option;
    uint16_t               port_min = option.port_min;
    uint16_t               port_max = option.port_max;
    if (port_min > port_max)
    {
        LOGF("SocketManager: port min must be lower than port max");
        terminateProgram(1);
    }
    else if (port_min == port_max)
    {
        option.multiport_backend = kMultiportBackendNone;
    }

    if (socketFilterOptionHasPortList(&option))
    {
        listenTcpPortListSockets(loop, filter, option.host, reg, &option.ports);
    }
    else if (option.multiport_backend == kMultiportBackendIptables)
    {
        listenTcpMultiPortIptables(loop, filter, option.host, port_min, reg, port_max);
    }
    else if (option.multiport_backend == kMultiportBackendSockets)
    {
        listenTcpMultiPortSockets(loop, filter, option.host, port_min, reg, port_max);
    }
    else
    {
        listenTcpSinglePort(loop, filter, option.host, port_min, reg);
    }
}

/**
 * @brief Classify TCP bind order so broad wildcard listeners bind before narrower endpoints.
 */
static int tcpFilterBindPhase(socket_filter_t *filter)
{
    computeFilterBindEndpoint(filter);
    if (! filter->bind_is_wildcard)
    {
        return 2;
    }
    return filter->bind_family == AF_INET6 ? 0 : 1;
}

/**
 * @brief Build TCP listeners broadest-first so narrower binds can safely defer.
 */
static void listenTcp(wloop_t *loop, endpoint_registry_t *reg)
{
    for (int phase = 0; phase <= 2; ++phase)
    {
        for (int ri = (kFilterLevels - 1); ri >= 0; ri--)
        {
            c_foreach(k, filters_t, socketmanager_gstate->filters[ri])
            {
                socket_filter_t *filter = *(k.ref);
                if (filter->option.protocol != IPPROTO_TCP)
                {
                    continue;
                }
                if (tcpFilterBindPhase(filter) != phase)
                {
                    continue;
                }
                listenOneTcpFilter(loop, filter, reg);
            }
        }
    }
}

/**
 * @brief Log dropped UDP payload when no filter matched.
 */
static void noUdpSocketConsumerFound(const udp_payload_t upl)
{
    char localaddrstr[SOCKADDR_STRLEN] = {0};
    char peeraddrstr[SOCKADDR_STRLEN]  = {0};
    LOGE("SocketManager: could not find consumer for Udp socket  [%s] <= [%s]",
         SOCKADDR_STR(wioGetLocaladdrU(upl.sock->io), localaddrstr),
         SOCKADDR_STR((sockaddr_u *) &upl.peer_addr, peeraddrstr));
}

/**
 * @brief Run a selected UDP listener callback on its target worker.
 */
static void runUdpPayloadCallback(void *worker_ptr, void *arg1, void *arg2, void *arg3)
{
    worker_t        *worker = worker_ptr;
    socket_filter_t *filter = arg1;
    udp_payload_t   *pl     = arg2;
    discard          arg3;

    wevent_t ev = (wevent_t) {.loop = worker->loop, .cb = filter->cb, .userdata = pl};
    filter->cb(&ev);
}

/**
 * @brief Release a UDP payload dispatch message if delivery fails.
 */
static void cleanupUdpPayloadDispatch(void *arg1, void *arg2, void *arg3)
{
    udp_payload_t *pl = arg2;
    discard        arg1;
    discard        arg3;

    if (pl != NULL)
    {
        sbufDestroy(pl->buf);
        udppayloadDestroy(pl);
    }
}

/**
 * @brief Post one UDP payload object to target filter callback.
 */
static void postUdpPayload(udp_payload_t post_pl, socket_filter_t *filter)
{
    udp_payload_t *pl = threadsafegenericpoolGetItem(socketmanager_gstate->udp_pools[post_pl.wid]);
    *pl               = post_pl;

    pl->tunnel = filter->tunnel;
    sendWorkerMessageWithCleanup(pl->wid, runUdpPayloadCallback, cleanupUdpPayloadDispatch, filter, pl, NULL);
}

/**
 * @brief Evaluate whether filter matches UDP packet metadata and ACL rules.
 */
static bool processUdpFilterMatch(const socket_filter_option_t option, uint16_t local_port, const ip_addr_t paddr)
{
    if (UNLIKELY(option.protocol != IPPROTO_UDP))
    {
        return false;
    }

    if (socketFilterOptionHasPortList(&option))
    {
        if (! socketFilterOptionPortListContains(&option, local_port))
        {
            return false;
        }
    }
    else if (option.port_min > local_port || option.port_max < local_port)
    {
        return false;
    }

    if (vec_ipmask_t_size(&option.white_list) > 0)
    {
        if (! checkIpIsWhiteList(paddr, option))
        {
            return false;
        }
    }
    if (vec_ipmask_t_size(&option.black_list) > 0)
    {
        if (checkIpIsBlackList(paddr, option))
        {
            return false;
        }
    }
    return true;
}

/**
 * @brief Handle one UDP balance candidate or collect it for random selection.
 */
static bool handleUdpBalancedFilter(socket_filter_t *filter, const socket_filter_option_t option,
                                    const udp_payload_t pl, const ip_addr_t *local_addr, int match_tier,
                                    hash_t *src_hash, bool *src_hashed, socket_filter_t **balance_selection_filters,
                                    uint8_t *balance_selection_filters_length, idle_table_t **selected_balance_table)
{
    if (*selected_balance_table != NULL && option.shared_balance_table != *selected_balance_table)
    {
        return false;
    }

    ip_addr_t paddr;
    sockaddrToIpAddr((sockaddr_u *) &pl.peer_addr, &paddr);

    if (! *src_hashed)
    {
        *src_hash   = socketManagerCombineBalanceLocalHash(ipaddrCalcHashNoPort(paddr), local_addr,
                                                           pl.real_localport, match_tier);
        *src_hashed = true;
    }

    idle_item_t *idle_item =
        idletableGetIdleItemByHash(socketmanager_gstate->wid, option.shared_balance_table, *src_hash);

    if (idle_item && balanceTargetStillMatches(idle_item->userdata, pl.real_localport, paddr, local_addr, match_tier,
                                               true))
    {
        socket_filter_t *target_filter = idle_item->userdata;
        idletableKeepIdleItemForAtleast(option.shared_balance_table,
                                        idle_item,
                                        option.balance_group_interval == 0 ? kDefaultBalanceInterval
                                                                           : option.balance_group_interval);
        postUdpPayload(pl, target_filter);
        return true;
    }

    if (UNLIKELY(*balance_selection_filters_length >= kMaxBalanceSelections))
    {
        LOGW("SocketManager: balance between more than %d tunnels is not supported", kMaxBalanceSelections);
        return false;
    }
    balance_selection_filters[(*balance_selection_filters_length)++] = filter;
    *selected_balance_table                                          = option.shared_balance_table;
    return false;
}

/**
 * @brief Select a UDP balance candidate after a dispatch pass.
 */
static bool finalizeUdpDistribution(socket_filter_t **balance_selection_filters,
                                    uint8_t balance_selection_filters_length, const udp_payload_t pl, hash_t src_hash)
{
    if (balance_selection_filters_length > 0)
    {
        socket_filter_t *filter = balance_selection_filters[fastRand() % balance_selection_filters_length];
        idletableCreateItem(filter->option.shared_balance_table,
                            src_hash,
                            filter,
                            NULL,
                            socketmanager_gstate->wid,
                            filter->option.balance_group_interval == 0 ? kDefaultBalanceInterval
                                                                       : filter->option.balance_group_interval);
        postUdpPayload(pl, filter);
        return true;
    }
    return false;
}

/**
 * @brief Try to dispatch a UDP payload at one specificity tier.
 */
static bool distributeUdpPayloadPass(const udp_payload_t pl, uint16_t local_port, const ip_addr_t *local_addr,
                                     const ip_addr_t paddr, int match_tier)
{
    socket_filter_t *balance_selection_filters[kMaxBalanceSelections];
    uint8_t          balance_selection_filters_length = 0;
    idle_table_t    *selected_balance_table           = NULL;
    hash_t           src_hash                         = 0x0;
    bool             src_hashed                       = false;

    for (int ri = (kFilterLevels - 1); ri >= 0; ri--)
    {
        c_foreach(k, filters_t, socketmanager_gstate->filters[ri])
        {
            socket_filter_t       *filter = *(k.ref);
            socket_filter_option_t option = filter->option;

            if (! processUdpFilterMatch(option, local_port, paddr))
            {
                continue;
            }
            if (! addrMatchesFilter(filter, local_addr, match_tier))
            {
                continue;
            }

            if (option.shared_balance_table)
            {
                if (handleUdpBalancedFilter(filter,
                                            option,
                                            pl,
                                            local_addr,
                                            match_tier,
                                            &src_hash,
                                            &src_hashed,
                                            balance_selection_filters,
                                            &balance_selection_filters_length,
                                            &selected_balance_table))
                {
                    return true;
                }
            }
            else
            {
                postUdpPayload(pl, filter);
                return true;
            }
        }
    }

    return finalizeUdpDistribution(balance_selection_filters, balance_selection_filters_length, pl, src_hash);
}

/**
 * @brief Dispatch a UDP payload from exact listener to broadest wildcard.
 */
static void distributeUdpPayload(const udp_payload_t pl)
{
    ip_addr_t paddr;
    sockaddrToIpAddr((sockaddr_u *) &pl.peer_addr, &paddr);

    ip_addr_t local_addr;
    if (! sockaddrToNormalizedIpAddr(&pl.real_localaddr, &local_addr))
    {
        memoryZero(&local_addr, sizeof(local_addr));
        local_addr.type = IPADDR_TYPE_V4;
    }

    uint16_t local_port = pl.real_localport;

    for (int tier = 0; tier < kDispatchTierCount; ++tier)
    {
        if (distributeUdpPayloadPass(pl, local_port, &local_addr, paddr, tier))
        {
            return;
        }
    }

    noUdpSocketConsumerFound(pl);
    sbufDestroy(pl.buf);
}

/**
 * @brief UDP read callback for single-port listeners.
 */
static void onUdpPacketReceived(wio_t *io, sbuf_t *buf)
{
    udpsock_t *socket      = weventGetUserdata(io);
    sockaddr_u local_addr  = *wioGetLocaladdrU(io);
    uint16_t   local_port  = sockaddrPort(&local_addr);
    uint16_t   remote_port = sockaddrPort(wioGetPeerAddrU(io));
    wid_t      target_wid  = (wid_t) remote_port % (getWorkersCount());

    if (UNLIKELY(isApplicationTerminating()))
    {
        sbufDestroy(buf);
        return;
    }

    udp_payload_t item = (udp_payload_t) {.sock           = socket,
                                          .buf            = buf,
                                          .wid            = target_wid,
                                          .peer_addr      = *wioGetPeerAddrU(io),
                                          .real_localaddr = local_addr,
                                          .real_localport = local_port};

    distributeUdpPayload(item);
}

/**
 * @brief UDP read callback for redirected multi-port listeners.
 */
static void onUdpPacketReceivedMultiPort(wio_t *io, sbuf_t *buf)
{

#ifdef OS_UNIX
    udpsock_t *socket          = weventGetUserdata(io);
    sockaddr_u local_addr      = *wioGetLocaladdrU(io);
    uint16_t   remote_port     = sockaddrPort(wioGetPeerAddrU(io));
    wid_t      target_wid      = (wid_t) remote_port % (getWorkersCount());
    uint16_t   real_local_port = sockaddrPort(&local_addr); // default fallback

    if (UNLIKELY(isApplicationTerminating()))
    {
        sbufDestroy(buf);
        return;
    }

    ip_addr_t paddr;
    if (sockaddrToIpAddr(wioGetPeerAddrU(io), &paddr))
    {
        bool          use_v4_strategy = paddr.type == IPADDR_TYPE_V6 ? needsV4SocketStrategy(paddr.u_addr.ip6) : true;
        unsigned char pbuf[28]        = {0};
        socklen_t     size            = use_v4_strategy ? 16 : 24;

        int level = use_v4_strategy ? IPPROTO_IP : IPPROTO_IPV6;
        if (getsockopt(wioGetFD(io), level, kSoOriginalDest, &(pbuf[0]), &size) >= 0)
        {
            real_local_port = (uint16_t) ((pbuf[2] << 8) | pbuf[3]);
        }
        else
        {
            char localaddrstr[SOCKADDR_STRLEN] = {0};
            char peeraddrstr[SOCKADDR_STRLEN]  = {0};
            LOGW("SocketManager: UDP multiport failure getting origin port FD:%x [%s] <= [%s], using fallback port",
                 wioGetFD(io),
                 SOCKADDR_STR(wioGetLocaladdrU(io), localaddrstr),
                 SOCKADDR_STR(wioGetPeerAddrU(io), peeraddrstr));
        }
    }

    // UDP redirects recover the original port only; specific-address iptables ranges are rejected at startup.
    sockaddrSetPort(&local_addr, real_local_port);

    udp_payload_t item = (udp_payload_t) {.sock           = socket,
                                          .buf            = buf,
                                          .wid            = target_wid,
                                          .peer_addr      = *wioGetPeerAddrU(io),
                                          .real_localaddr = local_addr,
                                          .real_localport = real_local_port};

    distributeUdpPayload(item);
#else
    onUdpPacketReceived(io, buf);
#endif
}

/**
 * @brief Listen UDP on single port.
 */
static void listenUdpSinglePort(wloop_t *loop, socket_filter_t *filter, char *host, uint16_t port,
                                endpoint_registry_t *reg)
{
    listener_endpoint_t *shared = endpointRegistryFind(reg, IPPROTO_UDP, filter, port);
    if (shared != NULL)
    {
        ensureUdpSharedEndpointCompatible(shared, filter, host, port);
        LOGI("SocketManager: %s:[%u] shares an existing UDP listener", host, port);
        return;
    }

    filter->listen_io = createUdpServerWithSocketOptions(loop, filter, host, port);

    if (filter->listen_io == NULL)
    {
        LOGF("SocketManager: stopping due to null socket handle");
        terminateProgram(1);
    }
    if (UNLIKELY(! startUdpListener(filter->listen_io, onUdpPacketReceived)))
    {
        filter->listen_io = NULL;
        LOGF("SocketManager: could not register UDP listener on %s:[%u]", host, port);
        terminateProgram(1);
    }
    udpsock_t *socket         = createUdpSocketSideData(filter->listen_io);
    filter->listen_udp_socket = socket;
    weventSetUserData(filter->listen_io, socket);
    endpointRegistryReserve(reg, IPPROTO_UDP, filter, port, filter->listen_io, socket);
    LOGI("SocketManager: listening on %s:[%u] (%s)", host, port, "UDP");
}

/**
 * @brief Listen UDP on range via iptables redirect backend.
 */
static void listenUdpMultiPortIptables(wloop_t *loop, socket_filter_t *filter, char *host, uint16_t port_min,
                                       endpoint_registry_t *reg, uint16_t port_max)
{
    // UDP redirects cannot reliably recover the original destination address.
    if (! filter->bind_is_wildcard)
    {
        LOGF("SocketManager: UDP iptables multiport does not support a specific bind address (%s); "
             "use the socket-per-port backend for listen-aware UDP",
             host);
        terminateProgram(1);
    }

    ensureUdpRedirectRangeCompatible(reg, filter, host, port_min, port_max);
    initializeIptablesIfNeeded();

    int main_port = -1;
    for (int p = (int) port_max; p >= (int) port_min; --p)
    {
        if (endpointRegistryFind(reg, IPPROTO_UDP, filter, (uint16_t) p) != NULL)
        {
            continue;
        }

        filter->listen_io = createUdpServerWithSocketOptions(loop, filter, host, (uint16_t) p);
        if (filter->listen_io != NULL)
        {
            main_port = p;
            break;
        }
    }

    if (filter->listen_io == NULL)
    {
        LOGF("SocketManager: stopping due to null UDP socket handle");
        terminateProgram(1);
    }

    filter->v6_dualstack = wioGetLocaladdr(filter->listen_io)->sa_family == AF_INET6;

    if (UNLIKELY(! startUdpListener(filter->listen_io, onUdpPacketReceivedMultiPort)))
    {
        filter->listen_io = NULL;
        LOGF("SocketManager: could not register UDP redirect listener on %s:[%d]", host, main_port);
        terminateProgram(1);
    }
    udpsock_t *socket         = createUdpSocketSideData(filter->listen_io);
    filter->listen_udp_socket = socket;
    weventSetUserData(filter->listen_io, socket);
    endpointRegistryReserve(reg, IPPROTO_UDP, filter, (uint16_t) main_port, filter->listen_io, socket);

    queueIptablesRule(IPPROTO_UDP, filter, port_min, port_max, (uint16_t) main_port);
    LOGI("SocketManager: listening on %s:[%u - %u] >> %d (%s)", host, port_min, port_max, main_port, "UDP");
}

/**
 * @brief Listen UDP on each port in range via socket-per-port backend.
 */
static void listenUdpMultiPortSockets(wloop_t *loop, socket_filter_t *filter, char *host, uint16_t port_min,
                                      endpoint_registry_t *reg, uint16_t port_max)
{
    const int length   = (int) (port_max - port_min + 1);
    filter->listen_ios = (wio_t **) memoryAllocateZero(sizeof(wio_t *) * ((size_t) length + 1));
    filter->listen_udp_sockets = (udpsock_t **) memoryAllocateZero(sizeof(udpsock_t *) * (size_t) length);
    int i = 0;

    for (uint32_t p = port_min; p <= port_max; ++p)
    {
        const uint16_t       port   = (uint16_t) p;
        listener_endpoint_t *shared = endpointRegistryFind(reg, IPPROTO_UDP, filter, port);
        if (shared != NULL)
        {
            ensureUdpSharedEndpointCompatible(shared, filter, host, port);
            LOGI("SocketManager: %s:[%u] shares an existing UDP listener", host, port);
            continue;
        }

        wio_t *udp_io = createUdpServerWithSocketOptions(loop, filter, host, port);
        if (udp_io == NULL)
        {
            LOGW("SocketManager: could not listen on %s:[%u] , skipped...", host, port);
            continue;
        }

        if (UNLIKELY(! startUdpListener(udp_io, onUdpPacketReceived)))
        {
            LOGW("SocketManager: could not register UDP listener on %s:[%u], skipped...", host, port);
            continue;
        }

        filter->listen_ios[i] = udp_io;
        filter->v6_dualstack  = wioGetLocaladdr(udp_io)->sa_family == AF_INET6;

        udpsock_t *socket             = createUdpSocketSideData(udp_io);
        filter->listen_udp_sockets[i] = socket;
        weventSetUserData(udp_io, socket);
        endpointRegistryReserve(reg, IPPROTO_UDP, filter, port, udp_io, socket);

        i++;
        LOGI("SocketManager: listening on %s:[%u] (%s)", host, port, "UDP");
    }
    filter->listen_ios_count         = (size_t) i;
    filter->listen_udp_sockets_count = (size_t) i;
}

/**
 * @brief Listen UDP on each explicitly listed port via socket-per-port backend.
 */
static void listenUdpPortListSockets(wloop_t *loop, socket_filter_t *filter, char *host, endpoint_registry_t *reg,
                                     const vec_listener_port_t *ports)
{
    const isize length = vec_listener_port_t_size(ports);
    filter->listen_ios = (wio_t **) memoryAllocateZero(sizeof(wio_t *) * ((size_t) length + 1));
    filter->listen_udp_sockets = (udpsock_t **) memoryAllocateZero(sizeof(udpsock_t *) * (size_t) length);
    int i = 0;

    for (isize pi = 0; pi < length; ++pi)
    {
        uint16_t p = *vec_listener_port_t_at(ports, pi);

        listener_endpoint_t *shared = endpointRegistryFind(reg, IPPROTO_UDP, filter, p);
        if (shared != NULL)
        {
            ensureUdpSharedEndpointCompatible(shared, filter, host, p);
            LOGI("SocketManager: %s:[%u] shares an existing UDP listener", host, p);
            continue;
        }

        wio_t *udp_io = createUdpServerWithSocketOptions(loop, filter, host, p);
        if (udp_io == NULL)
        {
            LOGW("SocketManager: could not listen on %s:[%u] , skipped...", host, p);
            continue;
        }

        if (UNLIKELY(! startUdpListener(udp_io, onUdpPacketReceived)))
        {
            LOGW("SocketManager: could not register UDP listener on %s:[%u], skipped...", host, p);
            continue;
        }

        filter->listen_ios[i] = udp_io;
        filter->v6_dualstack  = wioGetLocaladdr(udp_io)->sa_family == AF_INET6;

        udpsock_t *socket             = createUdpSocketSideData(udp_io);
        filter->listen_udp_sockets[i] = socket;
        weventSetUserData(udp_io, socket);
        endpointRegistryReserve(reg, IPPROTO_UDP, filter, p, udp_io, socket);

        i++;
        LOGI("SocketManager: listening on %s:[%u] (%s)", host, p, "UDP");
    }
    filter->listen_ios_count         = (size_t) i;
    filter->listen_udp_sockets_count = (size_t) i;
}

/**
 * @brief Build UDP listeners for all registered UDP filters.
 */
static void listenUdp(wloop_t *loop, endpoint_registry_t *reg)
{
    for (int ri = (kFilterLevels - 1); ri >= 0; ri--)
    {
        c_foreach(k, filters_t, socketmanager_gstate->filters[ri])
        {
            socket_filter_t *filter = *(k.ref);
            if (filter->option.protocol != IPPROTO_UDP)
            {
                continue;
            }

            computeFilterBindEndpoint(filter);

            if (filter->option.multiport_backend == kMultiportBackendDefault)
            {
                filter->option.multiport_backend = getDefaultMultiPortBackend();
            }

            socket_filter_option_t option   = filter->option;
            uint16_t               port_min = option.port_min;
            uint16_t               port_max = option.port_max;
            if (port_min > port_max)
            {
                LOGF("SocketManager: port min must be lower than port max");
                terminateProgram(1);
            }
            else if (port_min == port_max)
            {
                option.multiport_backend = kMultiportBackendNone;
            }
            {
                if (socketFilterOptionHasPortList(&option))
                {
                    listenUdpPortListSockets(loop, filter, option.host, reg, &option.ports);
                }
                else if (option.multiport_backend == kMultiportBackendIptables)
                {
                    listenUdpMultiPortIptables(loop, filter, option.host, port_min, reg, port_max);
                }
                else if (option.multiport_backend == kMultiportBackendSockets)
                {
                    listenUdpMultiPortSockets(loop, filter, option.host, port_min, reg, port_max);
                }
                else
                {
                    listenUdpSinglePort(loop, filter, option.host, port_min, reg);
                }
            }
        }
    }
}

/**
 * @brief Run a UDP write on the socket-manager worker.
 */
static void runUdpWriteCallback(void *worker_ptr, void *arg1, void *arg2, void *arg3)
{
    discard worker_ptr;
    discard arg2;
    discard arg3;

    udp_payload_t *upl  = arg1;
    udpsock_t     *sock = upl->sock;

    if (sock == NULL || sock->io == NULL || wioIsClosed(sock->io))
    {
        sbufDestroy(upl->buf);
        udppayloadDestroy(upl);
        return;
    }

    int     nwrite = wioWriteDatagram(sock->io, upl->buf, &upl->peer_addr);
    discard nwrite;
    udppayloadDestroy(upl);
}

/**
 * @brief Release a queued UDP write if delivery fails.
 */
static void cleanupUdpWriteDispatch(void *arg1, void *arg2, void *arg3)
{
    udp_payload_t *upl = arg1;
    discard        arg2;
    discard        arg3;

    if (upl != NULL)
    {
        sbufDestroy(upl->buf);
        udppayloadDestroy(upl);
    }
}

void postUdpWrite(udpsock_t *socket_io, wid_t wid_from, sbuf_t *buf, sockaddr_u peer_addr)
{
    if (wid_from == socketmanager_gstate->wid)
    {
        int     nwrite = wioWriteDatagram(socket_io->io, buf, &peer_addr);
        discard nwrite;
        return;
    }

    udp_payload_t *item = newUdpPayload(wid_from);

    *item = (udp_payload_t) {.sock = socket_io, .buf = buf, .wid = wid_from, .peer_addr = peer_addr};

    discard sendWorkerMessageForceQueueWithCleanup(
        socketmanager_gstate->wid, runUdpWriteCallback, cleanupUdpWriteDispatch, item, NULL, NULL);
}

struct socket_manager_s *socketmanagerGet(void)
{
    return socketmanager_gstate;
}

void socketmanagerSet(struct socket_manager_s *new_state)
{
    assert(socketmanager_gstate == NULL);
    socketmanager_gstate = new_state;
}

void socketmanagerStart(void)
{
    assert(socketmanager_gstate != NULL);

    assert(socketmanager_gstate && socketmanager_gstate->worker->loop && ! socketmanager_gstate->started);

    mutexLock(&(socketmanager_gstate->mutex));

    reconcileIptablesStartup();

    // Record only successful binds, so failed attempts never block later endpoint setup.
    endpoint_registry_t registry = endpoint_registry_t_init();

    listenTcp(socketmanager_gstate->worker->loop, &registry);
    listenUdp(socketmanager_gstate->worker->loop, &registry);

    // Install NAT rules specific-before-wildcard after all redirect sockets are known.
    installPendingIptablesRules();

    endpoint_registry_t_drop(&registry);

    socketmanager_gstate->started = true;
    mutexUnlock(&(socketmanager_gstate->mutex));
}

/**
 * @brief Allocate and initialize worker-specific TCP/UDP object pools.
 */
static void initializeSocketManagerPools(void)
{
    socketmanager_gstate->udp_pools =
        memoryAllocateZero(sizeof(*socketmanager_gstate->udp_pools) * getTotalWorkersCount());

    socketmanager_gstate->tcp_pools =
        memoryAllocateZero(sizeof(*socketmanager_gstate->tcp_pools) * getTotalWorkersCount());

    socketmanager_gstate->mp_udp = masterpoolCreateWithCapacity(2 * ((8) + RAM_PROFILE));
    socketmanager_gstate->mp_tcp = masterpoolCreateWithCapacity(2 * ((8) + RAM_PROFILE));

    for (unsigned int i = 0; i < getTotalWorkersCount(); ++i)
    {
        socketmanager_gstate->udp_pools[i] = threadsafegenericpoolCreateWithCapacity(
            socketmanager_gstate->mp_udp, (8) + RAM_PROFILE, allocUdpPayloadPoolHandle, destroyUdpPayloadPoolHandle);

        socketmanager_gstate->tcp_pools[i] = threadsafegenericpoolCreateWithCapacity(socketmanager_gstate->mp_tcp,
                                                                                     (8) + RAM_PROFILE,
                                                                                     allocTcpResultObjectPoolHandle,
                                                                                     destroyTcpResultObjectPoolHandle);
    }
}

/**
 * @brief Detect runtime availability of external socket-routing tools.
 */
static void detectSystemCapabilities(void)
{
#ifdef OS_UNIX
    socketmanager_gstate->iptables_installed = checkCommandAvailable("iptables");
    socketmanager_gstate->lsof_installed     = checkCommandAvailable("lsof");
#if SUPPORT_V6
    socketmanager_gstate->ip6tables_installed = checkCommandAvailable("ip6tables");
#endif
#endif
}

socket_manager_state_t *socketmanagerCreate(void)
{
    assert(socketmanager_gstate == NULL);
    socketmanager_gstate = memoryAllocateZero(sizeof(socket_manager_state_t));

    assert(getWID() == 0);
    socketmanager_gstate->worker = getWorker(0);
    socketmanager_gstate->wid    = 0;

    for (size_t i = 0; i < kFilterLevels; i++)
    {
        socketmanager_gstate->filters[i] = filters_t_init();
    }
    socketmanager_gstate->balance_groups = balancegroup_registry_t_with_capacity(8);
    socketmanager_gstate->pending_rules  = pending_rules_t_init();

    socketmanager_gstate->iptables_owner_lease_fd = -1;

    mutexInit(&socketmanager_gstate->mutex);
    initializeSocketManagerPools();
    detectSystemCapabilities();

    return socketmanager_gstate;
}

/**
 * @brief Close one listener while its event-loop IO storage is still alive.
 */
static void closeOneListenerIo(wio_t *io)
{
    if (io == NULL)
    {
        return;
    }

    wioClose(io);
}

/**
 * @brief Close one listener slot and clear the stored non-owning IO pointer.
 */
static void closeOneListenerSlot(wio_t **io_slot)
{
    assert(io_slot != NULL && *io_slot != NULL);

    closeOneListenerIo(*io_slot);
    *io_slot = NULL;
}

/**
 * @brief Release UDP listener side-data owned by the socket manager.
 */
static void cleanupOneUdpSocket(udpsock_t **socket_slot)
{
    assert(socket_slot != NULL && *socket_slot != NULL);

    udpsock_t *socket = *socket_slot;
    if (socket->idle_tables != NULL)
    {
        for (wid_t wid = 0; wid < getWorkersCount(); ++wid)
        {
            if (socket->idle_tables[wid] != NULL)
            {
                LOGW("SocketManager: destroying UDP socket with active worker-local idle table for worker %u",
                     (unsigned int) wid);
            }
        }
        memoryFree(socket->idle_tables);
        socket->idle_tables = NULL;
    }
    memoryFree(socket);
    *socket_slot = NULL;
}

/**
 * @brief Release all UDP listener side-data for one filter.
 */
static void cleanupFilterUdpSockets(socket_filter_t *filter)
{
    if (filter == NULL)
    {
        return;
    }

    if (filter->listen_udp_sockets != NULL)
    {
        for (size_t i = 0; i < filter->listen_udp_sockets_count; ++i)
        {
            cleanupOneUdpSocket(&filter->listen_udp_sockets[i]);
        }
        memoryFree(filter->listen_udp_sockets);
        filter->listen_udp_sockets       = NULL;
        filter->listen_udp_sockets_count = 0;
        return;
    }
    if (filter->listen_udp_socket != NULL)
    {
        cleanupOneUdpSocket(&filter->listen_udp_socket);
    }
}

/**
 * @brief Drain active UDP listener idle entries for one socket/worker pair.
 */
static void drainOneUdpSocketForWorker(udpsock_t *socket, wid_t wid)
{
    assert(wid == getWID());

    if (socket != NULL && socket->idle_tables != NULL && wid < getWorkersCount())
    {
        local_idle_table_t *table = socket->idle_tables[wid];
        if (table != NULL)
        {
            localidletableDrainItems(table);
            localidletableDestroy(table);
            socket->idle_tables[wid] = NULL;
        }
    }
}

/**
 * @brief Drain active UDP listener idle entries for one filter/worker pair.
 */
static void drainFilterUdpSocketsForWorker(socket_filter_t *filter, wid_t wid)
{
    if (filter == NULL)
    {
        return;
    }

    if (filter->listen_udp_sockets != NULL)
    {
        for (size_t i = 0; i < filter->listen_udp_sockets_count; ++i)
        {
            drainOneUdpSocketForWorker(filter->listen_udp_sockets[i], wid);
        }
        return;
    }

    drainOneUdpSocketForWorker(filter->listen_udp_socket, wid);
}

void socketmanagerDrainUdpIdleForWorker(wid_t wid)
{
    assert(socketmanager_gstate != NULL);

    for (size_t i = 0; i < kFilterLevels; i++)
    {
        c_foreach(filter, filters_t, socketmanager_gstate->filters[i])
        {
            drainFilterUdpSocketsForWorker(*filter.ref, wid);
        }
    }
}

/**
 * @brief Close listeners for a filter while their event-loop IO storage is still alive.
 */
static void cleanupFilterListenersForLiveLoop(socket_filter_t *filter, wloop_t *loop)
{
    if (filter == NULL || loop == NULL)
    {
        return;
    }

    if (filter->listen_ios != NULL)
    {
        for (size_t ios_i = 0; ios_i < filter->listen_ios_count; ++ios_i)
        {
            wio_t *io = filter->listen_ios[ios_i];
            if (io != NULL && weventGetLoop(io) == loop)
            {
                closeOneListenerSlot(&filter->listen_ios[ios_i]);
            }
        }
        return;
    }

    if (filter->listen_io != NULL && weventGetLoop(filter->listen_io) == loop)
    {
        closeOneListenerSlot(&filter->listen_io);
    }
}

void socketmanagerCloseListenersForLoop(wloop_t *loop)
{
    if (socketmanager_gstate == NULL || loop == NULL)
    {
        return;
    }

    for (size_t i = 0; i < kFilterLevels; i++)
    {
        c_foreach(filter, filters_t, socketmanager_gstate->filters[i])
        {
            cleanupFilterListenersForLiveLoop(*filter.ref, loop);
        }
    }
}

/**
 * @brief Destroy all registered filters and associated listener sockets.
 */
static void cleanupFilters(void)
{
    for (size_t i = 0; i < kFilterLevels; i++)
    {
        c_foreach(filter, filters_t, socketmanager_gstate->filters[i])
        {
            socket_filter_t *f = *filter.ref;

            if (f->listen_ios != NULL)
            {
                wloop_t *loop = socketmanager_gstate->worker != NULL ? socketmanager_gstate->worker->loop : NULL;
                if (loop != NULL)
                {
                    cleanupFilterListenersForLiveLoop(f, loop);
                }
                memoryFree((void *) f->listen_ios);
            }
            else
            {
                wloop_t *loop = socketmanager_gstate->worker != NULL ? socketmanager_gstate->worker->loop : NULL;
                if (loop != NULL)
                {
                    cleanupFilterListenersForLiveLoop(f, loop);
                }
            }

            cleanupFilterUdpSockets(f);
            socketfilteroptionDeInit(&(f->option));
            memoryFree(f);
        }
        filters_t_drop(&(socketmanager_gstate->filters[i]));
    }
}

/**
 * @brief Destroy all shared balance-group idle tables.
 */
static void destroyBalanceGroups(void)
{
    c_foreach(bg, balancegroup_registry_t, socketmanager_gstate->balance_groups)
    {
        idletableDestroy(bg.ref->second);
    }
    balancegroup_registry_t_drop(&socketmanager_gstate->balance_groups);
}

/**
 * @brief Destroy socket manager pools and synchronization primitives.
 */
static void destroyPools(void)
{
    for (unsigned int i = 0; i < getTotalWorkersCount(); ++i)
    {
        threadsafegenericpoolDestroy(socketmanager_gstate->udp_pools[i]);
        threadsafegenericpoolDestroy(socketmanager_gstate->tcp_pools[i]);
    }

    memoryFree(socketmanager_gstate->udp_pools);
    memoryFree(socketmanager_gstate->tcp_pools);
    masterpoolMakeEmpty(socketmanager_gstate->mp_tcp);
    masterpoolMakeEmpty(socketmanager_gstate->mp_udp);
    masterpoolDestroy(socketmanager_gstate->mp_tcp);
    masterpoolDestroy(socketmanager_gstate->mp_udp);
}

void socketmanagerDestroy(void)
{
    assert(socketmanager_gstate != NULL);

    if (socketmanager_gstate->iptables_used || socketmanager_gstate->iptables_published)
    {
        if (! cleanupOwnedIptablesChainsWithReconcileLock(true))
        {
            const char msg[] = "SocketManager: failed to fully remove owned iptables nat rules\n";
            ssize_t    n     = write(STDOUT_FILENO, msg, sizeof(msg) - 1);
            discard n;
        }
    }
    socketManagerIptablesReleaseLease(&socketmanager_gstate->iptables_owner_lease_fd);

    cleanupFilters();
    destroyBalanceGroups();
    pending_rules_t_drop(&socketmanager_gstate->pending_rules);
    destroyPools();
    memoryFree(socketmanager_gstate);
    socketmanager_gstate = NULL;
}

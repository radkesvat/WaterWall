/*
 * Socket listener manager for filtered TCP/UDP accept and worker dispatch.
 */

#include "socket_manager_internal.h"

#include "global_state.h"
#include "local_widle_table.h"
#include "loggers/internal_logger.h"
#include "socket_manager_iptables_recovery.h"
#include "stc/common.h"
#include "threadsafe_generic_pool.h"
#include "tunnel.h"
#include "wevent.h"
#include "wfrand.h"
#include "widle_table.h"
#include "wloop.h"
#include "wmutex.h"
#include "wproc.h"
#include "wthread.h"

#define i_type balancegroup_registry_t // NOLINT
#define i_key  hash_t                  // NOLINT
#define i_val  idle_table_t *          // NOLINT

#include "stc/hmap.h"

// NAT redirect rule queued during listener setup and installed after sorting.
typedef struct pending_iptables_rule_s
{
    uint8_t     protocol;   // IPPROTO_TCP / IPPROTO_UDP
    uint8_t     family;     // AF_INET / AF_INET6
    bool        has_dest;   // emit -d <ip> (never for wildcard)
    bool        dual_stack; // AF_INET6 wildcard (::) that also accepts IPv4-mapped traffic
    char        dest[64];   // destination address text when has_dest
    const char *iface_name; // emit -i <iface> when set
    uint16_t    port_min;
    uint16_t    port_max;
    uint16_t    to_port;
    int         sort_rank; // lower installs first (specific+iface < specific < wildcard+iface < wildcard)
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
    kSoOriginalDest = 80
};

typedef struct socket_manager_s
{
    filters_t filters[kFilterLevels];
    endpoint_registry_t endpoints;

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

#ifdef WW_SOCKET_MANAGER_CONSTRUCTOR_TEST_SEAM
bool socketManagerConstructorTestFailAfterMutex(void);
#endif

#ifdef WW_SOCKET_MANAGER_REGISTRATION_TEST_SEAM
bool socketManagerRegistrationTestFailPublication(void);
void socketManagerRegistrationTestUnpublishedOptionReleased(void);
void socketManagerRegistrationTestSetStarted(bool started);

void socketManagerRegistrationTestSetStarted(bool started)
{
    assert(socketmanager_gstate != NULL);
    socketmanager_gstate->started = started;
}
#endif

static void distributeTcpSocket(wio_t *io, uint16_t local_port, const ip_addr_t *local_addr);

static void distributeUdpPayload(udp_payload_t pl, const listener_endpoint_t *endpoint);

static const char *getSocketBindHost(socket_filter_t *filter, const char *host, char *host_if);

local_idle_table_t *udpsockGetWorkerIdleTable(udpsock_t *socket)
{
    assert(socket != NULL);
    assert(socket->idle_tables != NULL);

    // Worker-local table: one checked identity drives both the per-worker array
    // and the loop the table is armed on. A non-event thread fails loudly here
    // instead of quietly creating a table on worker 0's loop.
    const wid_t wid = getCurrentEventWorkerWID();
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
 * @brief Prepare UDP listener side-data before acquiring its socket.
 */
static udpsock_t *createUdpSocketSideData(void)
{
    udpsock_t *socket = memoryAllocate(sizeof(*socket));
    if (UNLIKELY(socket == NULL))
    {
        return NULL;
    }

    socket->idle_tables = memoryAllocateZero(sizeof(*socket->idle_tables) * getWorkersCount());
    if (UNLIKELY(socket->idle_tables == NULL))
    {
        memoryFree(socket);
        return NULL;
    }

    socket->io          = NULL;
    socket->listener_fd = -1;
    socket->owner_slot  = NULL;
    atomic_init(&socket->retired, false);
    return socket;
}

static void drainRetiredUdpSocket(void *worker_ptr, void *arg1, void *arg2, void *arg3)
{
    worker_t *worker = worker_ptr;
    discard   arg2;
    discard   arg3;
    socketmanagerDrainUdpSocketForWorker(arg1, worker->wid);
}

void udpsockRetire(udpsock_t *socket)
{
    if (atomic_exchange_explicit(&socket->retired, true, memory_order_acq_rel))
        return;
    socket->io = NULL;
    if (socket->owner_slot != NULL)
        *socket->owner_slot = NULL;
    for (wid_t wid = 0; wid < getWorkersCount(); ++wid)
    {
        /* Never drain inline: the close can occur inside this table's expiry
         * callback. Cancellation during shutdown is covered by owner drain.
         * Enqueue pressure retains the existing finite idle deadlines; writes
         * and receives on a retired socket cannot extend or create entries. */
        const worker_message_submit_result_e result =
            sendWorkerMessageForceQueueWithCleanup(wid, drainRetiredUdpSocket, NULL, socket, NULL, NULL);
        discard result;
    }
}

static void onListenerSocketClose(wio_t *io)
{
    listener_endpoint_t *endpoint = weventGetUserdata(io);
    endpoint->listen_io           = NULL;
    weventSetUserData(io, NULL);
    wioSetCallBackRead(io, NULL);
    wioSetCallBackClose(io, NULL);
    if (endpoint->udp_socket != NULL)
        udpsockRetire(endpoint->udp_socket);
}

static bool startUdpListener(wio_t *io, wread_cb read_cb)
{
    wioSetCallBackRead(io, read_cb);
    return wioRead(io) == 0;
}

static void runAcceptedSocketCallback(void *worker_ptr, void *arg1, void *arg2, void *arg3);
static void cleanupAcceptedSocketDispatch(void *arg1, void *arg2, void *arg3, worker_message_cancel_reason_e reason);
static void runUdpPayloadCallback(void *worker_ptr, void *arg1, void *arg2, void *arg3);
static void cleanupUdpPayloadDispatch(void *arg1, void *arg2, void *arg3, worker_message_cancel_reason_e reason);
static void runUdpWriteCallback(void *worker_ptr, void *arg1, void *arg2, void *arg3);
static void cleanupUdpWriteDispatch(void *arg1, void *arg2, void *arg3, worker_message_cancel_reason_e reason);

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
    // Every generated command carries a numeric xtables-lock wait so iptables
    // never blocks indefinitely; the parent-side deadline remains authoritative.
    const int wait = kSocketManagerIptablesLockWaitSeconds;
    switch (action)
    {
    case kSocketManagerIptablesCreateChain:
        snprintf(out, out_len, "%s -w %d -t nat -N %s", tool, wait, chain_name);
        return;
    case kSocketManagerIptablesAddJump:
        snprintf(out, out_len, "%s -w %d -t nat -A PREROUTING -j %s", tool, wait, chain_name);
        return;
    case kSocketManagerIptablesDeleteJump:
        snprintf(out, out_len, "%s -w %d -t nat -D PREROUTING -j %s", tool, wait, chain_name);
        return;
    case kSocketManagerIptablesFlushChain:
        snprintf(out, out_len, "%s -w %d -t nat -F %s", tool, wait, chain_name);
        return;
    case kSocketManagerIptablesDeleteChain:
        snprintf(out, out_len, "%s -w %d -t nat -X %s", tool, wait, chain_name);
        return;
    }

    assert(false);
    LOGF("socketManagerBuildOwnedChainCommand: invalid iptables chain action %u", (unsigned int) action);
    abortProgramNow(1);
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
             "%s -w %d -t nat -A %s -p %s%s%s --dport %s -j REDIRECT --to-port %u",
             tool,
             kSocketManagerIptablesLockWaitSeconds,
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
 * @brief Run one iptables/ip6tables mutation command through the bounded, deadline-aware supervisor.
 *
 * Returns true only for a clean zero exit. A timeout is logged distinctly from a normal nonzero
 * exit (which the caller reports) and surfaced via @p timed_out; the captured result is always freed.
 */
static bool runBoundedIptablesShellCommand(const char *command, bool *timed_out)
{
    socket_manager_iptables_cmd_output_t out;
    const bool ok = socketManagerIptablesRunShellCommand(command, kSocketManagerIptablesCommandTimeoutMs, &out);
    if (timed_out != NULL)
    {
        *timed_out = out.timed_out;
    }
    if (! ok && out.timed_out)
    {
        LOGE("SocketManager: iptables command timed out after %dms: %s",
             kSocketManagerIptablesCommandTimeoutMs,
             command);
    }
    socketManagerIptablesCmdOutputDrop(&out);
    return ok;
}

/**
 * @brief Execute one lifecycle operation for a socket-manager-owned chain, reporting a timeout.
 */
static bool runOwnedChainCommandEx(const char *tool, socket_manager_iptables_chain_action_t action,
                                   const owned_iptables_chain_t *chain, bool *timed_out)
{
    char command[128];
    socketManagerBuildOwnedChainCommand(command, sizeof(command), tool, action, chain->name);
    return runBoundedIptablesShellCommand(command, timed_out);
}

/**
 * @brief Execute one lifecycle operation for a socket-manager-owned chain.
 */
static bool runOwnedChainCommand(const char *tool, socket_manager_iptables_chain_action_t action,
                                 const owned_iptables_chain_t *chain)
{
    return runOwnedChainCommandEx(tool, action, chain, NULL);
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
        discard    n;
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

// Per-pass state for stale-chain cleanup. Once a cleanup command for a family
// times out, its iptables tooling is treated as stuck for the rest of the pass
// so later operations for that family fail without spawning another child that
// would just time out again. The other family is handled independently.
typedef struct recovery_cleanup_ctx_s
{
    bool v4_unavailable;
    bool v6_unavailable;
} recovery_cleanup_ctx_t;

static bool runRecoveryCleanupOp(const socket_manager_iptables_cleanup_op_t *op, void *userdata)
{
    recovery_cleanup_ctx_t *ctx  = userdata;
    const char             *tool = op->family == 4 ? "iptables" : "ip6tables";

    if (ctx != NULL && ((op->family == 4 && ctx->v4_unavailable) || (op->family == 6 && ctx->v6_unavailable)))
    {
        LOGE("SocketManager: skipping stale iptables cleanup action %d for %s after a prior family timeout",
             (int) op->action,
             op->chain_name);
        return false;
    }

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
    bool       timed_out = false;
    const bool ok        = runOwnedChainCommandEx(tool, action, &chain, &timed_out);
    if (! ok)
    {
        LOGE("SocketManager: failed stale iptables cleanup action %d for %s", (int) op->action, op->chain_name);
        if (timed_out && ctx != NULL)
        {
            if (op->family == 4)
            {
                ctx->v4_unavailable = true;
            }
            else if (op->family == 6)
            {
                ctx->v6_unavailable = true;
            }
        }
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
    recovery_probe_leases_t                     *leases = userdata;
    int                                          fd     = -1;
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
    *held_fd                     = -1;
    return kSocketManagerIptablesLeaseAcquired;
}

// Print safe, ordered manual cleanup instructions for any linked chain left by an
// older WaterWall release. WaterWall never mutates these chains; it only tells the
// operator how to remove them. Chain names have passed the strict legacy parser, so
// they are safe to interpolate into the printed commands (they are printed, not run).
static void reportLegacyIptablesBlockers(const socket_manager_iptables_cleanup_plan_t *plan)
{
    for (size_t i = 0; i < plan->blocker_count; ++i)
    {
        const socket_manager_iptables_legacy_blocker_t *blocker = &plan->blockers[i];
        const char                                     *tool    = blocker->family == 4 ? "iptables" : "ip6tables";

        LOGE("SocketManager: found a linked iptables chain \"%s\" (family %d) created by an older WaterWall release",
             blocker->chain_name,
             blocker->family);
        LOGE("SocketManager: it was intentionally left unchanged; new ipv%d iptables rules will not be published "
             "until it is removed",
             blocker->family);

        if (blocker->unexpected_reference)
        {
            LOGE("SocketManager: \"%s\" has references that are not a simple PREROUTING jump; inspect every reference "
                 "first with:",
                 blocker->chain_name);
            LOGE("SocketManager:   %s -w %d -t nat -S", tool, kSocketManagerIptablesLockWaitSeconds);
            LOGE("SocketManager: remove every reference to \"%s\" before flushing or deleting it", blocker->chain_name);
            continue;
        }

        // A non-unexpected blocker always has at least one exact PREROUTING jump. Print
        // the delete-jump command once per jump so the commands run correctly in order:
        // every reference must be removed before the flush and delete can succeed.
        LOGE("SocketManager: remove it manually with:");
        if (blocker->prerouting_jumps > 1)
        {
            LOGE(
                "SocketManager: (there are %lu PREROUTING jumps, so the delete-jump command is repeated once per jump)",
                (unsigned long) blocker->prerouting_jumps);
        }
        for (size_t j = 0; j < blocker->prerouting_jumps; ++j)
        {
            LOGE("SocketManager:   %s -w %d -t nat -D PREROUTING -j %s",
                 tool,
                 kSocketManagerIptablesLockWaitSeconds,
                 blocker->chain_name);
        }
        LOGE(
            "SocketManager:   %s -w %d -t nat -F %s", tool, kSocketManagerIptablesLockWaitSeconds, blocker->chain_name);
        LOGE(
            "SocketManager:   %s -w %d -t nat -X %s", tool, kSocketManagerIptablesLockWaitSeconds, blocker->chain_name);
    }
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
        include_v4 =
            socketManagerIptablesRunInspectCommand("iptables", kSocketManagerIptablesCommandTimeoutMs, &v4_snapshot);
        socketmanager_gstate->iptables_v4_reconciled = include_v4;
        if (! include_v4)
        {
            if (v4_snapshot.timed_out)
            {
                LOGE("SocketManager: ipv4 iptables inspection timed out after %dms; recovery for this family failed",
                     kSocketManagerIptablesCommandTimeoutMs);
            }
            else
            {
                LOGW("SocketManager: could not inspect ipv4 iptables nat table for stale WaterWall chains");
            }
        }
    }
    if (do_v6)
    {
        include_v6 =
            socketManagerIptablesRunInspectCommand("ip6tables", kSocketManagerIptablesCommandTimeoutMs, &v6_snapshot);
        socketmanager_gstate->iptables_v6_reconciled = include_v6;
        if (! include_v6)
        {
            if (v6_snapshot.timed_out)
            {
                LOGE("SocketManager: ipv6 iptables inspection timed out after %dms; recovery for this family failed",
                     kSocketManagerIptablesCommandTimeoutMs);
            }
            else
            {
                LOGW("SocketManager: could not inspect ipv6 iptables nat table for stale WaterWall chains");
            }
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

    // Any linked legacy chain fails its family above; tell the operator how to clean it up.
    reportLegacyIptablesBlockers(&plan);

    recovery_cleanup_ctx_t cleanup_ctx;
    memoryZero(&cleanup_ctx, sizeof(cleanup_ctx));
    if (! socketManagerIptablesExecuteCleanupPlan(&plan, runRecoveryCleanupOp, &cleanup_ctx, &v4_ok, &v6_ok))
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
        const char c  = *p;
        const bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' ||
                        c == ':' || c == '/' || c == '-' || c == '_' || c == '%';
        if (! ok)
        {
            return false;
        }
    }
    return true;
}

static void generateIptablesOwnerToken(void)
{
    uint64_t token                             = fastRand64();
    socketmanager_gstate->iptables_owner_token = token;
    socketManagerIptablesFormatChainName(
        token, 4, socketmanager_gstate->iptables_v4_chain.name, sizeof(socketmanager_gstate->iptables_v4_chain.name));
    socketManagerIptablesFormatChainName(
        token, 6, socketmanager_gstate->iptables_v6_chain.name, sizeof(socketmanager_gstate->iptables_v6_chain.name));
}

static bool acquireIptablesOwnerLease(void)
{
    if (socketmanager_gstate->iptables_owner_lease_fd >= 0)
    {
        return true;
    }

    for (int attempt = 0; attempt < 16; ++attempt)
    {
        generateIptablesOwnerToken();

        int                                          fd = -1;
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
        startupFailureRecord(1);
        return;
    }
#if SUPPORT_V6
    if (pendingIptablesNeedsFamily(6) &&
        (! socketmanager_gstate->iptables_reconciliation_attempted || ! socketmanager_gstate->iptables_v6_reconciled))
    {
        LOGF("SocketManager: refusing to install ipv6 iptables rules after failed startup recovery");
        startupFailureRecord(1);
        return;
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
    rule.iface_name = (filter->option.interface_name != NULL && filter->option.interface_name[0] != '\0')
                          ? filter->option.interface_name
                          : NULL;

    if (rule.iface_name != NULL && ! isSafeIptablesToken(rule.iface_name))
    {
        LOGF("SocketManager: unsafe interface name \"%s\" for iptables rule", rule.iface_name);
        startupFailureRecord(1);
        return;
    }

    if (! filter->bind_is_wildcard)
    {
        char        host_if[INET_ADDRSTRLEN] = {0};
        const char *host                     = getSocketBindHost(filter, filter->option.host, host_if);
        if (UNLIKELY(startupFailurePending()))
        {
            return;
        }
        if (host != NULL && host[0] != '\0')
        {
            if (! isSafeIptablesToken(host))
            {
                LOGF("SocketManager: unsafe destination host \"%s\" for iptables rule", host);
                startupFailureRecord(1);
                return;
            }
            rule.has_dest = true;
            snprintf(rule.dest, sizeof(rule.dest), "%s", host);
        }
    }

    rule.sort_rank = socketManagerComputeRedirectRuleRank(rule.has_dest, rule.iface_name != NULL);

    if (UNLIKELY(pending_rules_t_push(&socketmanager_gstate->pending_rules, rule) == NULL))
    {
        LOGF("SocketManager: failed to record a required pending iptables rule");
        startupFailureRecord(1);
        return;
    }
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
        return runBoundedIptablesShellCommand(command, NULL);
    }

#if SUPPORT_V6
    if (rule->family == AF_INET6)
    {
        bool result = true;

        if (rule->dual_stack)
        {
            owned_iptables_chain_t *chain = &socketmanager_gstate->iptables_v4_chain;
            buildIptablesCommand(command, sizeof(command), "iptables", proto_token, chain->name, rule);
            result = runBoundedIptablesShellCommand(command, NULL);
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
        return runBoundedIptablesShellCommand(command, NULL);
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
    if (UNLIKELY(startupFailurePending()))
    {
        return;
    }

    int lock_fd = -1;
    if (! socketManagerIptablesAcquireReconcileLock(&lock_fd, 5000))
    {
        LOGF("SocketManager: failed to acquire iptables reconciliation lock for rule publication");
        startupFailureRecord(1);
        return;
    }

    if (! acquireIptablesOwnerLease())
    {
        socketManagerIptablesReleaseLease(&lock_fd);
        startupFailureRecord(1);
        return;
    }

    const bool needs_v4 = pendingIptablesNeedsFamily(4);
    const bool needs_v6 = pendingIptablesNeedsFamily(6);

    if (needs_v4 && ! createOwnedIptablesChain("iptables", &socketmanager_gstate->iptables_v4_chain))
    {
        LOGF("SocketManager: failed to create ipv4 iptables chain %s", socketmanager_gstate->iptables_v4_chain.name);
        socketManagerIptablesReleaseLease(&lock_fd);
        startupFailureRecord(1);
        return;
    }
#if SUPPORT_V6
    if (needs_v6 && ! createOwnedIptablesChain("ip6tables", &socketmanager_gstate->iptables_v6_chain))
    {
        LOGF("SocketManager: failed to create ipv6 iptables chain %s", socketmanager_gstate->iptables_v6_chain.name);
        cleanupOwnedIptablesChains(false);
        socketManagerIptablesReleaseLease(&lock_fd);
        startupFailureRecord(1);
        return;
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
                startupFailureRecord(1);
                return;
            }
        }
    }

    if (needs_v4 && ! publishOwnedIptablesChain("iptables", &socketmanager_gstate->iptables_v4_chain))
    {
        LOGF("SocketManager: failed to publish ipv4 iptables chain %s", socketmanager_gstate->iptables_v4_chain.name);
        cleanupOwnedIptablesChains(false);
        socketManagerIptablesReleaseLease(&lock_fd);
        startupFailureRecord(1);
        return;
    }
#if SUPPORT_V6
    if (needs_v6 && ! publishOwnedIptablesChain("ip6tables", &socketmanager_gstate->iptables_v6_chain))
    {
        LOGF("SocketManager: failed to publish ipv6 iptables chain %s", socketmanager_gstate->iptables_v6_chain.name);
        cleanupOwnedIptablesChains(false);
        socketManagerIptablesReleaseLease(&lock_fd);
        startupFailureRecord(1);
        return;
    }
#endif

    socketmanager_gstate->iptables_published = needs_v4 || needs_v6;
    socketManagerIptablesReleaseLease(&lock_fd);
    pending_rules_t_clear(&socketmanager_gstate->pending_rules);
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

static void socketacceptorReleaseUnpublishedOption(socket_filter_option_t *option)
{
    socketfilteroptionDeInit(option);
#ifdef WW_SOCKET_MANAGER_REGISTRATION_TEST_SEAM
    socketManagerRegistrationTestUnpublishedOptionReleased();
#endif
}

/**
 * @brief Whether the filter uses an explicit port list.
 */
static bool socketFilterOptionHasPortList(const socket_filter_option_t *option)
{
    return vec_listener_port_t_size(&option->ports) > 0;
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
        const isize_t required = balancegroup_registry_t_size(&socketmanager_gstate->balance_groups) + 1;
        if (UNLIKELY(! balancegroup_registry_t_reserve(&socketmanager_gstate->balance_groups, required) ||
                     balancegroup_registry_t_capacity(&socketmanager_gstate->balance_groups) < required))
        {
            mutexUnlock(&(socketmanager_gstate->mutex));
            return NULL;
        }

        b_table = idleTableCreate(socketmanager_gstate->worker->loop);
        if (UNLIKELY(b_table == NULL))
        {
            mutexUnlock(&(socketmanager_gstate->mutex));
            return NULL;
        }
        balancegroup_registry_t_result inserted =
            balancegroup_registry_t_insert(&(socketmanager_gstate->balance_groups), name_hash, b_table);
        if (UNLIKELY(inserted.ref == NULL || ! inserted.inserted))
        {
            idletableDestroy(b_table);
            b_table = NULL;
        }
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
        socketacceptorReleaseUnpublishedOption(&option);
        startupFailureRecord(1);
        return;
    }

    socket_filter_t *filter   = memoryAllocate(sizeof(socket_filter_t));
    unsigned int     priority = calculateFilterPriority(option);

    if (UNLIKELY(filter == NULL))
    {
        LOGF("SocketManager: failed to allocate listener filter metadata");
        socketacceptorReleaseUnpublishedOption(&option);
        startupFailureRecord(1);
        return;
    }

    idle_table_t *balance_table = NULL;
    if (option.balance_group_name)
    {
        balance_table = getOrCreateBalanceTable(option.balance_group_name);
        if (UNLIKELY(balance_table == NULL))
        {
            memoryFree(filter);
            LOGF("SocketManager: failed to create balance-group metadata");
            socketacceptorReleaseUnpublishedOption(&option);
            startupFailureRecord(1);
            return;
        }
    }

    *filter = (socket_filter_t) {.tunnel = tunnel, .option = option, .cb = cb, .balance_table = balance_table};

    mutexLock(&(socketmanager_gstate->mutex));
    filters_t *filters  = &socketmanager_gstate->filters[priority];
    isize_t    required = filters_t_size(filters) + 1;
#ifdef WW_SOCKET_MANAGER_REGISTRATION_TEST_SEAM
    const bool test_fail_publication = socketManagerRegistrationTestFailPublication();
#else
    const bool test_fail_publication = false;
#endif
    if (UNLIKELY(test_fail_publication || ! filters_t_reserve(filters, required) ||
                 filters_t_capacity(filters) < required || filters_t_push(filters, filter) == NULL))
    {
        mutexUnlock(&(socketmanager_gstate->mutex));
        socketacceptorReleaseUnpublishedOption(&filter->option);
        memoryFree(filter);
        LOGF("SocketManager: failed to publish listener filter metadata");
        startupFailureRecord(1);
        return;
    }
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
static void cleanupAcceptedSocketDispatch(void *arg1, void *arg2, void *arg3, worker_message_cancel_reason_e reason)
{
    discard                 reason;
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
        const int  effective_mark = option->fwmark >= 0 ? option->fwmark : 0;
        int        current_mark   = 0;
        const bool have_current   = socketOptionGetFwMark(wioGetFD(io), &current_mark);
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

/**
 * @brief Select a TCP listener, apply its options, then transfer the accepted WIO.
 */
static void distributeTcpSocket(wio_t *io, uint16_t local_port, const ip_addr_t *local_addr)
{
    listener_arrival_t arrival = {.endpoint   = weventGetUserdata(io),
                                  .local_addr = *local_addr,
                                  .local_port = local_port,
                                  .protocol   = IPPROTO_TCP};
    if (! sockaddrToNormalizedIpAddr(wioGetPeerAddrU(io), &arrival.peer_addr))
    {
        wioClose(io);
        return;
    }
    listener_selection_t selection =
        socketManagerSelect(socketmanager_gstate->filters, socketmanager_gstate->wid, &arrival);
    if (selection.filter == NULL)
    {
        noTcpSocketConsumerFound(io);
        return;
    }
    if (! applyAcceptedTcpSocketOptions(io, &selection.filter->option))
    {
        wioClose(io);
        return;
    }
    socketManagerCommitSelection(socketmanager_gstate->wid, &selection);
    distributeSocket(io, selection.filter, local_port);
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
        startupFailureRecord(1);
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

    if (! getInterfaceHostString(filter->option.interface_name, host_if))
    {
        return NULL;
    }
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
    if (UNLIKELY(startupFailurePending()))
    {
        return;
    }

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
            family = (addr.type == IPADDR_TYPE_V6) ? AF_INET6 : AF_INET;
            normalizeIpAddr(&addr);
            wildcard = ipAddrIsWildcard(&addr);
        }
    }

    filter->bind_addr           = addr;
    filter->bind_family         = family;
    filter->bind_is_wildcard    = wildcard;
    filter->bind_endpoint_ready = true;
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
static listener_endpoint_t *endpointRegistryFind(endpoint_registry_t *reg, uint8_t protocol, socket_filter_t *filter,
                                                 uint16_t port)
{
    computeFilterBindEndpoint(filter);
    const char *iface = filterInterfaceScope(filter);

    c_foreach(it, endpoint_registry_t, *reg)
    {
        listener_endpoint_t *ep = *it.ref;
        if (ep->listen_io == NULL || ep->protocol != protocol || ep->port != port)
        {
            continue;
        }
        if (ep->family != filter->bind_family || ep->is_wildcard != filter->bind_is_wildcard)
        {
            continue;
        }
        if (! interfaceScopeEquals(ep->interface_scope, iface))
        {
            continue;
        }
        if (! ep->is_wildcard && ! ipAddrEqualsExact(&ep->bind_addr, &filter->bind_addr))
        {
            continue;
        }
        return ep;
    }
    return NULL;
}

/* Consume an unpublished, caller-owned endpoint. No socket or callbacks may
 * have been attached to it. */
static void releaseUnpublishedEndpoint(listener_endpoint_t *endpoint)
{
    if (endpoint->udp_socket != NULL)
    {
        memoryFree(endpoint->udp_socket->idle_tables);
        memoryFree(endpoint->udp_socket);
    }
    memoryFree(endpoint->interface_scope);
    memoryFree(endpoint);
}

/* Prepare fallible metadata before acquiring a socket. A non-NULL result is
 * caller-owned until publishEndpoint() or releaseUnpublishedEndpoint(). */
static listener_endpoint_t *prepareEndpoint(endpoint_registry_t *reg, socket_filter_t *filter, uint8_t protocol,
                                            uint16_t port)
{
    computeFilterBindEndpoint(filter);
    if (UNLIKELY(startupFailurePending()))
        return NULL;
    const isize_t required = endpoint_registry_t_size(reg) + 1;
    if (UNLIKELY(! endpoint_registry_t_reserve(reg, required) || endpoint_registry_t_capacity(reg) < required))
        goto failed;
    listener_endpoint_t *endpoint = memoryAllocateZero(sizeof(*endpoint));
    if (UNLIKELY(endpoint == NULL))
        goto failed;
    *endpoint         = (listener_endpoint_t) {.protocol         = protocol,
                                               .family           = filter->bind_family,
                                               .is_wildcard      = filter->bind_is_wildcard,
                                               .bind_addr        = filter->bind_addr,
                                               .port             = port,
                                               .fwmark           = filter->option.fwmark,
                                               .send_buffer_size = filter->option.send_buffer_size,
                                               .recv_buffer_size = filter->option.recv_buffer_size};
    const char *scope = filterInterfaceScope(filter);
    if (scope != NULL)
    {
        endpoint->interface_scope = stringDuplicate(scope);
        if (UNLIKELY(endpoint->interface_scope == NULL))
        {
            releaseUnpublishedEndpoint(endpoint);
            goto failed;
        }
    }
    if (protocol == IPPROTO_UDP)
    {
        endpoint->udp_socket = createUdpSocketSideData();
        if (UNLIKELY(endpoint->udp_socket == NULL))
        {
            releaseUnpublishedEndpoint(endpoint);
            goto failed;
        }
        endpoint->udp_socket->owner_slot = &endpoint->listen_io;
    }
    return endpoint;
failed:
    LOGF("SocketManager: failed to prepare listener endpoint metadata before binding");
    startupFailureRecord(1);
    return NULL;
}

/* Startup is exclusive. Publish the sole owner and initialize callbacks before
 * enabling accept/read; no fallible allocation remains in this publication.
 * Consumes endpoint and io on every result: success transfers both to reg;
 * false closes io and frees endpoint. Neither remains caller-owned. */
static bool publishEndpoint(endpoint_registry_t *reg, listener_endpoint_t *endpoint, wio_t *io)
{
    sockaddr_u bound_addr = {0};
    socklen_t  bound_len  = sizeof(bound_addr);
    if (getsockname(wioGetFD(io), &bound_addr.sa, &bound_len) != 0)
    {
        wioClose(io);
        releaseUnpublishedEndpoint(endpoint);
        LOGF("SocketManager: could not snapshot bound listener address");
        startupFailureRecord(1);
        return false;
    }
    endpoint->port = sockaddrPort(&bound_addr);
    wioSetLocaladdr(io, &bound_addr.sa, (int) bound_len);
    assert(endpoint_registry_t_size(reg) < endpoint_registry_t_capacity(reg));
    if (UNLIKELY(endpoint_registry_t_push(reg, endpoint) == NULL))
    {
        LOGF("SocketManager: reserved listener endpoint publication failed");
        abortProgramNow(1);
    }
    endpoint->listen_io = io;
    if (endpoint->udp_socket != NULL)
    {
        endpoint->udp_socket->io          = io;
        endpoint->udp_socket->listener_fd = wioGetFD(io);
    }
    weventSetUserData(io, endpoint);
    wioSetCallBackClose(io, onListenerSocketClose);
    return true;
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
        startupFailureRecord(1);
        return;
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
            if (UNLIKELY(startupFailurePending()))
            {
                return;
            }
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
        const listener_endpoint_t *ep = *it.ref;
        if (ep->listen_io == NULL || ep->protocol != IPPROTO_TCP || ! ep->is_wildcard || ep->port != port)
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
        // Deferral follows the normalized destination family: a mapped IPv4
        // specific bind can be served by an existing IPv4 wildcard socket.
        return registryHasBoundTcpWildcard(reg, port, iface, filter->bind_addr.type == IPADDR_TYPE_V6);
    }

    // A 0.0.0.0 wildcard defers only to a bound :: dual-stack wildcard.
    if (filter->bind_family == AF_INET)
    {
        return registryHasBoundTcpWildcard(reg, port, iface, true);
    }
    return false;
}

/**
 * @brief Create a TCP listener with a persistent owner before enabling accept.
 */
static listener_endpoint_t *createTcpListener(wloop_t *loop, socket_filter_t *filter, char *host, uint16_t port,
                                              endpoint_registry_t *reg, waccept_cb callback)
{
    listener_endpoint_t *endpoint = prepareEndpoint(reg, filter, IPPROTO_TCP, port);
    if (endpoint == NULL)
        return NULL;
    char        host_if[INET_ADDRSTRLEN] = {0};
    const char *bind_host                = getSocketBindHost(filter, host, host_if);
    if (UNLIKELY(startupFailurePending()))
    {
        releaseUnpublishedEndpoint(endpoint);
        return NULL;
    }
    wio_t *io = wioCreateSocketWithOptions(
        loop, bind_host, port, WIO_TYPE_TCP, WIO_SERVER_SIDE, filter->option.interface_name, filter->option.fwmark);
    if (io == NULL)
    {
        releaseUnpublishedEndpoint(endpoint);
        return NULL;
    }
    if (! publishEndpoint(reg, endpoint, io))
        return NULL;
    wioSetCallBackAccept(io, callback);
    /* wioAccept closes on failure. The endpoint remains owned for rollback,
     * with a NULL authoritative slot, and cannot be reused as a bound socket. */
    if (wioAccept(io) != 0)
        return NULL;
    return endpoint;
}

/**
 * @brief Create a UDP listener with side-data/userdata before enabling reads.
 *
 * After publication, read-setup failure closes the socket but leaves its
 * endpoint and side-data owned by reg for rollback.
 */
static listener_endpoint_t *createUdpListener(wloop_t *loop, socket_filter_t *filter, char *host, uint16_t port,
                                              endpoint_registry_t *reg, wread_cb callback, bool stop_on_read_failure)
{
    listener_endpoint_t *endpoint = prepareEndpoint(reg, filter, IPPROTO_UDP, port);
    if (endpoint == NULL)
        return NULL;
    char        host_if[INET_ADDRSTRLEN] = {0};
    const char *bind_host                = getSocketBindHost(filter, host, host_if);
    if (UNLIKELY(startupFailurePending()))
    {
        releaseUnpublishedEndpoint(endpoint);
        return NULL;
    }
    wio_t *io = wloopCreateUdpServerWithBufferOptions(loop,
                                                      bind_host,
                                                      port,
                                                      filter->option.interface_name,
                                                      filter->option.fwmark,
                                                      filter->option.send_buffer_size,
                                                      filter->option.recv_buffer_size);
    if (io == NULL)
    {
        releaseUnpublishedEndpoint(endpoint);
        return NULL;
    }
    if (! publishEndpoint(reg, endpoint, io))
        return NULL;
    if (! startUdpListener(io, callback))
    {
        if (endpoint->listen_io != NULL)
            wioClose(endpoint->listen_io);
        if (stop_on_read_failure)
        {
            LOGF("SocketManager: could not register UDP redirect listener on %s:[%u]", host, port);
            startupFailureRecord(1);
        }
        return NULL;
    }
    return endpoint;
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

        listener_endpoint_t *endpoint =
            createTcpListener(loop, filter, host, (uint16_t) main_port, reg, onAcceptTcpMultiPort);
        if (UNLIKELY(startupFailurePending()))
            return 0;
        if (endpoint == NULL)
            continue;

        return (uint16_t) main_port;
    }

    LOGF("SocketManager: stopping due to null socket handle");
    startupFailureRecord(1);
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
        startupFailureRecord(1);
        return;
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
    if (UNLIKELY(startupFailurePending()))
    {
        return;
    }

    uint16_t main_port = selectMainPortForIptables(filter, loop, host, port_min, port_max, reg);
    if (UNLIKELY(startupFailurePending()))
    {
        return;
    }

    queueIptablesRule(IPPROTO_TCP, filter, port_min, port_max, main_port);
    if (UNLIKELY(startupFailurePending()))
    {
        return;
    }
    LOGI("SocketManager: listening on %s:[%u - %u] >> %d (%s)", host, port_min, port_max, main_port, "TCP");
}

/**
 * @brief Listen TCP on each port in range via socket-per-port backend.
 */
static void listenTcpMultiPortSockets(wloop_t *loop, socket_filter_t *filter, char *host, uint16_t port_min,
                                      endpoint_registry_t *reg, uint16_t port_max)
{
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

        listener_endpoint_t *endpoint = createTcpListener(loop, filter, host, port, reg, onAcceptTcpSinglePort);
        if (UNLIKELY(startupFailurePending()))
            return;
        if (endpoint == NULL)
        {
            LOGW("SocketManager: could not listen on %s:[%u] , skipped...", host, port);
            continue;
        }
        LOGI("SocketManager: listening on %s:[%u] (%s)", host, port, "TCP");
    }
}

/**
 * @brief Listen TCP on each explicitly listed port via socket-per-port backend.
 */
static void listenTcpPortListSockets(wloop_t *loop, socket_filter_t *filter, char *host, endpoint_registry_t *reg,
                                     const vec_listener_port_t *ports)
{
    const isize length = vec_listener_port_t_size(ports);
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

        listener_endpoint_t *endpoint = createTcpListener(loop, filter, host, p, reg, onAcceptTcpSinglePort);
        if (UNLIKELY(startupFailurePending()))
            return;
        if (endpoint == NULL)
        {
            LOGW("SocketManager: could not listen on %s:[%u] , skipped...", host, p);
            continue;
        }
        LOGI("SocketManager: listening on %s:[%u] (%s)", host, p, "TCP");
    }
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

    listener_endpoint_t *endpoint = createTcpListener(loop, filter, host, port, reg, onAcceptTcpSinglePort);
    if (UNLIKELY(startupFailurePending()))
        return;
    if (endpoint == NULL)
    {
        LOGF("SocketManager: stopping due to null socket handle");
        startupFailureRecord(1);
        return;
    }
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
        startupFailureRecord(1);
        return;
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
                if (UNLIKELY(startupFailurePending()))
                {
                    return;
                }
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

    if (udpsockIsRetired(pl->sock))
    {
        sbufDestroy(pl->buf);
        udppayloadDestroy(pl);
        return;
    }
    wevent_t ev = (wevent_t) {.loop = worker->loop, .cb = filter->cb, .userdata = pl};
    filter->cb(&ev);
}

/**
 * @brief Release a UDP payload dispatch message if delivery fails.
 */
static void cleanupUdpPayloadDispatch(void *arg1, void *arg2, void *arg3, worker_message_cancel_reason_e reason)
{
    discard        reason;
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
 * @brief Select a UDP listener and transfer its payload with existing side-data.
 */
static void distributeUdpPayload(const udp_payload_t pl, const listener_endpoint_t *endpoint)
{
    listener_arrival_t arrival = {.endpoint = endpoint, .local_port = pl.real_localport, .protocol = IPPROTO_UDP};
    if (! sockaddrToNormalizedIpAddr(&pl.peer_addr, &arrival.peer_addr))
    {
        sbufDestroy(pl.buf);
        return;
    }
    if (! sockaddrToNormalizedIpAddr(&pl.real_localaddr, &arrival.local_addr))
    {
        memoryZero(&arrival.local_addr, sizeof(arrival.local_addr));
        arrival.local_addr.type = IPADDR_TYPE_V4;
    }
    listener_selection_t selection =
        socketManagerSelect(socketmanager_gstate->filters, socketmanager_gstate->wid, &arrival);
    if (selection.filter != NULL)
    {
        socketManagerCommitSelection(socketmanager_gstate->wid, &selection);
        postUdpPayload(pl, selection.filter);
        return;
    }
    noUdpSocketConsumerFound(pl);
    sbufDestroy(pl.buf);
}

/**
 * @brief UDP read callback for single-port listeners.
 */
static void onUdpPacketReceived(wio_t *io, sbuf_t *buf)
{
    listener_endpoint_t *endpoint    = weventGetUserdata(io);
    udpsock_t           *socket      = endpoint->udp_socket;
    sockaddr_u local_addr  = *wioGetLocaladdrU(io);
    uint16_t   local_port  = sockaddrPort(&local_addr);
    uint16_t   remote_port = sockaddrPort(wioGetPeerAddrU(io));
    wid_t      target_wid  = (wid_t) remote_port % (getWorkersCount());

    udp_payload_t item = (udp_payload_t) {.sock           = socket,
                                          .buf            = buf,
                                          .wid            = target_wid,
                                          .peer_addr      = *wioGetPeerAddrU(io),
                                          .real_localaddr = local_addr,
                                          .real_localport = local_port};

    distributeUdpPayload(item, endpoint);
}

/**
 * @brief UDP read callback for redirected multi-port listeners.
 */
static void onUdpPacketReceivedMultiPort(wio_t *io, sbuf_t *buf)
{

#ifdef OS_UNIX
    listener_endpoint_t *endpoint        = weventGetUserdata(io);
    udpsock_t           *socket          = endpoint->udp_socket;
    sockaddr_u local_addr      = *wioGetLocaladdrU(io);
    uint16_t   remote_port     = sockaddrPort(wioGetPeerAddrU(io));
    wid_t      target_wid      = (wid_t) remote_port % (getWorkersCount());
    uint16_t   real_local_port = sockaddrPort(&local_addr); // default fallback

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

    distributeUdpPayload(item, endpoint);
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
        if (UNLIKELY(startupFailurePending()))
        {
            return;
        }
        LOGI("SocketManager: %s:[%u] shares an existing UDP listener", host, port);
        return;
    }

    listener_endpoint_t *endpoint = createUdpListener(loop, filter, host, port, reg, onUdpPacketReceived, false);
    if (UNLIKELY(startupFailurePending()))
        return;
    if (endpoint == NULL)
    {
        LOGF("SocketManager: could not start UDP listener on %s:[%u]", host, port);
        startupFailureRecord(1);
        return;
    }
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
        startupFailureRecord(1);
        return;
    }

    ensureUdpRedirectRangeCompatible(reg, filter, host, port_min, port_max);
    if (UNLIKELY(startupFailurePending()))
    {
        return;
    }
    initializeIptablesIfNeeded();
    if (UNLIKELY(startupFailurePending()))
    {
        return;
    }

    int main_port = -1;
    for (int p = (int) port_max; p >= (int) port_min; --p)
    {
        if (endpointRegistryFind(reg, IPPROTO_UDP, filter, (uint16_t) p) != NULL)
            continue;
        listener_endpoint_t *endpoint =
            createUdpListener(loop, filter, host, (uint16_t) p, reg, onUdpPacketReceivedMultiPort, true);
        if (UNLIKELY(startupFailurePending()))
            return;
        if (endpoint != NULL)
        {
            main_port = p;
            break;
        }
    }
    if (main_port < 0)
    {
        LOGF("SocketManager: stopping due to null UDP socket handle");
        startupFailureRecord(1);
        return;
    }

    queueIptablesRule(IPPROTO_UDP, filter, port_min, port_max, (uint16_t) main_port);
    if (UNLIKELY(startupFailurePending()))
    {
        return;
    }
    LOGI("SocketManager: listening on %s:[%u - %u] >> %d (%s)", host, port_min, port_max, main_port, "UDP");
}

/**
 * @brief Listen UDP on each port in range via socket-per-port backend.
 */
static void listenUdpMultiPortSockets(wloop_t *loop, socket_filter_t *filter, char *host, uint16_t port_min,
                                      endpoint_registry_t *reg, uint16_t port_max)
{
    for (uint32_t p = port_min; p <= port_max; ++p)
    {
        const uint16_t       port   = (uint16_t) p;
        listener_endpoint_t *shared = endpointRegistryFind(reg, IPPROTO_UDP, filter, port);
        if (shared != NULL)
        {
            ensureUdpSharedEndpointCompatible(shared, filter, host, port);
            if (UNLIKELY(startupFailurePending()))
            {
                return;
            }
            LOGI("SocketManager: %s:[%u] shares an existing UDP listener", host, port);
            continue;
        }

        listener_endpoint_t *endpoint = createUdpListener(loop, filter, host, port, reg, onUdpPacketReceived, false);
        if (UNLIKELY(startupFailurePending()))
            return;
        if (endpoint == NULL)
        {
            LOGW("SocketManager: could not listen on %s:[%u] , skipped...", host, port);
            continue;
        }
        LOGI("SocketManager: listening on %s:[%u] (%s)", host, port, "UDP");
    }
}

/**
 * @brief Listen UDP on each explicitly listed port via socket-per-port backend.
 */
static void listenUdpPortListSockets(wloop_t *loop, socket_filter_t *filter, char *host, endpoint_registry_t *reg,
                                     const vec_listener_port_t *ports)
{
    const isize length         = vec_listener_port_t_size(ports);
    for (isize pi = 0; pi < length; ++pi)
    {
        uint16_t p = *vec_listener_port_t_at(ports, pi);

        listener_endpoint_t *shared = endpointRegistryFind(reg, IPPROTO_UDP, filter, p);
        if (shared != NULL)
        {
            ensureUdpSharedEndpointCompatible(shared, filter, host, p);
            if (UNLIKELY(startupFailurePending()))
            {
                return;
            }
            LOGI("SocketManager: %s:[%u] shares an existing UDP listener", host, p);
            continue;
        }

        listener_endpoint_t *endpoint = createUdpListener(loop, filter, host, p, reg, onUdpPacketReceived, false);
        if (UNLIKELY(startupFailurePending()))
            return;
        if (endpoint == NULL)
        {
            LOGW("SocketManager: could not listen on %s:[%u] , skipped...", host, p);
            continue;
        }
        LOGI("SocketManager: listening on %s:[%u] (%s)", host, p, "UDP");
    }
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
                startupFailureRecord(1);
                return;
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
                if (UNLIKELY(startupFailurePending()))
                {
                    return;
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
static void cleanupUdpWriteDispatch(void *arg1, void *arg2, void *arg3, worker_message_cancel_reason_e reason)
{
    discard        reason;
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
        if (UNLIKELY(socket_io->io == NULL))
        {
            reuseBuffer(buf);
            return;
        }
        int     nwrite = wioWriteDatagram(socket_io->io, buf, &peer_addr);
        discard nwrite;
        return;
    }

    udp_payload_t *item = newUdpPayload(wid_from);

    *item = (udp_payload_t) {.sock = socket_io, .buf = buf, .wid = wid_from, .peer_addr = peer_addr};

    sendWorkerMessageForceQueueBestEffortWithCleanup(
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

static isize_t socketmanagerListenerReservationBound(void)
{
    uint64_t total = 0;
    for (size_t level = 0; level < kFilterLevels; ++level)
    {
        c_foreach(it, filters_t, socketmanager_gstate->filters[level])
        {
            const socket_filter_t *filter = *it.ref;
            const isize_t          listed = vec_listener_port_t_size(&filter->option.ports);
            uint64_t               count  = 1;
            if (listed > 0)
            {
                count = (uint64_t) listed;
            }
            else if (filter->option.port_max >= filter->option.port_min)
            {
                count = (uint64_t) filter->option.port_max - (uint64_t) filter->option.port_min + 1U;
            }
            if (UNLIKELY(total > (uint64_t) PTRDIFF_MAX - count))
            {
                return -1;
            }
            total += count;
        }
    }
    return (isize_t) total;
}

ww_startup_result_t socketmanagerStart(void)
{
    ww_startup_context_t startup = {0};
    wwStartupContextBegin(&startup);

    assert(socketmanager_gstate != NULL);

    assert(socketmanager_gstate && socketmanager_gstate->worker->loop && ! socketmanager_gstate->started);

    mutexLock(&(socketmanager_gstate->mutex));

    reconcileIptablesStartup();

    // Record only successful binds, so failed attempts never block later endpoint setup.
    endpoint_registry_t *registry = &socketmanager_gstate->endpoints;

    const isize_t listener_bound = socketmanagerListenerReservationBound();
    if (UNLIKELY(
            listener_bound < 0 ||
            (listener_bound > 0 && (! endpoint_registry_t_reserve(registry, listener_bound) ||
                                    endpoint_registry_t_capacity(registry) < listener_bound ||
                                    ! pending_rules_t_reserve(&socketmanager_gstate->pending_rules, listener_bound) ||
                                    pending_rules_t_capacity(&socketmanager_gstate->pending_rules) < listener_bound))))
    {
        mutexUnlock(&(socketmanager_gstate->mutex));
        LOGF("SocketManager: failed to reserve listener ownership metadata before binding");
        startupFailureRecord(1);
        return wwStartupContextEnd(&startup);
    }

    listenTcp(socketmanager_gstate->worker->loop, registry);
    if (UNLIKELY(startupFailurePending()))
    {
        goto startup_failed;
    }
    listenUdp(socketmanager_gstate->worker->loop, registry);
    if (UNLIKELY(startupFailurePending()))
    {
        goto startup_failed;
    }

    // Install NAT rules specific-before-wildcard after all redirect sockets are known.
    installPendingIptablesRules();
    if (UNLIKELY(startupFailurePending()))
    {
        goto startup_failed;
    }


    socketmanager_gstate->started = true;
    mutexUnlock(&(socketmanager_gstate->mutex));
    return wwStartupContextEnd(&startup);

startup_failed:
    mutexUnlock(&(socketmanager_gstate->mutex));
    return wwStartupContextEnd(&startup);
}

/**
 * @brief Allocate and initialize worker-specific TCP/UDP object pools.
 */
static bool initializeSocketManagerPools(socket_manager_state_t *state)
{
    const wid_t                 workers   = getTotalWorkersCount();
    threadsafe_generic_pool_t **udp_pools = memoryAllocateZero(sizeof(*udp_pools) * workers);
    threadsafe_generic_pool_t **tcp_pools = memoryAllocateZero(sizeof(*tcp_pools) * workers);
    master_pool_t              *mp_udp    = masterpoolCreateWithCapacity(2 * ((8) + RAM_PROFILE));
    master_pool_t              *mp_tcp    = masterpoolCreateWithCapacity(2 * ((8) + RAM_PROFILE));

    if (UNLIKELY(udp_pools == NULL || tcp_pools == NULL || mp_udp == NULL || mp_tcp == NULL))
    {
        memoryFree(udp_pools);
        memoryFree(tcp_pools);
        masterpoolDestroy(mp_udp);
        masterpoolDestroy(mp_tcp);
        return false;
    }

    for (wid_t i = 0; i < workers; ++i)
    {
        udp_pools[i] = threadsafegenericpoolCreateWithCapacity(
            mp_udp, (8) + RAM_PROFILE, allocUdpPayloadPoolHandle, destroyUdpPayloadPoolHandle);
        tcp_pools[i] = threadsafegenericpoolCreateWithCapacity(
            mp_tcp, (8) + RAM_PROFILE, allocTcpResultObjectPoolHandle, destroyTcpResultObjectPoolHandle);

        if (UNLIKELY(udp_pools[i] == NULL || tcp_pools[i] == NULL))
        {
            for (wid_t cleanup = 0; cleanup <= i; ++cleanup)
            {
                threadsafegenericpoolDestroy(udp_pools[cleanup]);
                threadsafegenericpoolDestroy(tcp_pools[cleanup]);
            }
            memoryFree(udp_pools);
            memoryFree(tcp_pools);
            masterpoolDestroy(mp_udp);
            masterpoolDestroy(mp_tcp);
            return false;
        }
    }

    state->udp_pools = udp_pools;
    state->tcp_pools = tcp_pools;
    state->mp_udp    = mp_udp;
    state->mp_tcp    = mp_tcp;
    return true;
}

/**
 * @brief Detect runtime availability of external socket-routing tools.
 */
static void detectSystemCapabilities(socket_manager_state_t *state)
{
#ifdef OS_UNIX
    state->iptables_installed = checkCommandAvailable("iptables");
    state->lsof_installed     = checkCommandAvailable("lsof");
#if SUPPORT_V6
    state->ip6tables_installed = checkCommandAvailable("ip6tables");
#endif
#else
    discard state;
#endif
}

socket_manager_state_t *socketmanagerCreate(void)
{
    assert(socketmanager_gstate == NULL);
    socket_manager_state_t *state = memoryAllocateZero(sizeof(*state));
    if (UNLIKELY(state == NULL))
    {
        return NULL;
    }

    // Startup-only: worker 0 is bound before managers are created, and the
    // manager's own worker/wid fields are structurally worker-0 owned.
    if (UNLIKELY(! currentThreadIsEventWorkerWID(0)))
    {
        LOGF("SocketManager: socketmanagerCreate() must run on worker 0, current worker: %d",
             workerWIDForLog(getWID()));
        abortProgramNow(1);
    }
    state->worker = getWorker(0);
    state->wid    = 0;

    for (size_t i = 0; i < kFilterLevels; i++)
    {
        state->filters[i] = filters_t_init();
    }
    state->balance_groups = balancegroup_registry_t_init();
    state->pending_rules  = pending_rules_t_init();
    state->endpoints      = endpoint_registry_t_init();

    state->iptables_owner_lease_fd = -1;

    if (UNLIKELY(! balancegroup_registry_t_reserve(&state->balance_groups, 8) ||
                 balancegroup_registry_t_capacity(&state->balance_groups) < 8 ||
                 ! pending_rules_t_reserve(&state->pending_rules, 8) ||
                 pending_rules_t_capacity(&state->pending_rules) < 8 || ! mutexTryInit(&state->mutex)))
    {
        balancegroup_registry_t_drop(&state->balance_groups);
        pending_rules_t_drop(&state->pending_rules);
        for (size_t i = 0; i < kFilterLevels; ++i)
        {
            filters_t_drop(&state->filters[i]);
        }
        memoryFree(state);
        return NULL;
    }

    bool fail_after_mutex = false;
#ifdef WW_SOCKET_MANAGER_CONSTRUCTOR_TEST_SEAM
    fail_after_mutex = socketManagerConstructorTestFailAfterMutex();
#endif
    if (UNLIKELY(fail_after_mutex || ! initializeSocketManagerPools(state)))
    {
        mutexDestroy(&state->mutex);
        balancegroup_registry_t_drop(&state->balance_groups);
        pending_rules_t_drop(&state->pending_rules);
        for (size_t i = 0; i < kFilterLevels; ++i)
        {
            filters_t_drop(&state->filters[i]);
        }
        memoryFree(state);
        return NULL;
    }
    detectSystemCapabilities(state);

    socketmanager_gstate = state;
    return state;
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
 * @brief Drain active UDP listener idle entries for one socket/worker pair.
 */
void socketmanagerDrainUdpSocketForWorker(udpsock_t *socket, wid_t wid)
{
    // Runs as part of a worker tearing itself down, for its own slot only.
    assert(currentThreadIsEventWorkerWID(wid));

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

void socketmanagerDrainUdpIdleForWorker(wid_t wid)
{
    if (socketmanager_gstate == NULL)
        return;
    c_foreach(it, endpoint_registry_t, socketmanager_gstate->endpoints)
    {
        socketmanagerDrainUdpSocketForWorker((*it.ref)->udp_socket, wid);
    }
}

void socketmanagerCloseListenersForLoop(wloop_t *loop)
{
    if (socketmanager_gstate == NULL || loop == NULL)
        return;
    c_foreach(it, endpoint_registry_t, socketmanager_gstate->endpoints)
    {
        listener_endpoint_t *endpoint = *it.ref;
        if (endpoint->listen_io != NULL && weventGetLoop(endpoint->listen_io) == loop)
        {
            wioClose(endpoint->listen_io);
            /* The close callback clears the one authoritative slot. */
            assert(endpoint->listen_io == NULL);
        }
    }
}

void socketmanagerQuiesceWorker(wid_t wid)
{
    if (socketmanager_gstate == NULL || wid != 0)
    {
        return;
    }
    assert(currentThreadIsEventWorkerWID(wid));

    c_foreach(bg, balancegroup_registry_t, socketmanager_gstate->balance_groups)
    {
        if (bg.ref->second != NULL)
        {
            idletableDestroy(bg.ref->second);
            bg.ref->second = NULL;
        }
    }
}

/* Startup rollback can destroy the manager while its loop remains alive;
 * normal shutdown already closed sockets and settled all worker dependencies. */
static void cleanupEndpoints(void)
{
    wloop_t *loop = socketmanager_gstate->worker != NULL ? socketmanager_gstate->worker->loop : NULL;
    if (loop != NULL)
        socketmanagerCloseListenersForLoop(loop);
    c_foreach(it, endpoint_registry_t, socketmanager_gstate->endpoints)
    {
        listener_endpoint_t *endpoint = *it.ref;
        assert(endpoint->listen_io == NULL);
        if (endpoint->udp_socket != NULL)
            cleanupOneUdpSocket(&endpoint->udp_socket);
        memoryFree(endpoint->interface_scope);
        memoryFree(endpoint);
    }
    endpoint_registry_t_drop(&socketmanager_gstate->endpoints);
}

static void cleanupFilters(void)
{
    for (size_t i = 0; i < kFilterLevels; i++)
    {
        c_foreach(filter, filters_t, socketmanager_gstate->filters[i])
        {
            socket_filter_t *f = *filter.ref;
            socketfilteroptionDeInit(&f->option);
            memoryFree(f);
        }
        filters_t_drop(&socketmanager_gstate->filters[i]);
    }
}

/**
 * @brief Destroy all shared balance-group idle tables.
 */
static void destroyBalanceGroups(void)
{
    c_foreach(bg, balancegroup_registry_t, socketmanager_gstate->balance_groups)
    {
        if (bg.ref->second != NULL)
        {
            idletableDestroy(bg.ref->second);
        }
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
    if (socketmanager_gstate == NULL)
    {
        return;
    }

    if (socketmanager_gstate->iptables_used || socketmanager_gstate->iptables_published)
    {
        if (! cleanupOwnedIptablesChainsWithReconcileLock(true))
        {
            const char msg[] = "SocketManager: failed to fully remove owned iptables nat rules\n";
            ssize_t    n     = write(STDOUT_FILENO, msg, sizeof(msg) - 1);
            discard    n;
        }
    }
    socketManagerIptablesReleaseLease(&socketmanager_gstate->iptables_owner_lease_fd);

    cleanupEndpoints();
    cleanupFilters();
    destroyBalanceGroups();
    pending_rules_t_drop(&socketmanager_gstate->pending_rules);
    destroyPools();
    /* Construction publishes the manager only after this hybrid mutex owns
     * its backing synchronization resource. All users are quiesced above, so
     * release that resource before freeing the state. */
    mutexDestroy(&socketmanager_gstate->mutex);
    memoryFree(socketmanager_gstate);
    socketmanager_gstate = NULL;
}

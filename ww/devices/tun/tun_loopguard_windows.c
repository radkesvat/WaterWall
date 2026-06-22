#include "managers/windivert_manager.h"

#ifdef OS_WIN

#include "tun_loopguard.h"

#include "global_state.h"
#include "wmutex.h"
#include "wthread.h"

#include "loggers/internal_logger.h"

#include <iphlpapi.h>
#include <netioapi.h>
#include <ws2ipdef.h>
#include <ws2tcpip.h>

/*
 * Windows implementation of the TUN loop-guard (see tun_loopguard.h).
 *
 * Mechanism:
 *  - WinDivert is opened at the FLOW layer (SNIFF | RECV_ONLY), filtered to this
 *    process only, observing its own flow ESTABLISHED/DELETED events. The FLOW
 *    layer is used (rather than SOCKET) because it captures *all* flows -- TCP
 *    connections AND non-TCP flows such as UDP, including unconnected sendto()
 *    traffic (the implicit flow created by the first datagram). This matters
 *    because WaterWall's UdpConnector binds + sendto() and never calls connect(),
 *    so the SOCKET layer's CONNECT event would never fire for it and its packets
 *    to the upstream server would loop. The FLOW layer is observe-only (it cannot
 *    block or inject), which matches how we use it; the bypass route is installed
 *    as the flow is established (small inherent first-packet race, self-heals).
 *  - For each new flow endpoint, GetBestRoute2() is consulted. If the endpoint
 *    would be routed *into the TUN*, a host (/32 or /128) bypass route via the
 *    original default gateway is installed so the packet exits the physical NIC
 *    instead, breaking the loop. Endpoints that are already routed elsewhere
 *    (LAN/on-link, loopback, user-excluded ranges) are left untouched.
 *  - Bypass routes are reference-counted per destination and tracked per flow
 *    EndpointId, removed on the matching FLOW_DELETED (leftovers removed on stop).
 */

enum
{
    kLoopGuardFilterLen = 160
};

// One protected flow. We track the flow's WinDivert EndpointId (unique per
// kernel flow) so that a FLOW_DELETED belonging to an *unrelated* flow that
// happens to share the same remote IP (e.g. an inbound flow) can never tear down
// the bypass route of a live protected connector. The bypass route for a given
// destination is reference counted as "number of protected flows that share that
// destination address".
typedef struct prot_flow_s
{
    UINT64        endpoint_id;
    SOCKADDR_INET dest; // destination the bypass route was installed for
} prot_flow_t;

struct tun_loopguard_s
{
    HANDLE      divert_handle;
    wthread_t   thread;
    atomic_bool running;
    DWORD       pid;
    uint64_t    tun_luid;

    // Original default route per family, captured before the TUN routes exist.
    bool          have_v4;
    NET_LUID      v4_if_luid;
    SOCKADDR_INET v4_gateway;
    bool          have_v6;
    NET_LUID      v6_if_luid;
    SOCKADDR_INET v6_gateway;

    // Set of protected flows (keyed by EndpointId).
    wmutex_t     lock;
    prot_flow_t *items;
    size_t       count;
    size_t       capacity;
};

// ---------------------------------------------------------------------------
// address helpers
// ---------------------------------------------------------------------------

static const void *sockaddrInetAddrPtr(const SOCKADDR_INET *a, int *out_len)
{
    if (a->si_family == AF_INET6)
    {
        *out_len = (int) sizeof(a->Ipv6.sin6_addr);
        return &a->Ipv6.sin6_addr;
    }
    *out_len = (int) sizeof(a->Ipv4.sin_addr);
    return &a->Ipv4.sin_addr;
}

// Best-effort presentation string for logs (returns "?" on failure).
static const char *formatInet(const SOCKADDR_INET *a, char *buf, size_t buflen)
{
    const void *p = (a->si_family == AF_INET6) ? (const void *) &a->Ipv6.sin6_addr : (const void *) &a->Ipv4.sin_addr;
    if (inet_ntop(a->si_family, (void *) p, buf, buflen) == NULL)
    {
        stringNPrintf(buf, buflen, "?");
    }
    return buf;
}

static bool sockaddrInetSameAddr(const SOCKADDR_INET *a, const SOCKADDR_INET *b)
{
    if (a->si_family != b->si_family)
    {
        return false;
    }
    int         len_a = 0;
    int         len_b = 0;
    const void *pa    = sockaddrInetAddrPtr(a, &len_a);
    const void *pb    = sockaddrInetAddrPtr(b, &len_b);
    return len_a == len_b && memoryCompare(pa, pb, (size_t) len_a) == 0;
}

static void setSockaddrInetV4(SOCKADDR_INET *out, const struct in_addr *v4)
{
    memorySet(out, 0, sizeof(*out));
    out->Ipv4.sin_family = AF_INET;
    out->Ipv4.sin_addr   = *v4;
}

// Decode the remote endpoint of a FLOW-layer event into a SOCKADDR_INET.
//
// Per the WinDivert docs, Flow.RemoteAddr is *always* stored as an IPv6 address,
// and IPv4 endpoints are represented as IPv4-mapped IPv6 (::ffff:a.b.c.d) -- this
// holds whether the addr->IPv6 flag is set (real IPv6 / dual-stack socket) or
// cleared (IPv4 flow). So we always decode the 4-word RemoteAddr as IPv6 and then
// demote v4-mapped addresses to a real IPv4 SOCKADDR_INET, so the bypass route
// matches the actual (IPv4) wire traffic instead of an unmatchable ::ffff:/128.
static bool decodeFlowRemote(const WINDIVERT_ADDRESS *addr, SOCKADDR_INET *out)
{
    char            buf[64];
    struct in6_addr v6;

    if (! windivertHelperFormatIPv6Address(addr->Flow.RemoteAddr, buf, sizeof(buf)))
    {
        return false;
    }
    if (inet_pton(AF_INET6, buf, &v6) != 1)
    {
        return false;
    }

    if (IN6_IS_ADDR_V4MAPPED(&v6))
    {
        // Embedded IPv4 lives in the last 4 bytes (network order).
        struct in_addr v4;
        memoryCopy(&v4, &v6.s6_addr[12], sizeof(v4));
        setSockaddrInetV4(out, &v4);
        return true;
    }

    memorySet(out, 0, sizeof(*out));
    out->Ipv6.sin6_family = AF_INET6;
    out->Ipv6.sin6_addr   = v6;
    return true;
}

// ---------------------------------------------------------------------------
// routing helpers
// ---------------------------------------------------------------------------

// Capture the original default route for a family by asking for the best route to
// a well-known public address. Must run before the TUN system routes exist.
static bool captureDefaultRoute(int family, NET_LUID *out_luid, SOCKADDR_INET *out_gateway)
{
    SOCKADDR_INET dest;
    memorySet(&dest, 0, sizeof(dest));

    if (family == AF_INET)
    {
        dest.Ipv4.sin_family = AF_INET;
        inet_pton(AF_INET, "8.8.8.8", &dest.Ipv4.sin_addr);
    }
    else
    {
        dest.Ipv6.sin6_family = AF_INET6;
        inet_pton(AF_INET6, "2001:4860:4860::8888", &dest.Ipv6.sin6_addr);
    }

    MIB_IPFORWARD_ROW2 row;
    SOCKADDR_INET      best_src;
    NETIO_STATUS       status = GetBestRoute2(NULL, 0, NULL, &dest, 0, &row, &best_src);
    if (status != NO_ERROR)
    {
        return false;
    }

    *out_luid    = row.InterfaceLuid;
    *out_gateway = row.NextHop;
    return true;
}

// Returns true if, with the current routing table, `dest` would be sent into the
// TUN interface (i.e. it would loop).
static bool destinationRoutesToTun(const tun_loopguard_t *guard, const SOCKADDR_INET *dest)
{
    MIB_IPFORWARD_ROW2 row;
    SOCKADDR_INET      best_src;
    if (GetBestRoute2(NULL, 0, NULL, dest, 0, &row, &best_src) != NO_ERROR)
    {
        return false;
    }
    return row.InterfaceLuid.Value == guard->tun_luid;
}

static bool buildBypassRow(const tun_loopguard_t *guard, const SOCKADDR_INET *dest, MIB_IPFORWARD_ROW2 *row)
{
    NET_LUID      luid;
    SOCKADDR_INET gateway;

    if (dest->si_family == AF_INET6)
    {
        if (! guard->have_v6)
        {
            return false;
        }
        luid    = guard->v6_if_luid;
        gateway = guard->v6_gateway;
    }
    else
    {
        if (! guard->have_v4)
        {
            return false;
        }
        luid    = guard->v4_if_luid;
        gateway = guard->v4_gateway;
    }

    InitializeIpForwardEntry(row);
    row->InterfaceLuid                  = luid;
    row->DestinationPrefix.Prefix       = *dest;
    row->DestinationPrefix.PrefixLength = (dest->si_family == AF_INET6) ? 128 : 32;
    row->NextHop                        = gateway;
    row->Protocol                       = MIB_IPPROTO_NETMGMT;
    row->Metric                         = 0;
    return true;
}

static bool installBypassRoute(const tun_loopguard_t *guard, const SOCKADDR_INET *dest)
{
    MIB_IPFORWARD_ROW2 row;
    if (! buildBypassRow(guard, dest, &row))
    {
        return false;
    }

    NETIO_STATUS status = CreateIpForwardEntry2(&row);
    if (status != NO_ERROR && status != ERROR_OBJECT_ALREADY_EXISTS)
    {
        char dbuf[64];
        LOGE("TunLoopGuard: failed to install bypass route for %s, code: %lu",
             formatInet(dest, dbuf, sizeof(dbuf)),
             status);
        return false;
    }

    char dbuf[64];
    char gbuf[64];
    LOGI("TunLoopGuard: installed bypass route %s via %s (status %lu)",
         formatInet(dest, dbuf, sizeof(dbuf)),
         formatInet(dest->si_family == AF_INET6 ? &guard->v6_gateway : &guard->v4_gateway, gbuf, sizeof(gbuf)),
         status);
    return true;
}

static void removeBypassRoute(const tun_loopguard_t *guard, const SOCKADDR_INET *dest)
{
    MIB_IPFORWARD_ROW2 row;
    if (! buildBypassRow(guard, dest, &row))
    {
        return;
    }

    NETIO_STATUS status = DeleteIpForwardEntry2(&row);
    if (status != NO_ERROR && status != ERROR_NOT_FOUND)
    {
        LOGW("TunLoopGuard: failed to remove bypass route, code: %lu", status);
    }
}

// ---------------------------------------------------------------------------
// protected-flow set (must be called with guard->lock held)
// ---------------------------------------------------------------------------

static bool findEndpointLocked(tun_loopguard_t *guard, UINT64 endpoint_id)
{
    for (size_t i = 0; i < guard->count; ++i)
    {
        if (guard->items[i].endpoint_id == endpoint_id)
        {
            return true;
        }
    }
    return false;
}

// Number of protected flows still using `dest` (the route refcount).
static size_t countDestLocked(tun_loopguard_t *guard, const SOCKADDR_INET *dest)
{
    size_t n = 0;
    for (size_t i = 0; i < guard->count; ++i)
    {
        if (sockaddrInetSameAddr(&guard->items[i].dest, dest))
        {
            n++;
        }
    }
    return n;
}

// True if `dest` already appears at an index < `index` (used to remove each
// distinct bypass route only once when draining the set at shutdown).
static bool findDestBeforeIndex(tun_loopguard_t *guard, const SOCKADDR_INET *dest, size_t index)
{
    for (size_t i = 0; i < index; ++i)
    {
        if (sockaddrInetSameAddr(&guard->items[i].dest, dest))
        {
            return true;
        }
    }
    return false;
}

static bool appendEndpointLocked(tun_loopguard_t *guard, UINT64 endpoint_id, const SOCKADDR_INET *dest)
{
    if (guard->count == guard->capacity)
    {
        size_t       next_capacity = guard->capacity == 0 ? 16 : guard->capacity * 2;
        prot_flow_t *new_items     = memoryReAllocate(guard->items, next_capacity * sizeof(prot_flow_t));
        if (new_items == NULL)
        {
            LOGE("TunLoopGuard: failed to grow protected-flow set");
            return false;
        }
        guard->items    = new_items;
        guard->capacity = next_capacity;
    }

    guard->items[guard->count].endpoint_id = endpoint_id;
    guard->items[guard->count].dest        = *dest;
    guard->count++;
    return true;
}

// ---------------------------------------------------------------------------
// event handling
// ---------------------------------------------------------------------------

static void handleFlowEstablished(tun_loopguard_t *guard, const WINDIVERT_ADDRESS *addr)
{
    UINT64        endpoint_id = addr->Flow.EndpointId;
    SOCKADDR_INET dest;
    if (! decodeFlowRemote(addr, &dest))
    {
        return;
    }

    mutexLock(&guard->lock);

    if (findEndpointLocked(guard, endpoint_id))
    {
        // Duplicate FLOW_ESTABLISHED for a flow we already track.
        mutexUnlock(&guard->lock);
        return;
    }

    // Is the bypass route for this destination already installed (another
    // protected flow shares it)? If so we only need to register this flow.
    bool route_present = countDestLocked(guard, &dest) > 0;
    mutexUnlock(&guard->lock);

    if (! route_present)
    {
        char dbuf[64];
        // Only protect endpoints that would actually be routed into the TUN.
        if (! destinationRoutesToTun(guard, &dest))
        {
            LOGI("TunLoopGuard: flow to %s is NOT routed via the TUN -> no bypass installed",
                 formatInet(&dest, dbuf, sizeof(dbuf)));
            return;
        }
        LOGI("TunLoopGuard: flow to %s routes into the TUN -> installing bypass",
             formatInet(&dest, dbuf, sizeof(dbuf)));
        if (! installBypassRoute(guard, &dest))
        {
            return;
        }
    }

    mutexLock(&guard->lock);
    bool registered = appendEndpointLocked(guard, endpoint_id, &dest);
    // If we just installed the route but failed to register the flow, and no
    // other flow uses it, roll the route back to avoid leaking it.
    bool rollback = (! registered) && (! route_present) && (countDestLocked(guard, &dest) == 0);
    mutexUnlock(&guard->lock);

    if (rollback)
    {
        removeBypassRoute(guard, &dest);
    }
}

static void handleFlowDeleted(tun_loopguard_t *guard, const WINDIVERT_ADDRESS *addr)
{
    UINT64        endpoint_id = addr->Flow.EndpointId;
    SOCKADDR_INET dest;
    bool          remove_route = false;

    mutexLock(&guard->lock);
    for (size_t i = 0; i < guard->count; ++i)
    {
        if (guard->items[i].endpoint_id != endpoint_id)
        {
            continue;
        }

        dest = guard->items[i].dest;
        // remove this protected flow entry (swap with last)
        guard->items[i] = guard->items[guard->count - 1];
        guard->count--;

        // Drop the route only when no other protected flow still uses it.
        remove_route = countDestLocked(guard, &dest) == 0;
        break;
    }
    mutexUnlock(&guard->lock);

    if (remove_route)
    {
        removeBypassRoute(guard, &dest);
    }
}

static WTHREAD_ROUTINE(routineLoopGuard) // NOLINT
{
    tun_loopguard_t *guard = userdata;

    while (atomicLoadRelaxed(&guard->running))
    {
        WINDIVERT_ADDRESS addr;
        UINT              recv_len = 0;

        if (! windivertRecv(guard->divert_handle, NULL, 0, &recv_len, &addr))
        {
            DWORD last_error = GetLastError();
            if (last_error == ERROR_NO_DATA)
            {
                // handle was shut down
                break;
            }
            if (! atomicLoadRelaxed(&guard->running))
            {
                break;
            }
            continue;
        }

        if (addr.Event == WINDIVERT_EVENT_FLOW_ESTABLISHED)
        {
            handleFlowEstablished(guard, &addr);
        }
        else if (addr.Event == WINDIVERT_EVENT_FLOW_DELETED)
        {
            handleFlowDeleted(guard, &addr);
        }

        // The handle is opened SNIFF | RECV_ONLY: flow events are observed, not
        // blocked, and the FLOW layer does not support injecting/permitting
        // events. So we never call WinDivertSend here -- the flow proceeds
        // normally and we just install the bypass route alongside it.
    }

    return 0;
}

// ---------------------------------------------------------------------------
// lifecycle
// ---------------------------------------------------------------------------

tun_loopguard_t *tunLoopGuardStart(uint64_t tun_luid_value)
{
    if (tun_luid_value == 0)
    {
        LOGW("TunLoopGuard: TUN interface LUID unknown, self-traffic loop protection disabled");
        return NULL;
    }

    if (! windivertManagerEnsureLoaded())
    {
        LOGE("TunLoopGuard: WinDivert unavailable, self-traffic loop protection disabled");
        return NULL;
    }

    tun_loopguard_t *guard = memoryAllocate(sizeof(tun_loopguard_t));
    memorySet(guard, 0, sizeof(*guard));
    guard->pid      = GetCurrentProcessId();
    guard->tun_luid = tun_luid_value;
    mutexInit(&guard->lock);

    guard->have_v4 = captureDefaultRoute(AF_INET, &guard->v4_if_luid, &guard->v4_gateway);
    guard->have_v6 = captureDefaultRoute(AF_INET6, &guard->v6_if_luid, &guard->v6_gateway);

    if (! guard->have_v4 && ! guard->have_v6)
    {
        LOGW("TunLoopGuard: no original default route found, self-traffic loop protection disabled");
        mutexDestroy(&guard->lock);
        memoryFree(guard);
        return NULL;
    }

    // Filter to this process only; the FLOW layer then yields ESTABLISHED and
    // DELETED events for every TCP/UDP flow we open (which is exactly what we want
    // to observe -- we dispatch on addr.Event in the thread).
    char filter[kLoopGuardFilterLen];
    stringNPrintf(filter, sizeof(filter), "processId == %lu", (unsigned long) guard->pid);

    // SNIFF | RECV_ONLY: observe our own flow events without blocking them. The
    // FLOW layer cannot inject/permit/block events anyway; we install the bypass
    // route as the flow is established.
    guard->divert_handle =
        windivertOpen(filter, WINDIVERT_LAYER_FLOW, 0, WINDIVERT_FLAG_SNIFF | WINDIVERT_FLAG_RECV_ONLY);
    if (guard->divert_handle == INVALID_HANDLE_VALUE)
    {
        LOGE("TunLoopGuard: failed to open WinDivert flow layer: error %lu", GetLastError());
        mutexDestroy(&guard->lock);
        memoryFree(guard);
        return NULL;
    }

    atomicStoreRelaxed(&guard->running, true);
    guard->thread = threadCreate(routineLoopGuard, guard);

    char gw4[64] = "none";
    char gw6[64] = "none";
    if (guard->have_v4)
    {
        formatInet(&guard->v4_gateway, gw4, sizeof(gw4));
    }
    if (guard->have_v6)
    {
        formatInet(&guard->v6_gateway, gw6, sizeof(gw6));
    }
    LOGI("TunLoopGuard: active (pid=%lu, original gateway v4=%s v6=%s, tun_luid=%llu)",
         (unsigned long) guard->pid,
         gw4,
         gw6,
         (unsigned long long) guard->tun_luid);
    return guard;
}

void tunLoopGuardStop(tun_loopguard_t *guard)
{
    if (guard == NULL)
    {
        return;
    }

    atomicStoreRelaxed(&guard->running, false);

    // Unblock the guard thread's WinDivertRecv() (it returns with ERROR_NO_DATA)
    // but do NOT close the handle yet -- the thread may still be inside a recv
    // call. Join first, then close, so the handle stays valid for the whole life
    // of the thread.
    if (guard->divert_handle != NULL && guard->divert_handle != INVALID_HANDLE_VALUE)
    {
        windivertShutdown(guard->divert_handle, WINDIVERT_SHUTDOWN_BOTH);
    }

    safeThreadJoin(guard->thread);

    if (guard->divert_handle != NULL && guard->divert_handle != INVALID_HANDLE_VALUE)
    {
        windivertClose(guard->divert_handle);
        guard->divert_handle = NULL;
    }

    // The thread is gone; remove each distinct remaining bypass route once.
    for (size_t i = 0; i < guard->count; ++i)
    {
        if (! findDestBeforeIndex(guard, &guard->items[i].dest, i))
        {
            removeBypassRoute(guard, &guard->items[i].dest);
        }
    }

    memoryFree(guard->items);
    mutexDestroy(&guard->lock);
    memoryFree(guard);
}

#endif // OS_WIN

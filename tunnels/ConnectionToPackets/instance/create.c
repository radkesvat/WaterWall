#include "structure.h"

#include "DomainResolver/interface.h"

#include "loggers/network_logger.h"

static void initializeTunnelCallbacks(tunnel_t *t)
{
    t->fnInitU    = &ctpTunnelUpStreamInit;
    t->fnEstU     = &ctpTunnelUpStreamEst;
    t->fnFinU     = &ctpTunnelUpStreamFinish;
    t->fnPayloadU = &ctpTunnelUpStreamPayload;
    t->fnPauseU   = &ctpTunnelUpStreamPause;
    t->fnResumeU  = &ctpTunnelUpStreamResume;

    t->fnInitD    = &ctpTunnelDownStreamInit;
    t->fnEstD     = &ctpTunnelDownStreamEst;
    t->fnFinD     = &ctpTunnelDownStreamFinish;
    t->fnPayloadD = &ctpTunnelDownStreamPayload;
    t->fnPauseD   = &ctpTunnelDownStreamPause;
    t->fnResumeD  = &ctpTunnelDownStreamResume;

    t->onChain      = &ctpTunnelOnChain;
    t->onStart      = &ctpTunnelOnStart;
    t->onPreStop    = &ctpTunnelOnPreStop;
    t->onStop       = &ctpTunnelOnStop;
    t->onWorkerStop = &ctpTunnelOnWorkerStop;
    t->onDestroy    = &ctpTunnelDestroy;
}

static bool ctpAddDomainStrategySetting(cJSON *settings, enum domain_strategy strategy)
{
    cJSON *strategy_json = cJSON_AddNumberToObject(settings, "strategy", (double) strategy);
    if (strategy_json == NULL)
    {
        return false;
    }

    strategy_json->valueint    = (int) strategy;
    strategy_json->valuedouble = (double) strategy_json->valueint;
    return true;
}

static cJSON *ctpCreateDomainResolverSettings(enum domain_strategy strategy)
{
    cJSON *settings = cJSON_CreateObject();
    if (settings == NULL)
    {
        return NULL;
    }

    if (! ctpAddDomainStrategySetting(settings, strategy))
    {
        cJSON_Delete(settings);
        return NULL;
    }

    return settings;
}

/*
 * The same internal-resolver pattern the connectors use: a DomainResolver is
 * inserted directly in front of this node during chaining, so Init always runs
 * with a resolved destination and never has to buffer while DNS is pending.
 */
static bool ctpCreateInternalDomainResolver(tunnel_t *t, node_t *node)
{
    ctp_tstate_t *ts = tunnelGetState(t);

    ts->domain_resolver_settings = ctpCreateDomainResolverSettings((enum domain_strategy) ts->domain_strategy);
    if (ts->domain_resolver_settings == NULL)
    {
        LOGF("ConnectionToPackets: failed to create internal DomainResolver settings");
        return false;
    }

    if (! nodeConfigureChild(&ts->domain_resolver_node,
                             nodeDomainResolverGet(),
                             node,
                             ".domain-resolver",
                             kNodeChildLinkNone,
                             ts->domain_resolver_settings))
    {
        LOGF("ConnectionToPackets: failed to configure internal DomainResolver node");
        return false;
    }

    ts->domain_resolver_tunnel = nodemanagerCreateTunnelInstance(&ts->domain_resolver_node);
    if (ts->domain_resolver_tunnel == NULL)
    {
        LOGF("ConnectionToPackets: failed to create internal DomainResolver");
        return false;
    }

    domainresolverTunnelUseLineStrategy(ts->domain_resolver_tunnel, true);
    domainresolverTunnelSetPrepareHook(
        ts->domain_resolver_tunnel, t, sizeof(ctp_domain_resolver_lstate_t), ctpDomainResolverPrepare, NULL);
    ts->domain_resolver_node.instance = ts->domain_resolver_tunnel;
    return true;
}

static bool ctpLoadSourceAddress(ctp_tstate_t *ts, const cJSON *settings)
{
    const char               *source_ipv4 = NULL;
    const json_value_status_t status      = jsonGetObjectNonEmptyString(settings, "source-ipv4", &source_ipv4);

    if (status != kJsonValuePresent)
    {
        LOGF("JSON Error: ConnectionToPackets->settings->source-ipv4 (string field) : The value was empty or invalid");
        return false;
    }

    if (! ip4AddrAddressToNetwork(source_ipv4, &ts->source_ip))
    {
        LOGF("JSON Error: ConnectionToPackets->settings->source-ipv4 (string field) : \"%s\" is not an IPv4 address",
             source_ipv4);
        return false;
    }

    // The field is documented as a routable unicast address, so every class that
    // could never carry a reply is refused here rather than at the first packet.
    if (ip4_addr_isany_val(ts->source_ip) || ip4_addr_isloopback(&ts->source_ip) ||
        ip4_addr_ismulticast(&ts->source_ip) || ip4_addr_get_u32(&ts->source_ip) == IPADDR_BROADCAST)
    {
        LOGF("JSON Error: ConnectionToPackets->settings->source-ipv4 (string field) : \"%s\" cannot be used as a "
             "routable virtual source address",
             source_ipv4);
        return false;
    }

    return true;
}

/*
 * Optional integers are validated rather than defaulted on error.
 * getIntFromJsonObjectOrDefault() cannot tell a missing field from a present
 * one of the wrong type, so `"mtu": "bad"` used to configure 1500 silently.
 */
static bool ctpLoadOptionalInteger(const cJSON *settings, const char *key, int64_t minimum, int64_t maximum,
                                   int64_t *value_inout)
{
    int64_t                   parsed = 0;
    const json_value_status_t status = jsonGetObjectIntegerInRange(settings, key, minimum, maximum, &parsed);

    if (status == kJsonValueMissing)
    {
        return true;
    }

    if (status == kJsonValueInvalid)
    {
        LOGF("JSON Error: ConnectionToPackets->settings->%s (int field) : expected a whole number between %lld and "
             "%lld",
             key,
             (long long) minimum,
             (long long) maximum);
        return false;
    }

    *value_inout = parsed;
    return true;
}

bool ctpLoadSettings(ctp_tstate_t *ts, const cJSON *settings)
{
    if (! checkJsonIsObjectAndHasChild(settings))
    {
        LOGF("JSON Error: ConnectionToPackets->settings (object field) : The object was empty or invalid");
        return false;
    }

    // No default: a silent virtual source would sooner or later collide with a
    // real address on the packet side.
    if (! ctpLoadSourceAddress(ts, settings))
    {
        return false;
    }

    /*
     * An omitted mtu inherits the core misc.mtu, the same way TunDevice's
     * device-mtu does. A node value overrides it, but the inherited value is
     * validated too: a core MTU this node cannot honour is a configuration
     * error, not something to silently round into range.
     */
    int64_t mtu = (int64_t) GLOBAL_MTU_SIZE;
    if (! ctpLoadOptionalInteger(settings, "mtu", (int64_t) kCtpMinMtu, (int64_t) kCtpMaxMtu, &mtu))
    {
        return false;
    }
    if (mtu < (int64_t) kCtpMinMtu || mtu > (int64_t) kCtpMaxMtu)
    {
        LOGF("JSON Error: ConnectionToPackets->settings->mtu (int field) : the inherited core misc.mtu of %lld is "
             "outside the supported range %u..%u; set an explicit node mtu",
             (long long) mtu,
             (unsigned int) kCtpMinMtu,
             (unsigned int) kCtpMaxMtu);
        return false;
    }
    ts->mtu = (uint32_t) mtu;

    /*
     * This node is IPv4-only by design, not pending IPv6 support, so `only-ipv4`
     * is the sole accepted strategy rather than merely the default.
     *
     * Every other value can hand this node an address it cannot use: the two
     * ipv6 strategies obviously, `prefer-ipv4` because its fallback resolves an
     * AAAA-only domain to IPv6, and `accept-dns-returned-order` because it
     * prefers neither family and takes whatever the server listed first. Refusing
     * them here turns a class of runtime line failures into one configuration
     * error that names the value to use.
     */
    enum domain_strategy domain_strategy = kDsOnlyIpV4;
    if (! getDomainStrategyFromJsonObjectOrDefault(&domain_strategy, settings, "domain-strategy", kDsOnlyIpV4))
    {
        LOGF("JSON Error: ConnectionToPackets->settings->domain-strategy (string or integer field) : The value was "
             "invalid");
        return false;
    }
    if (domain_strategy != kDsOnlyIpV4)
    {
        LOGF("JSON Error: ConnectionToPackets->settings->domain-strategy (string or integer field) : this node emits "
             "IPv4 only, so \"only-ipv4\" is the only strategy that can always produce a usable destination");
        return false;
    }
    ts->domain_strategy = (int) domain_strategy;

    int64_t connect_timeout_ms = (int64_t) kCtpDefaultConnectTimeoutMs;
    if (! ctpLoadOptionalInteger(settings, "tcp-connect-timeout-ms", 1, (int64_t) UINT32_MAX, &connect_timeout_ms))
    {
        return false;
    }
    ts->connect_timeout_ms = (uint32_t) connect_timeout_ms;

    int64_t max_pending_bytes = (int64_t) kCtpDefaultMaxPendingBytes;
    if (! ctpLoadOptionalInteger(settings,
                                 "max-pending-bytes",
                                 (int64_t) kCtpMinMaxPendingBytes,
                                 (int64_t) kCtpMaxMaxPendingBytes,
                                 &max_pending_bytes))
    {
        return false;
    }
    ts->max_pending_bytes = (uint32_t) max_pending_bytes;

    return true;
}

tunnel_t *ctpTunnelCreate(node_t *node)
{
    tunnel_t *t = tunnelCreate(node, sizeof(ctp_tstate_t), sizeof(ctp_lstate_t));
    if (! t)
    {
        return NULL;
    }
    ctp_tstate_t *ts       = tunnelGetState(t);
    const cJSON  *settings = node->node_settings_json;

    initializeTunnelCallbacks(t);

    *ts = (ctp_tstate_t) {
        .mtu                = GLOBAL_MTU_SIZE,
        .connect_timeout_ms = kCtpDefaultConnectTimeoutMs,
        .max_pending_bytes  = kCtpDefaultMaxPendingBytes,
        .domain_strategy    = (int) kDsOnlyIpV4,
        .next_generation    = 0,
    };
    atomic_init(&ts->stopping, false);
    deviceLifetimeGateInit(&ts->prev_gate);
    deviceLifetimeGateInit(&ts->next_gate);
    deviceLifetimeGateInit(&ts->packet_ingress_gate);

    // Brought up before anything that could fail, so every teardown path below
    // and in onDestroy() can take the core lock unconditionally.
    initTcpIpStack();

    /*
     * One stage per fallible resource, each committed before the next is
     * attempted. ctpTunnelDestroy() is the single unwind path for all of them,
     * and it decides what to release from the state each stage published -
     * `netifs`, `flow_registry_initialized`, `async_session` - rather than from
     * how far this function happened to get.
     *
     * The registry stage used to share a short-circuiting condition with the
     * netif array, so a failed array allocation skipped it entirely and the
     * unwind then locked a flows_lock that was never created.
     */
    ts->netifs_count   = getWorkersCount();
    ts->netifs         = memoryAllocateZero(sizeof(*ts->netifs) * ts->netifs_count);
    ts->terminal_lines = memoryAllocateZero(sizeof(*ts->terminal_lines) * ts->netifs_count);
    if (UNLIKELY(ts->netifs == NULL || ts->terminal_lines == NULL))
    {
        ctpTunnelDestroy(t);
        return NULL;
    }

    if (UNLIKELY(! ctpFlowRegistryInitialize(ts)))
    {
        ctpTunnelDestroy(t);
        return NULL;
    }

    ts->async_session = tunnelasyncsessionCreate(t, "ConnectionToPackets");
    if (UNLIKELY(ts->async_session == NULL))
    {
        ctpTunnelDestroy(t);
        return NULL;
    }

    if (! ctpLoadSettings(ts, settings) || ! ctpCreateInternalDomainResolver(t, node))
    {
        ctpTunnelDestroy(t);
        return NULL;
    }

    return t;
}

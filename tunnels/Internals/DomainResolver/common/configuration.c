#include "structure.h"

#include "loggers/network_logger.h"

static bool domainresolverCreateDirectConnector(tunnel_t *t)
{
    domainresolver_tstate_t *ts             = tunnelGetState(t);
    node_t                   connector_node = nodelibraryLoadByTypeName("TcpUdpConnector");
    if (connector_node.createHandle == NULL)
    {
        LOGF("DomainResolver: direct mode requires the TcpUdpConnector node in this build");
        return false;
    }

    // Registry metadata is borrowed; private child metadata has owner lifetime.
    connector_node.type        = stringDuplicate(connector_node.type);
    ts->dns_connector_settings = cJSON_CreateObject();
    cJSON_AddStringToObject(ts->dns_connector_settings, "address", "dest_context->address");
    cJSON_AddStringToObject(ts->dns_connector_settings, "port", "dest_context->port");
    if (! nodeConfigureChild(&ts->dns_connector_node,
                             connector_node,
                             t->node,
                             ".dns-connector",
                             kNodeChildLinkNone,
                             ts->dns_connector_settings))
        return false;

    /* These are fresh connector settings. In particular the connector's own
     * resolver receives its existing native settings, never this node's mode. */
    ts->dns_connector               = nodemanagerCreateTunnelInstance(&ts->dns_connector_node);
    ts->dns_connector_node.instance = ts->dns_connector;
    return ts->dns_connector != NULL;
}

bool domainresolverConfigureTransport(tunnel_t *t, const cJSON *settings)
{
    domainresolver_tstate_t    *ts = tunnelGetState(t);
    dns_policy_t                policy;
    const dns_policy_defaults_t defaults = {
        .resolve       = true,
        .strategy      = GSTATE.domain_strategy,
        .core_strategy = GSTATE.domain_strategy,
    };
    if (! dnsPolicyParseFlat(&policy, settings, &defaults, "DomainResolver->settings"))
        return false;
    ts->resolve     = policy.resolve;
    ts->strategy    = policy.strategy;
    ts->mode        = (domainresolver_mode_t) policy.mode;
    ts->dns_servers = policy.servers_csv;
    ts->dns_next    = policy.dns_next;
    if (ts->dns_next != NULL && t->node->name != NULL && strcmp(ts->dns_next, t->node->name) == 0)
    {
        LOGF("DomainResolver: dns-next must not refer to the resolver itself");
        return false;
    }
    if (! ts->resolve || ts->mode == kDomainResolverModeNative)
        return true;
    ts->dns_options = GSTATE.dns_options;
    if (! ts->dns_options.defaults_initialized)
        asyncdnsOptionsSetDefaults(&ts->dns_options);
    if (ts->dns_options.socket_send_buffer_size_set || ts->dns_options.socket_receive_buffer_size_set ||
        ts->dns_options.sortlist != NULL || ts->dns_options.resolvconf_path != NULL)
    {
        LOGF("DomainResolver: line DNS modes do not support core DNS socket-buffer-size, sortlist, or resolvconf-path "
             "options");
        return false;
    }
    ts->dns_options.servers_csv = ts->dns_servers;
    if (ts->mode == kDomainResolverModeDirect && ! domainresolverCreateDirectConnector(t))
        return false;
    ts->dns_workers_count = getWorkersCount();
    ts->dns_workers       = memoryCalloc(ts->dns_workers_count, sizeof(*ts->dns_workers));
    ts->dns_worker_closed = memoryCalloc(ts->dns_workers_count, sizeof(*ts->dns_worker_closed));
    return true;
}

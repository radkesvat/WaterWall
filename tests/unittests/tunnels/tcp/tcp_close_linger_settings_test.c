/* Real TCP adapter and combined-node constructors. SocketManager receives registrations without binding ports. */
#include "TcpConnector/structure.h"

#define kTunnelStateSize kTcpListenerTunnelStateSize
#define kLineStateSize   kTcpListenerLineStateSize
#include "TcpListener/structure.h"
#undef kLineStateSize
#undef kTunnelStateSize

#define kTunnelStateSize kTcpUdpConnectorTunnelStateSize
#define kLineStateSize   kTcpUdpConnectorLineStateSize
#include "TcpUdpConnector/interface.h"
#include "TcpUdpConnector/structure.h"
#undef kLineStateSize
#undef kTunnelStateSize

#define kTunnelStateSize kTcpUdpListenerTunnelStateSize
#define kLineStateSize   kTcpUdpListenerLineStateSize
#include "TcpUdpListener/structure.h"
#undef kLineStateSize
#undef kTunnelStateSize

#include "fixtures/failure/tunnel_line_failure_harness.h"

static tunnel_t *construct(node_t *node, const char *name, const char *next, const char *settings, const char *value)
{
    node->name               = (char *) name;
    node->next               = (char *) next;
    node->node_settings_json = cJSON_Parse(settings);
    twfRequire(node->node_settings_json != NULL, "invalid TCP settings fixture");
    if (value != NULL)
    {
        cJSON *item = cJSON_Parse(value);
        twfRequire(item != NULL && cJSON_AddItemToObject(node->node_settings_json, "linger-on-normal-close", item),
                   "failed to add linger setting to fixture");
    }

    ww_startup_context_t startup = {0};
    wwStartupContextBegin(&startup);
    node->instance                   = nodemanagerCreateTunnelInstance(node);
    const ww_startup_result_t result = wwStartupContextEnd(&startup);
    twfRequire(node->instance == NULL || wwStartupSucceeded(result), "constructed node reported startup failure");
    return node->instance;
}

static void destroy(node_t *node)
{
    if (node->instance != NULL)
        node->instance->onDestroy(node->instance, wwLifecycleStartupRollback());
    cJSON_Delete(node->node_settings_json);
    memoryFree(node->type);
}

static void runSettingsCase(const char *value, bool accepted, bool linger_enabled)
{
    twfSetCase(value != NULL ? value : "omitted linger-on-normal-close defaults to true");
    twfRequire(socketmanagerCreate() != NULL, "failed to create constructor fixture SocketManager");
    node_t      listener_node      = nodeTcpListenerGet();
    node_t      connector_node     = nodeTcpConnectorGet();
    node_t      udp_listener_node  = nodeTcpUdpListenerGet();
    node_t      udp_connector_node = nodeTcpUdpConnectorGet();
    const char *socket_settings    = "{\"address\":\"127.0.0.1\",\"port\":8000}";
    const char *destinations       = "{\"addresses\":[{\"address\":\"127.0.0.1\",\"port\":8000,\"weight\":2},"
                                     "{\"address\":\"127.0.0.1\",\"port\":8001,\"weight\":1}]}";

    tunnel_t *listener      = construct(&listener_node, "listener", "connector", socket_settings, value);
    tunnel_t *connector     = construct(&connector_node, "connector", NULL, destinations, value);
    tunnel_t *udp_listener  = construct(&udp_listener_node, "combined-listener", "connector", socket_settings, value);
    tunnel_t *udp_connector = construct(&udp_connector_node, "combined-connector", NULL, socket_settings, value);
    twfRequire((listener != NULL) == accepted, "TcpListener accepted an invalid value or rejected a valid one");
    twfRequire((connector != NULL) == accepted, "TcpConnector accepted an invalid value or rejected a valid one");
    twfRequire((udp_listener != NULL) == accepted, "TcpUdpListener did not preserve its TCP child's validation");
    twfRequire((udp_connector != NULL) == accepted, "TcpUdpConnector did not preserve its TCP child's validation");

    if (accepted)
    {
        const tcplistener_tstate_t  *listener_state  = tunnelGetState(listener);
        const tcpconnector_tstate_t *connector_state = tunnelGetState(connector);
        twfRequire(listener_state->linger_on_normal_close == linger_enabled, "listener lost its linger setting");
        twfRequire(connector_state->destinations_count == 2 &&
                       connector_state->linger_on_normal_close == linger_enabled,
                   "connector lost its node-wide linger setting with multiple destinations");

        const tcpudplistener_tstate_t  *udp_listener_state  = tunnelGetState(udp_listener);
        const tcpudpconnector_tstate_t *udp_connector_state = tunnelGetState(udp_connector);
        twfRequire(udp_listener_state->tcp_listener != NULL && udp_listener_state->udp_listener != NULL &&
                       udp_connector_state->tcp_connector != NULL && udp_connector_state->udp_connector != NULL,
                   "combined constructor did not create both transport legs");

        const tcplistener_tstate_t  *listener_child  = tunnelGetState(udp_listener_state->tcp_listener);
        const tcpconnector_tstate_t *connector_child = tunnelGetState(udp_connector_state->tcp_connector);
        twfRequire(listener_child->linger_on_normal_close == linger_enabled,
                   "combined listener TCP leg lost its setting");
        twfRequire(connector_child->linger_on_normal_close == linger_enabled,
                   "combined connector TCP leg lost its setting");
    }

    socketmanagerDestroy();
    destroy(&udp_connector_node);
    destroy(&udp_listener_node);
    destroy(&connector_node);
    destroy(&listener_node);
}

static void runOppositeSettingsCase(bool listener_lingers)
{
    twfSetCase(listener_lingers ? "listener enables linger and connector disables it in one chain"
                                : "listener disables linger and connector enables it in one chain");
    twfRequire(socketmanagerCreate() != NULL, "failed to create chain fixture SocketManager");
    node_t      listener_node  = nodeTcpListenerGet();
    node_t      connector_node = nodeTcpConnectorGet();
    const char *settings       = "{\"address\":\"127.0.0.1\",\"port\":8000}";
    tunnel_t   *listener =
        construct(&listener_node, "listener", "connector", settings, listener_lingers ? "true" : "false");
    tunnel_t *connector = construct(&connector_node, "connector", NULL, settings, listener_lingers ? "false" : "true");
    twfRequire(listener != NULL && connector != NULL, "failed to construct opposite TCP settings");
    tunnel_chain_t *chain = tunnelchainCreate(1);
    tunnelBind(listener, connector);
    tunnelchainInsert(chain, listener);
    tunnelchainInsert(chain, connector);

    const tcplistener_tstate_t  *listener_state  = tunnelGetState(listener);
    const tcpconnector_tstate_t *connector_state = tunnelGetState(connector);
    twfRequire(listener_state->linger_on_normal_close == listener_lingers &&
                   connector_state->linger_on_normal_close == ! listener_lingers,
               "one endpoint's setting changed the other endpoint's close policy");

    socketmanagerDestroy();
    destroy(&connector_node);
    destroy(&listener_node);
    tunnelchainDestroy(chain);
}

int main(void)
{
    twf_worker_env_t env;
    twfWorkerEnvSetup(&env, 4096, 0);
    GSTATE.domain_strategy = kDsPreferIpV4;
    runSettingsCase(NULL, true, true);
    runSettingsCase("true", true, true);
    runSettingsCase("false", true, false);
    runSettingsCase("null", false, false);
    runSettingsCase("\"true\"", false, false);
    runSettingsCase("1", false, false);
    runOppositeSettingsCase(true);
    runOppositeSettingsCase(false);
    twfWorkerEnvTeardown(&env);
    return 0;
}

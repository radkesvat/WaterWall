#include "connector.h"
#include "types.h"
#include "utils/sockutils.h"
#include "loggers/network_logger.h"

tunnel_t *newConnector(node_instance_context_t *instance_info)
{
    connector_state_t *state = malloc(sizeof(connector_state_t));
    memset(state, 0, sizeof(connector_state_t));
    const cJSON *settings = instance_info->node_settings_json;

    if (!(cJSON_IsObject(settings) && settings->child != NULL))
    {
        LOGF("JSON Error: Connector->settings (object field) : The object was empty or invalid");
        return NULL;
    }

    const cJSON *tcp_settings = cJSON_GetObjectItemCaseSensitive(settings, "tcp");
    if ((cJSON_IsObject(tcp_settings) && settings->child != NULL))
    {
        getBoolFromJsonObject(&(state->tcp_no_delay), tcp_settings, "nodelay");
        getBoolFromJsonObject(&(state->tcp_fast_open), tcp_settings, "fastopen");
        getBoolFromJsonObject(&(state->reuse_addr), tcp_settings, "reuseaddr");
        int ds = 0;
        getIntFromJsonObject(&ds, tcp_settings, "domain-strategy");
        state->domain_strategy = ds;
    }
    else
    {
        // memset set everything to 0...
    }

    state->dest_addr = parseDynamicStrValueFromJsonObject(settings, "address",2,
                                                          "src_context->address",
                                                         "dest_context->address");

    if (state->dest_addr.status == kDvsEmpty)
    {
        LOGF("JSON Error: Connector->settings->address (string field) : The vaule was empty or invalid");
        return NULL;
    }

    state->dest_port = parseDynamicNumericValueFromJsonObject(settings, "port",2,
                                                              "src_context->port",
                                                              "dest_context->port");

    if (state->dest_port.status == kDvsEmpty)
    {
        LOGF("JSON Error: Connector->settings->port (number field) : The vaule was empty or invalid");
        return NULL;
    }
    if(state->dest_addr.status == kDvsConstant){
        state->dest_atype = getHostAddrType(state->dest_addr.value_ptr); 
        state->dest_domain_len = strlen(state->dest_addr.value_ptr);
    }

    
    tunnel_t *t = newTunnel();
    t->state = state;

    t->upStream = &connectorUpStream;
    t->packetUpStream = &connectorPacketUpStream;
    t->downStream = &connectorDownStream;
    t->packetDownStream = &connectorPacketDownStream;

    atomic_thread_fence(memory_order_release);

    return t;
}
api_result_t apiConnector(tunnel_t *self, char *msg)
{
    (void)(self); (void)(msg); return (api_result_t){0}; // TODO
}
tunnel_t *destroyConnector(tunnel_t *self)
{
    return NULL;
}
tunnel_metadata_t getMetadataConnector()
{
    return (tunnel_metadata_t){.version = 0001, .flags = 0x0};
}
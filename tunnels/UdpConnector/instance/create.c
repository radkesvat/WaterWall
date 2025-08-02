#include "structure.h"

#include "loggers/network_logger.h"

static void initializeTunnelCallbacks(tunnel_t *t)
{
    t->fnInitU    = &udpconnectorTunnelUpStreamInit;
    t->fnEstU     = &udpconnectorTunnelUpStreamEst;
    t->fnFinU     = &udpconnectorTunnelUpStreamFinish;
    t->fnPayloadU = &udpconnectorTunnelUpStreamPayload;
    t->fnPauseU   = &udpconnectorTunnelUpStreamPause;
    t->fnResumeU  = &udpconnectorTunnelUpStreamResume;

    t->fnInitD    = &udpconnectorTunnelDownStreamInit;
    t->fnEstD     = &udpconnectorTunnelDownStreamEst;
    t->fnFinD     = &udpconnectorTunnelDownStreamFinish;
    t->fnPayloadD = &udpconnectorTunnelDownStreamPayload;
    t->fnPauseD   = &udpconnectorTunnelDownStreamPause;
    t->fnResumeD  = &udpconnectorTunnelDownStreamResume;

    t->onPrepair = &udpconnectorTunnelOnPrepair;
    t->onStart   = &udpconnectorTunnelOnStart;
    t->onDestroy = &udpconnectorTunnelDestroy;
}

static bool parseAddressSettings(udpconnector_tstate_t *state, const cJSON *settings)
{
    state->dest_addr_selected =
        parseDynamicStrValueFromJsonObject(settings, "address", 2, "src_context->address", "dest_context->address");

    if (state->dest_addr_selected.status == kDvsEmpty)
    {
        LOGF("JSON Error: UdpConnector->settings->address (string field) : The vaule was empty or invalid");
        return false;
    }

    if (state->dest_addr_selected.status == kDvsConstant)
    {
        if (addressIsIp(state->dest_addr_selected.string))
        {
            addresscontextSetIpAddress(&state->constant_dest_addr, state->dest_addr_selected.string);
        }
        else
        {
            addresscontextDomainSetConstMem(&(state->constant_dest_addr), state->dest_addr_selected.string,
                                            stringLength(state->dest_addr_selected.string));
        }
    }

    return true;
}

static bool parseRandomPortRange(const char *port_str, udpconnector_tstate_t *state, tunnel_t *t)
{
    const char *start = port_str + 7;
    const char *comma = strchr(start, ',');
    const char *end   = strchr(start, ')');

    if (comma == NULL || end == NULL || comma >= end)
    {
        LOGF("JSON Error: UdpConnector->settings->port: Invalid random port format, expected 'random(x,y)'");
        tunnelDestroy(t);
        return false;
    }

    char   x_str[16] = {0};
    size_t x_len     = comma - start;
    if (x_len >= sizeof(x_str))
    {
        LOGF("JSON Error: UdpConnector->settings->port: X value too long in random port range");
        tunnelDestroy(t);
        return false;
    }

    stringCopyN(x_str, start, x_len);
    x_str[x_len] = '\0';

    char   y_str[16] = {0};
    size_t y_len     = end - (comma + 1);
    if (y_len >= sizeof(y_str))
    {
        LOGF("JSON Error: UdpConnector->settings->port: Y value too long in random port range");
        tunnelDestroy(t);
        return false;
    }

    stringCopyN(y_str, comma + 1, y_len);
    y_str[y_len] = '\0';

    char *x_endptr;
    char *y_endptr;
    long  x_long = strtol(x_str, &x_endptr, 10);
    long  y_long = strtol(y_str, &y_endptr, 10);

    if (*x_endptr != '\0' || *y_endptr != '\0' || x_long < 0 || x_long > UINT16_MAX ||
        y_long < 0 || y_long > UINT16_MAX || x_long > y_long)
    {
        LOGF("JSON Error: UdpConnector->settings->port: Invalid random port range values or x > y");
        tunnelDestroy(t);
        return false;
    }

    uint16_t x_port = (uint16_t) x_long;
    uint16_t y_port = (uint16_t) y_long;

    addresscontextSetPort(&(state->constant_dest_addr), 0);
    state->dest_port_selected.status = kDvsRandom;
    state->random_dest_port_x = x_port;
    state->random_dest_port_y = y_port;

    LOGD("UdpConnector: Parsed random port range [%u, %u]", x_port, y_port);
    return true;
}

static bool parsePortAsNumber(const char *port_str, udpconnector_tstate_t *state, tunnel_t *t)
{
    char *endptr;
    long  port_long = strtol(port_str, &endptr, 10);

    if (*endptr != '\0' || port_long < 0 || port_long > UINT16_MAX)
    {
        LOGF("JSON Error: UdpConnector->settings->port: Expected 'random(x,y)' format or valid port number");
        tunnelDestroy(t);
        return false;
    }

    uint16_t port = (uint16_t) port_long;
    addresscontextSetPort(&(state->constant_dest_addr), port);
    return true;
}

static bool parsePortStringSettings(const char *port_str, udpconnector_tstate_t *state, tunnel_t *t)
{
    if (stringLength(port_str) < 1)
    {
        LOGF("JSON Error: UdpConnector->settings->port (string | int field) : The vaule was empty or invalid");
        return false;
    }

    if (strncmp(port_str, "random(", 7) == 0)
    {
        return parseRandomPortRange(port_str, state, t);
    }

    return parsePortAsNumber(port_str, state, t);
}

static bool parsePortSettings(udpconnector_tstate_t *state, const cJSON *settings, tunnel_t *t)
{
    const cJSON *jstr = cJSON_GetObjectItemCaseSensitive(settings, "port");

    if (cJSON_IsString(jstr) && (jstr->valuestring != NULL))
    {
        return parsePortStringSettings(jstr->valuestring, state, t);
    }

    state->dest_port_selected = parseDynamicNumericValueFromJsonObject(settings, "port", 3, "src_context->port",
                                                                       "dest_context->port", "random[x,y]");

    if (state->dest_port_selected.status == kDvsEmpty)
    {
        LOGF("JSON Error: UdpConnector->settings->port (number field) : The vaule was empty or invalid");
        tunnelDestroy(t);
        return false;
    }

    if (state->dest_port_selected.status == kDvsConstant)
    {
        addresscontextSetPort(&(state->constant_dest_addr), state->dest_port_selected.integer);
    }

    return true;
}

tunnel_t *udpconnectorTunnelCreate(node_t *node)
{
    tunnel_t *t = tunnelCreate(node, sizeof(udpconnector_tstate_t), sizeof(udpconnector_lstate_t));

    initializeTunnelCallbacks(t);

    const cJSON *settings = node->node_settings_json;
    udpconnector_tstate_t *state = tunnelGetState(t);

    if (! (cJSON_IsObject(settings) && settings->child != NULL))
    {
        LOGF("JSON Error: UdpConnector->settings (object field) : The object was empty or invalid");
        return NULL;
    }

    getBoolFromJsonObject(&(state->reuse_addr), settings, "reuseaddr");

    if (!parseAddressSettings(state, settings))
    {
        return NULL;
    }

    if (!parsePortSettings(state, settings, t))
    {
        return NULL;
    }

    return t;
}

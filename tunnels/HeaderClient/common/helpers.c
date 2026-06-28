#include "structure.h"

#include "loggers/network_logger.h"

static bool headerclientParsePort(uint16_t *out, const cJSON *value, const char *json_path)
{
    if (! cJSON_IsNumber(value))
    {
        LOGF("HeaderClient: %s must be a port number, \"src_context->port\", \"proxy-protocol\", "
             "\"proxy-protocol-v1\", or \"proxy-protocol-v2\"",
             json_path);
        return false;
    }

    if (value->valueint <= 0 || value->valueint > UINT16_MAX)
    {
        LOGF("HeaderClient: %s must be in range [1, %u]", json_path, (unsigned int) UINT16_MAX);
        return false;
    }

    *out = (uint16_t) value->valueint;
    return true;
}

static bool headerclientIsProxyProtocolMode(headerclient_data_mode_e mode)
{
    return mode == kHeaderClientDataModeProxyProtocolV1 || mode == kHeaderClientDataModeProxyProtocolV2;
}

static bool headerclientParseFrontendIpv4(headerclient_tstate_t *ts, const cJSON *settings)
{
    const cJSON *ip_json = cJSON_GetObjectItemCaseSensitive(settings, "frontend-ipv4");
    if (ip_json == NULL)
    {
        LOGF("HeaderClient: settings.frontend-ipv4 is required for PROXY protocol modes");
        return false;
    }

    if (! cJSON_IsString(ip_json) || ip_json->valuestring == NULL || stringLength(ip_json->valuestring) == 0)
    {
        LOGF("HeaderClient: settings.frontend-ipv4 must be an IPv4 address string");
        return false;
    }

    if (! addresscontextSetIpAddress(&ts->proxy_frontend_ipv4, ip_json->valuestring) ||
        ! addresscontextIsIpv4(&ts->proxy_frontend_ipv4))
    {
        LOGF("HeaderClient: settings.frontend-ipv4 must be an IPv4 address");
        return false;
    }

    addresscontextSetOnlyProtocol(&ts->proxy_frontend_ipv4, IP_PROTO_TCP);
    return true;
}

bool headerclientLoadSettings(headerclient_tstate_t *ts, const cJSON *settings)
{
    dynamic_value_t data = parseDynamicNumericValueFromJsonObject(settings,
                                                                  "data",
                                                                  5,
                                                                  "src_context->port",
                                                                  "line->src_ctx->port",
                                                                  "proxy-protocol",
                                                                  "proxy-protocol-v1",
                                                                  "proxy-protocol-v2");

    switch (data.status)
    {
    case kDvsFirstOption:
    case kDvsSecondOption:
        ts->data_mode = kHeaderClientDataModeSourcePort;
        break;

    case kDvsThirdOption:
    case kDvsFifthOption:
        ts->data_mode = kHeaderClientDataModeProxyProtocolV2;
        break;

    case kDvsFourthOption:
        ts->data_mode = kHeaderClientDataModeProxyProtocolV1;
        break;

    case kDvsConstant: {
        const cJSON *data_json = cJSON_GetObjectItemCaseSensitive(settings, "data");
        ts->data_mode          = kHeaderClientDataModeConstant;
        if (! headerclientParsePort(&ts->constant_port, data_json, "settings.data"))
        {
            return false;
        }
        break;
    }

    default:
        LOGF("HeaderClient: settings.data is required and must be a port number, \"src_context->port\", "
             "\"proxy-protocol\", \"proxy-protocol-v1\", or \"proxy-protocol-v2\"");
        return false;
    }

    if (headerclientIsProxyProtocolMode(ts->data_mode))
    {
        return headerclientParseFrontendIpv4(ts, settings);
    }

    return true;
}

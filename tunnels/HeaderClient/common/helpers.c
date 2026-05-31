#include "structure.h"

#include "loggers/network_logger.h"

static bool headerclientParsePort(uint16_t *out, const cJSON *value, const char *json_path)
{
    if (! cJSON_IsNumber(value))
    {
        LOGF("HeaderClient: %s must be a port number or \"src_context->port\"", json_path);
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

bool headerclientLoadSettings(headerclient_tstate_t *ts, const cJSON *settings)
{
    dynamic_value_t data =
        parseDynamicNumericValueFromJsonObject(settings, "data", 2, "src_context->port", "line->src_ctx->port");

    switch (data.status)
    {
    case kDvsFirstOption:
    case kDvsSecondOption:
        ts->data_mode = kHeaderClientDataModeSourcePort;
        return true;

    case kDvsConstant: {
        const cJSON *data_json = cJSON_GetObjectItemCaseSensitive(settings, "data");
        ts->data_mode          = kHeaderClientDataModeConstant;
        return headerclientParsePort(&ts->constant_port, data_json, "settings.data");
    }

    default:
        LOGF("HeaderClient: settings.data is required and must be a port number or \"src_context->port\"");
        return false;
    }
}

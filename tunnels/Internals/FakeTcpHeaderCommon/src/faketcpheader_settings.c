#include "FakeTcpHeaderCommon/faketcpheader_wire.h"

#include "loggers/network_logger.h"

typedef struct faketcpheader_settings_integer_s
{
    const char *key;
    uint32_t    minimum;
    uint32_t    maximum;
} faketcpheader_settings_integer_t;

static const faketcpheader_settings_integer_t kSettingsServerPort      = {"server-port", 1, UINT16_MAX};
static const faketcpheader_settings_integer_t kSettingsClientPort      = {"client-port", 1, UINT16_MAX};
static const faketcpheader_settings_integer_t kSettingsClientPortCount = {
    "client-port-count", 1, kFakeTcpHeaderWireMaxClientPortCount};
static const faketcpheader_settings_integer_t kSettingsSequence        = {"sequence", 0, UINT32_MAX};
static const faketcpheader_settings_integer_t kSettingsAcknowledgment  = {"acknowledgment", 0, UINT32_MAX};
static const faketcpheader_settings_integer_t kSettingsWindow          = {"window", 0, UINT16_MAX};
static const faketcpheader_settings_integer_t kSettingsUrgentPointer   = {"urgent-pointer", 0, UINT16_MAX};
static const faketcpheader_settings_integer_t kSettingsPayloadProtocol = {"payload-protocol", 6, 17};

static const faketcpheader_settings_integer_t *const kSettingsIntegers[] = {&kSettingsPayloadProtocol,
                                                                            &kSettingsServerPort,
                                                                            &kSettingsClientPort,
                                                                            &kSettingsClientPortCount,
                                                                            &kSettingsSequence,
                                                                            &kSettingsAcknowledgment,
                                                                            &kSettingsWindow,
                                                                            &kSettingsUrgentPointer};

static const char *const kSettingsOptions = "options";

static bool faketcpheaderSettingsKeyIsKnown(const char *key)
{
    if (key == NULL)
    {
        return false;
    }
    for (size_t i = 0; i < ARRAY_SIZE(kSettingsIntegers); ++i)
    {
        if (stringCompare(key, kSettingsIntegers[i]->key) == 0)
        {
            return true;
        }
    }
    return stringCompare(key, kSettingsOptions) == 0;
}

static bool faketcpheaderSettingsKeysAreKnown(const cJSON *settings, const char *node_name)
{
    const cJSON *item = NULL;
    cJSON_ArrayForEach(item, settings)
    {
        if (! faketcpheaderSettingsKeyIsKnown(item->string))
        {
            LOGF("JSON Error: %s->settings->%s : unknown setting",
                 node_name,
                 item->string != NULL ? item->string : "<unnamed>");
            return false;
        }
        if (! jsonObjectFieldStringsAreExact(settings, item->string))
        {
            LOGF("JSON Error: %s->settings->%s : expected a key and value without embedded NUL or invalid UTF-8",
                 node_name,
                 item->string);
            return false;
        }
    }
    return true;
}

static bool faketcpheaderSettingsLoadInteger(const cJSON *settings, const char *node_name,
                                             const faketcpheader_settings_integer_t *rule, uint32_t fallback,
                                             uint32_t *value_out)
{
    int64_t                   value = 0;
    const json_value_status_t status =
        jsonGetObjectIntegerInRange(settings, rule->key, rule->minimum, rule->maximum, &value);
    if (status == kJsonValueInvalid)
    {
        LOGF("JSON Error: %s->settings->%s : expected an integer from %u to %u",
             node_name,
             rule->key,
             (unsigned int) rule->minimum,
             (unsigned int) rule->maximum);
        return false;
    }
    *value_out = status == kJsonValuePresent ? (uint32_t) value : fallback;
    return true;
}

static bool faketcpheaderSettingsLoadOptions(const cJSON *settings, const char *node_name,
                                             faketcpheader_wire_config_t *config)
{
    const cJSON *options = cJSON_GetObjectItemCaseSensitive(settings, kSettingsOptions);
    if (options == NULL)
    {
        return true;
    }

    const size_t hex_length =
        cJSON_IsString(options) && options->valuestring != NULL ? stringLength(options->valuestring) : SIZE_MAX;
    const size_t byte_length = hex_length / 2U;
    if (hex_length == SIZE_MAX || hex_length % 2U != 0 || byte_length > kFakeTcpHeaderWireMaxOptionsLength ||
        byte_length % 4U != 0 ||
        ! asciiHexDecodeBytes((const uint8_t *) options->valuestring, hex_length, config->options, byte_length))
    {
        LOGF("JSON Error: %s->settings->%s : expected a hexadecimal string of 0 to %u bytes in four-byte groups",
             node_name,
             kSettingsOptions,
             (unsigned int) kFakeTcpHeaderWireMaxOptionsLength);
        return false;
    }
    config->options_length = (uint8_t) byte_length;
    return true;
}

bool faketcpheaderWireLoadSettings(const cJSON *settings, const char *node_name, faketcpheader_wire_config_t *out)
{
    assert(node_name != NULL && out != NULL);

    faketcpheader_wire_config_t config = {0};
    if (settings != NULL && ! cJSON_IsObject(settings))
    {
        LOGF("JSON Error: %s->settings : expected an object", node_name);
        return false;
    }
    int64_t payload_protocol = 0;
    if (jsonGetObjectIntegerInRange(settings, kSettingsPayloadProtocol.key, 6, 17, &payload_protocol) !=
            kJsonValuePresent ||
        (payload_protocol != IPPROTO_TCP && payload_protocol != IPPROTO_UDP))
    {
        LOGF("JSON Error: %s->settings->payload-protocol : required integer 6 (TCP) or 17 (UDP)", node_name);
        return false;
    }
    if (! faketcpheaderSettingsKeysAreKnown(settings, node_name))
    {
        return false;
    }

    uint32_t server_port = 0, client_port = 0, client_port_count = 0, window = 0, urgent_pointer = 0;
    if (! faketcpheaderSettingsLoadInteger(settings, node_name, &kSettingsServerPort, 40000, &server_port) ||
        ! faketcpheaderSettingsLoadInteger(settings, node_name, &kSettingsClientPort, 40001, &client_port) ||
        ! faketcpheaderSettingsLoadInteger(settings, node_name, &kSettingsClientPortCount, 16, &client_port_count) ||
        ! faketcpheaderSettingsLoadInteger(settings, node_name, &kSettingsSequence, 0, &config.sequence) ||
        ! faketcpheaderSettingsLoadInteger(settings, node_name, &kSettingsAcknowledgment, 0, &config.acknowledgment) ||
        ! faketcpheaderSettingsLoadInteger(settings, node_name, &kSettingsWindow, UINT16_MAX, &window) ||
        ! faketcpheaderSettingsLoadInteger(settings, node_name, &kSettingsUrgentPointer, 0, &urgent_pointer) ||
        ! faketcpheaderSettingsLoadOptions(settings, node_name, &config))
    {
        return false;
    }

    if (client_port + client_port_count - 1U > UINT16_MAX)
    {
        LOGF("JSON Error: %s->settings->%s : expected client-port + client-port-count - 1 <= 65535 (client-port %u)",
             node_name,
             kSettingsClientPortCount.key,
             (unsigned int) client_port);
        return false;
    }
    if (server_port >= client_port && server_port < client_port + client_port_count)
    {
        LOGF("JSON Error: %s->settings->%s : expected a port outside the client range %u to %u",
             node_name,
             kSettingsServerPort.key,
             (unsigned int) client_port,
             (unsigned int) (client_port + client_port_count - 1U));
        return false;
    }

    config.server_port       = (uint16_t) server_port;
    config.client_port       = (uint16_t) client_port;
    config.client_port_count = (uint16_t) client_port_count;
    config.payload_protocol  = (uint8_t) payload_protocol;
    config.window            = (uint16_t) window;
    config.urgent_pointer    = (uint16_t) urgent_pointer;
    *out                     = config;
    return true;
}

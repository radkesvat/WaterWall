#include "FakeTcpHeaderCommon/faketcpheader_wire.h"

#include "loggers/network_logger.h"

typedef struct faketcpheader_settings_integer_s
{
    const char *key;
    uint32_t    minimum;
    uint32_t    maximum;
} faketcpheader_settings_integer_t;

static const faketcpheader_settings_integer_t        kSettingsServerPort    = {"server-port", 1, UINT16_MAX};
static const faketcpheader_settings_integer_t        kSettingsClientPort    = {"client-port", 1, UINT16_MAX};
static const faketcpheader_settings_integer_t        kSettingsWindow        = {"window", 0, UINT16_MAX};
static const faketcpheader_settings_integer_t        kSettingsUrgentPointer = {"urgent-pointer", 0, UINT16_MAX};
static const faketcpheader_settings_integer_t *const kSettingsIntegers[]    = {
    &kSettingsServerPort, &kSettingsClientPort, &kSettingsWindow, &kSettingsUrgentPointer};

static const char *const kSettingsOptions           = "options";
static const char *const kSettingsClientPortRange   = "client-port-range";
static const char *const kSettingsIncrementSequence = "increment-sequence";
static const char *const kSettingsIncrementAcknowledgment = "increment-acknowledgment";
static const char *const kSettingsSequence          = "sequence";
static const char *const kSettingsAcknowledgment    = "acknowledgment";
static const char *const kSettingsFlags                   = "flags";

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
    return stringCompare(key, kSettingsOptions) == 0 || stringCompare(key, kSettingsClientPortRange) == 0 ||
           stringCompare(key, kSettingsIncrementSequence) == 0 || stringCompare(key, kSettingsSequence) == 0 ||
           stringCompare(key, kSettingsAcknowledgment) == 0 ||
           stringCompare(key, kSettingsIncrementAcknowledgment) == 0 || stringCompare(key, kSettingsFlags) == 0;
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

static bool faketcpheaderSettingsLoadClientPorts(const cJSON *settings, const char *node_name, uint32_t *first_out,
                                                 uint32_t *count_out)
{
    const cJSON *port  = cJSON_GetObjectItemCaseSensitive(settings, kSettingsClientPort.key);
    const cJSON *range = cJSON_GetObjectItemCaseSensitive(settings, kSettingsClientPortRange);
    if (port != NULL && range != NULL)
    {
        LOGF("JSON Error: %s->settings->%s : use either client-port or client-port-range, not both",
             node_name,
             kSettingsClientPortRange);
        return false;
    }
    if (range == NULL)
    {
        if (! faketcpheaderSettingsLoadInteger(settings, node_name, &kSettingsClientPort, 40001, first_out))
        {
            return false;
        }
        *count_out = port != NULL ? 1 : 16;
        return true;
    }
    if (! cJSON_IsArray(range) || cJSON_GetArraySize(range) != 2)
    {
        LOGF("JSON Error: %s->settings->%s : expected [first, last] with exactly two integer ports",
             node_name,
             kSettingsClientPortRange);
        return false;
    }
    int64_t first = 0, last = 0;
    if (! jsonGetIntegerInRange(cJSON_GetArrayItem(range, 0), 1, UINT16_MAX, &first) ||
        ! jsonGetIntegerInRange(cJSON_GetArrayItem(range, 1), 1, UINT16_MAX, &last))
    {
        LOGF("JSON Error: %s->settings->%s : expected integer endpoints from 1 to 65535",
             node_name,
             kSettingsClientPortRange);
        return false;
    }
    if (first > last)
    {
        LOGF("JSON Error: %s->settings->%s : first port must be lower than or equal to last port",
             node_name,
             kSettingsClientPortRange);
        return false;
    }
    const uint32_t count = (uint32_t) (last - first + 1);
    if (count > kFakeTcpHeaderWireMaxClientPortCount)
    {
        LOGF("JSON Error: %s->settings->%s : expected at most %u ports",
             node_name,
             kSettingsClientPortRange,
             (unsigned int) kFakeTcpHeaderWireMaxClientPortCount);
        return false;
    }
    *first_out = (uint32_t) first;
    *count_out = count;
    return true;
}

static bool faketcpheaderSettingsLoadField(const cJSON *settings, const char *node_name, const char *key,
                                           bool allow_random_packet, faketcpheader_field_mode_t *mode_out,
                                           uint32_t *value_out)
{
    const cJSON *item = cJSON_GetObjectItemCaseSensitive(settings, key);
    if (item == NULL)
    {
        return true;
    }
    int64_t value = 0;
    if (jsonGetIntegerInRange(item, 0, UINT32_MAX, &value))
    {
        *mode_out  = kFakeTcpHeaderFieldNumeric;
        *value_out = (uint32_t) value;
        return true;
    }
    const char *mode = cJSON_GetStringValue(item);
    if (mode != NULL)
    {
        if (stringCompare(mode, "random_node") == 0)
        {
            *mode_out = kFakeTcpHeaderFieldRandomNode;
            return true;
        }
        if (stringCompare(mode, "random_port") == 0)
        {
            *mode_out = kFakeTcpHeaderFieldRandomPort;
            return true;
        }
        if (allow_random_packet && stringCompare(mode, "random_packet") == 0)
        {
            *mode_out = kFakeTcpHeaderFieldRandomPacket;
            return true;
        }
    }
    LOGF("JSON Error: %s->settings->%s : expected an integer from 0 to 4294967295 or %s",
         node_name,
         key,
         allow_random_packet ? "random_node, random_port or random_packet" : "random_node or random_port");
    return false;
}

static bool faketcpheaderSettingsLoadFlags(const cJSON *settings, const char *node_name,
                                           faketcpheader_wire_config_t *config)
{
    const cJSON *array = NULL;
    const cJSON *field = NULL;
    cJSON_ArrayForEach(field, settings)
    {
        if (stringCompare(field->string, kSettingsFlags) == 0)
        {
            if (array != NULL)
            {
                LOGF("JSON Error: %s->settings->flags : duplicate setting", node_name);
                return false;
            }
            array = field;
        }
    }
    if (array == NULL)
    {
        return true;
    }
    const int count = cJSON_GetArraySize(array);
    if (! cJSON_IsArray(array) || count < 1 || count > kFakeTcpHeaderWireMaxFlagCount)
    {
        LOGF("JSON Error: %s->settings->flags : expected an array of 1 to %u flag objects",
             node_name,
             (unsigned int) kFakeTcpHeaderWireMaxFlagCount);
        return false;
    }
    static const struct
    {
        const char *name;
        uint8_t     mask;
    } bits[]           = {{"fin", TCP_FIN},
                          {"syn", TCP_SYN},
                          {"rst", TCP_RST},
                          {"psh", TCP_PSH},
                          {"ack", TCP_ACK},
                          {"urg", TCP_URG},
                          {"ece", TCP_ECE},
                          {"cwr", TCP_CWR}};
    const cJSON *entry = NULL;
    unsigned int index = 0;
    cJSON_ArrayForEach(entry, array)
    {
        if (! cJSON_IsObject(entry))
        {
            LOGF("JSON Error: %s->settings->flags : entry %u must be an object", node_name, index);
            return false;
        }
        uint8_t flags = 0, seen = 0;
        cJSON_ArrayForEach(field, entry)
        {
            size_t bit = 0;
            while (bit < ARRAY_SIZE(bits) &&
                   (field->string == NULL || stringCompare(field->string, bits[bit].name) != 0))
            {
                ++bit;
            }
            if (bit == ARRAY_SIZE(bits) || ! jsonObjectFieldStringsAreExact(entry, bits[bit].name))
            {
                LOGF(
                    "JSON Error: %s->settings->flags : entry %u has an unknown or invalid flag name", node_name, index);
                return false;
            }
            if ((seen & bits[bit].mask) != 0 || ! cJSON_IsBool(field))
            {
                LOGF("JSON Error: %s->settings->flags : entry %u->%s must be a single true or false value",
                     node_name,
                     index,
                     bits[bit].name);
                return false;
            }
            seen |= bits[bit].mask;
            if (cJSON_IsTrue(field))
            {
                flags |= bits[bit].mask;
            }
        }
        config->flags[index++] = flags;
    }
    config->flags_count = (uint8_t) count;
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

    faketcpheader_wire_config_t config = {.sequence_mode      = kFakeTcpHeaderFieldRandomPort,
                                          .increment_sequence = true,
                                          .flags_count        = 1,
                                          .flags              = {kFakeTcpHeaderWireTcpFlags}};
    if (settings != NULL && ! cJSON_IsObject(settings))
    {
        LOGF("JSON Error: %s->settings : expected an object", node_name);
        return false;
    }
    if (! faketcpheaderSettingsKeysAreKnown(settings, node_name))
    {
        return false;
    }
    if (jsonGetObjectBoolean(settings, kSettingsIncrementSequence, &config.increment_sequence) == kJsonValueInvalid)
    {
        LOGF("JSON Error: %s->settings->%s : expected true or false", node_name, kSettingsIncrementSequence);
        return false;
    }
    if (jsonGetObjectBoolean(settings, kSettingsIncrementAcknowledgment, &config.increment_acknowledgment) ==
        kJsonValueInvalid)
    {
        LOGF("JSON Error: %s->settings->%s : expected true or false", node_name, kSettingsIncrementAcknowledgment);
        return false;
    }

    uint32_t server_port = 0, client_port = 0, client_port_count = 0, window = 0, urgent_pointer = 0;
    if (! faketcpheaderSettingsLoadInteger(settings, node_name, &kSettingsServerPort, 40000, &server_port) ||
        ! faketcpheaderSettingsLoadClientPorts(settings, node_name, &client_port, &client_port_count) ||
        ! faketcpheaderSettingsLoadField(
            settings, node_name, kSettingsSequence, false, &config.sequence_mode, &config.sequence) ||
        ! faketcpheaderSettingsLoadField(
            settings, node_name, kSettingsAcknowledgment, true, &config.acknowledgment_mode, &config.acknowledgment) ||
        ! faketcpheaderSettingsLoadInteger(settings, node_name, &kSettingsWindow, UINT16_MAX, &window) ||
        ! faketcpheaderSettingsLoadInteger(settings, node_name, &kSettingsUrgentPointer, 0, &urgent_pointer) ||
        ! faketcpheaderSettingsLoadOptions(settings, node_name, &config) ||
        ! faketcpheaderSettingsLoadFlags(settings, node_name, &config))
    {
        return false;
    }

    if (config.increment_acknowledgment && config.acknowledgment_mode == kFakeTcpHeaderFieldRandomPacket)
    {
        LOGF("JSON Error: %s->settings->%s : cannot be true with acknowledgment set to random_packet",
             node_name,
             kSettingsIncrementAcknowledgment);
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
    config.window            = (uint16_t) window;
    config.urgent_pointer    = (uint16_t) urgent_pointer;
    *out                     = config;
    return true;
}

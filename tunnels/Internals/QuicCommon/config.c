#include "quic_common.h"

#include "loggers/network_logger.h"

static void quicFatalAllocation(void)
{
    abortProgramNow(1);
}

static bool quicCheckFieldStrings(const cJSON *object, const char *name)
{
    if (! jsonObjectFieldStringsAreExact(object, name))
    {
        LOGF("JSON Error: QUIC setting \"%s\" requires valid exact strings", name);
        return false;
    }
    return true;
}

static bool quicCheckSettingsStrings(const cJSON *settings)
{
    /* Both roles recognize this vocabulary. Unknown settings keep their normal
     * policy, while malformed recognized keys cannot alias a consumed field. */
    static const char *const names[] = {"protocol",
                                        "carrier-mode",
                                        "sni",
                                        "ca-file",
                                        "cert-file",
                                        "key-file",
                                        "verify",
                                        "verbose",
                                        "handshake-timeout-ms",
                                        "idle-timeout-ms",
                                        "max-packet-size",
                                        "max-buffered-bytes",
                                        "max-buffered-buffers",
                                        "receive-window-bytes"};
    for (size_t i = 0; i < ARRAY_SIZE(names); ++i)
    {
        if (! quicCheckFieldStrings(settings, names[i]))
        {
            return false;
        }
    }
    return true;
}

static bool quicReadInteger(const cJSON *settings, const char *name, uint32_t minimum, uint32_t maximum,
                            uint32_t *value)
{
    int64_t parsed = *value;
    if (jsonGetObjectIntegerInRange(settings, name, minimum, maximum, &parsed) == kJsonValueInvalid)
    {
        LOGF("JSON Error: QUIC settings->%s must be an integer in %u..%u", name, minimum, maximum);
        return false;
    }
    *value = (uint32_t) parsed;
    return true;
}

bool quicReadString(const cJSON *settings, const char *name, const char **value, bool required)
{
    json_value_status_t result = jsonGetObjectNonEmptyString(settings, name, value);
    if (result == kJsonValueInvalid || (required && result == kJsonValueMissing))
    {
        LOGF("JSON Error: QUIC settings->%s must be a nonempty string", name);
        return false;
    }
    return true;
}

bool quicReadBoolean(const cJSON *settings, const char *name, bool *value)
{
    if (jsonGetObjectBoolean(settings, name, value) == kJsonValueInvalid)
    {
        LOGF("JSON Error: QUIC settings->%s must be a boolean", name);
        return false;
    }
    return true;
}

bool quicReadCommonSettings(const node_t *node, quic_node_settings_t *settings)
{
    const cJSON *json = node->node_settings_json;
    if (! quicCheckFieldStrings(node->node_json, "type") || ! quicCheckFieldStrings(node->node_json, "settings"))
    {
        return false;
    }
    /* Check every settings occurrence, including duplicates ignored by lookup.
     * Also validate the actual settings pointer for directly constructed nodes. */
    if (cJSON_IsObject(node->node_json))
    {
        for (const cJSON *field = node->node_json->child; field != NULL; field = field->next)
        {
            if (field->string != NULL && strcmp(field->string, "settings") == 0 && ! quicCheckSettingsStrings(field))
            {
                return false;
            }
        }
    }
    if (! quicCheckSettingsStrings(json))
    {
        return false;
    }
    if (json != NULL && ! cJSON_IsObject(json))
    {
        LOGF("JSON Error: QUIC settings must be an object");
        return false;
    }
    *settings                   = (quic_node_settings_t) {.engine = {.verify               = true,
                                                                     .protocol             = "h3",
                                                                     .handshake_timeout_ms = 10000,
                                                                     .idle_timeout_ms      = 60000,
                                                                     .max_packet_size      = 1350,
                                                                     .max_buffered_bytes   = 2097152,
                                                                     .max_buffered_buffers = 1024,
                                                                     .receive_window_bytes = 1048576,
                                                                     .allocate             = memoryAllocate,
                                                                     .deallocate           = memoryFree,
                                                                     .fatal                = quicFatalAllocation}};
    ww_quic_settings_t *engine  = &settings->engine;
    const char         *carrier = "datagram";
    if (! quicReadString(json, "protocol", &engine->protocol, false) ||
        ! quicReadString(json, "carrier-mode", &carrier, false) ||
        ! quicReadBoolean(json, "verbose", &settings->verbose) ||
        ! quicReadInteger(json, "handshake-timeout-ms", 1, WW_QUIC_MAX_TIMEOUT_MS, &engine->handshake_timeout_ms) ||
        ! quicReadInteger(json, "idle-timeout-ms", 1, WW_QUIC_MAX_TIMEOUT_MS, &engine->idle_timeout_ms) ||
        ! quicReadInteger(json, "max-packet-size", 1200, 1452, &engine->max_packet_size) ||
        ! quicReadInteger(json, "max-buffered-bytes", 65536, WW_QUIC_MAX_BUFFERED_BYTES, &engine->max_buffered_bytes) ||
        ! quicReadInteger(
            json, "max-buffered-buffers", 1, WW_QUIC_MAX_BUFFERED_BUFFERS, &engine->max_buffered_buffers) ||
        ! quicReadInteger(json, "receive-window-bytes", 16384, 16777216, &engine->receive_window_bytes))
    {
        return false;
    }
    if (strcmp(carrier, "datagram") != 0 && strcmp(carrier, "stream") != 0)
    {
        LOGF("JSON Error: QUIC settings->carrier-mode must be datagram or stream");
        return false;
    }
    if (engine->receive_window_bytes > engine->max_buffered_bytes)
    {
        LOGF("JSON Error: QUIC receive-window-bytes must fit max-buffered-bytes");
        return false;
    }
    if (((uint64_t) engine->max_buffered_buffers + 1) * WW_QUIC_EVENT_DESCRIPTOR_CHARGE > engine->max_buffered_bytes)
    {
        LOGF("JSON Error: QUIC max-buffered-buffers descriptors must fit max-buffered-bytes");
        return false;
    }
    settings->stream_carrier = strcmp(carrier, "stream") == 0;
    return true;
}

bool quicConfigureTunnel(tunnel_t *t, const quic_node_settings_t *settings, const quic_output_t *output)
{
    assert(output != NULL && output->wire_payload != NULL && output->application_payload != NULL &&
           output->application_pause != NULL && output->application_resume != NULL);
    const ww_quic_settings_t *engine     = &settings->engine;
    char                      error[512] = {0};
    ww_quic_config_t         *config     = ww_quic_config_create(engine, error, sizeof(error));
    if (config == NULL)
    {
        LOGF("JSON Error: %s: %s", engine->is_client ? "QuicClient" : "QuicServer", error);
        return false;
    }
    quic_tstate_t *state = tunnelGetState(t);
    *state               = (quic_tstate_t) {.config         = config,
                                            .workers        = memoryCalloc(getWorkersCount(), sizeof(quic_context_t *)),
                                            .output         = output,
                                            .max_bytes      = engine->max_buffered_bytes,
                                            .max_buffers    = engine->max_buffered_buffers,
                                            .client         = engine->is_client,
                                            .stream_carrier = settings->stream_carrier,
                                            .verbose        = settings->verbose};
    atomic_init(&state->stopping, false);
    return true;
}

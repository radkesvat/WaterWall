#include "internal.h"

#include "../../Internals/AuthenticationCommon/stream.h"
#include "loggers/network_logger.h"

static void authenticationclientWriteNetworkUI32(uint8_t *dest, uint32_t value);

static uint32_t authenticationclientReadNetworkUI32(const uint8_t *src);

static uint64_t authenticationclientReadNetworkUI64(const uint8_t *src);

static const char *authenticationclientRequestTypeName(uint8_t request_type);

static const char *authenticationclientResponseTypeName(uint8_t response_type);

static void authenticationclientCorrelationIdWrite(uint8_t  dest[kAuthenticationClientCorrelationIdSize],
                                                   uint32_t value);

static uint32_t authenticationclientCorrelationIdRead(const uint8_t src[kAuthenticationClientCorrelationIdSize]);

static sbuf_t *authenticationclientCreateRequestMessage(line_t *l, uint8_t request_type, uint32_t correlation_id,
                                                        const uint8_t *request_data, uint32_t request_data_len,
                                                        const uint8_t token[kAuthenticationClientSessionTokenSize]);

static bool authenticationclientSendJsonRequest(tunnel_t *t, uint8_t request_type, cJSON *json);

static bool authenticationclientReadMessageHeader(authenticationclient_lstate_t *ls, uint32_t *message_body_len);

static bool authenticationclientValidateResponsePayload(sbuf_t *payload);

static void authenticationclientWriteNetworkUI32(uint8_t *dest, uint32_t value)
{
    uint32_t network_value = htonl(value);
    sbufByteCopy(dest, &network_value, (uint32_t) sizeof(network_value));
}

static uint32_t authenticationclientReadNetworkUI32(const uint8_t *src)
{
    uint32_t network_value = 0;
    sbufByteCopy(&network_value, src, (uint32_t) sizeof(network_value));
    return ntohl(network_value);
}

static uint64_t authenticationclientReadNetworkUI64(const uint8_t *src)
{
    return ((uint64_t) src[0] << 56U) | ((uint64_t) src[1] << 48U) | ((uint64_t) src[2] << 40U) |
           ((uint64_t) src[3] << 32U) | ((uint64_t) src[4] << 24U) | ((uint64_t) src[5] << 16U) |
           ((uint64_t) src[6] << 8U) | (uint64_t) src[7];
}

static const char *authenticationclientRequestTypeName(uint8_t request_type)
{
    switch (request_type)
    {
    case kAuthenticationClientRequestTypePing:
        return "Ping";
    case kAuthenticationClientRequestTypeGetUserBySHA256Hex:
        return "GetUserBySHA256Hex";
    case kAuthenticationClientRequestTypeGetUserBySHA256Base64:
        return "GetUserBySHA256Base64";
    case kAuthenticationClientRequestTypeGetUserBySHA256:
        return "GetUserBySHA256";
    case kAuthenticationClientRequestTypeGetUserBySHA224Hex:
        return "GetUserBySHA224Hex";
    case kAuthenticationClientRequestTypeGetUserBySHA224Base64:
        return "GetUserBySHA224Base64";
    case kAuthenticationClientRequestTypeGetUserBySHA224:
        return "GetUserBySHA224";
    case kAuthenticationClientRequestTypeGetUserByPassword:
        return "GetUserByPassword";
    case kAuthenticationClientRequestTypeAddNewUser:
        return "AddNewUser";
    case kAuthenticationClientRequestTypeUpdateUser:
        return "UpdateUser";
    case kAuthenticationClientRequestTypeGetAllUsers:
        return "GetUsersPage";
    case kAuthenticationClientRequestTypeAuthenticate:
        return "Authenticate";
    case kAuthenticationClientRequestTypePushUserStats:
        return "PushUserStats";
    default:
        return "Unknown";
    }
}

static const char *authenticationclientResponseTypeName(uint8_t response_type)
{
    switch (response_type)
    {
    case kAuthenticationClientResponseTypeOk:
        return "Ok";
    case kAuthenticationClientResponseTypeError:
        return "Error";
    case kAuthenticationClientResponseTypePong:
        return "Pong";
    case kAuthenticationClientResponseTypeUser:
        return "User";
    case kAuthenticationClientResponseTypeUsers:
        return "Users";
    case kAuthenticationClientResponseTypeSession:
        return "Session";
    default:
        return "Unknown";
    }
}

static void authenticationclientCorrelationIdWrite(uint8_t dest[kAuthenticationClientCorrelationIdSize], uint32_t value)
{
    authenticationclientWriteNetworkUI32(dest, value);
}

static uint32_t authenticationclientCorrelationIdRead(const uint8_t src[kAuthenticationClientCorrelationIdSize])
{
    return authenticationclientReadNetworkUI32(src);
}

static sbuf_t *authenticationclientCreateRequestMessage(line_t *l, uint8_t request_type, uint32_t correlation_id,
                                                        const uint8_t *request_data, uint32_t request_data_len,
                                                        const uint8_t token[kAuthenticationClientSessionTokenSize])
{
    const uint32_t frame_len   = kAuthenticationClientRequestHeaderSize + request_data_len;
    const uint32_t message_len = kAuthenticationClientRequestEnvelopeHeaderSize + frame_len;

    // Protocol limits are intentionally far below UINT32_MAX; revisit if those limits grow.
    if (UNLIKELY(request_data_len > kAuthenticationClientMaxRequestData ||
                 frame_len > kAuthenticationClientMaxMessagePayload))
    {
        LOGW("AuthenticationClient: refused oversized request type %u", (unsigned int) request_type);
        return NULL;
    }

    sbuf_t *message = bufferpoolGetLargeBuffer(lineGetBufferPool(l));
    message         = sbufReserveSpace(message, message_len);
    sbufSetLength(message, message_len);

    uint8_t *ptr = sbufGetMutablePtr(message);
    authenticationclientWriteNetworkUI32(ptr, message_len - kAuthenticationClientMessageHeaderSize);
    memoryCopy(ptr + kAuthenticationClientMessageHeaderSize, token, kAuthenticationClientSessionTokenSize);

    uint8_t *frame = ptr + kAuthenticationClientRequestEnvelopeHeaderSize;
    frame[0]       = request_type;
    authenticationclientCorrelationIdWrite(frame + 1, correlation_id);
    authenticationclientWriteNetworkUI32(frame + 1 + kAuthenticationClientCorrelationIdSize, request_data_len);
    if (request_data_len > 0)
    {
        memoryCopy(frame + kAuthenticationClientRequestHeaderSize, request_data, request_data_len);
    }

    return message;
}

bool authenticationclientSendRequest(tunnel_t *t, uint8_t request_type, const uint8_t *request_data,
                                     uint32_t request_data_len)
{
    authenticationclient_tstate_t *ts                                           = tunnelGetState(t);
    uint8_t                        token[kAuthenticationClientSessionTokenSize] = {0};
    uint32_t                       correlation_id                               = 0;
    uint64_t                       now_ms                                       = wloopNowMonotonicMS(getWorkerLoop(0));

    mutexLock(&ts->control_mutex);
    if (UNLIKELY(! authenticationclientRequestMayBeSentLocked(ts, request_type)))
    {
        if (ts->verbose)
        {
            LOGD("AuthenticationClient: not sending %s request; started=%s stopping=%s connected=%s "
                 "authenticated=%s write-paused=%s control-line=%s",
                 authenticationclientRequestTypeName(request_type),
                 boolToTrueFalse(ts->started),
                 boolToTrueFalse(ts->stopping),
                 boolToTrueFalse(ts->connected),
                 boolToTrueFalse(ts->authenticated),
                 boolToTrueFalse(ts->write_paused),
                 ts->control_line != NULL ? "present" : "none");
        }
        mutexUnlock(&ts->control_mutex);
        return false;
    }

    correlation_id = ts->next_correlation_id++;
    if (UNLIKELY(ts->next_correlation_id == 0))
    {
        ts->next_correlation_id = 1U;
    }

    if (UNLIKELY(! authenticationclientPendingAppend(ts, correlation_id, request_type, now_ms)))
    {
        mutexUnlock(&ts->control_mutex);
        LOGW("AuthenticationClient: pending request table is full");
        return false;
    }
    authenticationclientMarkRequestInFlightLocked(ts, request_type, true);

    if (request_type != kAuthenticationClientRequestTypeAuthenticate)
    {
        memoryCopy(token, ts->token, sizeof(token));
    }

    line_t *line = ts->control_line;
    assert(line != NULL && lineIsAlive(line));
    lineRef(line);
    mutexUnlock(&ts->control_mutex);

    authenticationclientUpdateRequestTimer(t);

    sbuf_t *message = authenticationclientCreateRequestMessage(
        line, request_type, correlation_id, request_data, request_data_len, token);
    if (UNLIKELY(message == NULL))
    {
        authenticationclientRemovePendingById(t, correlation_id);

        lineUnref(line);
        return false;
    }

    if (ts->verbose)
    {
        LOGD("AuthenticationClient: sending %s request correlation-id=%u payload=%u",
             authenticationclientRequestTypeName(request_type),
             (unsigned int) correlation_id,
             (unsigned int) request_data_len);
    }

    tunnelNextUpStreamPayload(t, line, message);
    bool alive = lineIsAlive(line);
    if (UNLIKELY(! alive) && ts->verbose)
    {
        LOGD("AuthenticationClient: control line closed while sending %s request correlation-id=%u",
             authenticationclientRequestTypeName(request_type),
             (unsigned int) correlation_id);
    }
    lineUnref(line);
    return alive;
}

static bool authenticationclientSendJsonRequest(tunnel_t *t, uint8_t request_type, cJSON *json)
{
    char      *text      = cJSON_PrintUnformatted(json);
    const bool sensitive = request_type == kAuthenticationClientRequestTypeAuthenticate;
    if (sensitive)
    {
        cJSON *secret = cJSON_GetObjectItemCaseSensitive(json, "secret");
        if (cJSON_IsString(secret) && secret->valuestring != NULL)
            memorySecureZero(secret->valuestring, strlen(secret->valuestring) + 1);
    }
    cJSON_Delete(json);
    if (UNLIKELY(text == NULL))
    {
        return false;
    }

    const size_t length = stringLength(text);
    bool         ok     = authenticationclientSendRequest(t, request_type, (const uint8_t *) text, (uint32_t) length);
    if (sensitive)
        memorySecureZero(text, length + 1);
    cJSON_free(text);
    return ok;
}

bool authenticationclientSendAuthenticate(tunnel_t *t)
{
    authenticationclient_tstate_t *ts = tunnelGetState(t);

    cJSON  *json = cJSON_CreateObject();
    discard cJSON_AddStringToObject(json, "name", ts->name);
    discard cJSON_AddStringToObject(json, "secret", ts->secret);
    if (ts->accounting_epoch[0] != '\0')
        discard cJSON_AddStringToObject(json, "epoch", ts->accounting_epoch);

    return authenticationclientSendJsonRequest(t, kAuthenticationClientRequestTypeAuthenticate, json);
}

bool authenticationclientSendPing(tunnel_t *t)
{
    static const char ping_request[] = "ping";

    return authenticationclientSendRequest(t,
                                           kAuthenticationClientRequestTypePing,
                                           (const uint8_t *) ping_request,
                                           (uint32_t) (sizeof(ping_request) - 1U));
}

static bool authenticationclientReadMessageHeader(authenticationclient_lstate_t *ls, uint32_t *message_body_len)
{
    uint8_t header[kAuthenticationClientMessageHeaderSize];

    if (bufferstreamGetBufLen(&ls->read_stream) < kAuthenticationClientMessageHeaderSize)
    {
        return false;
    }

    bufferstreamViewBytesAt(&ls->read_stream, 0, header, sizeof(header));
    *message_body_len = authenticationclientReadNetworkUI32(header);
    return true;
}

static bool authenticationclientValidateResponsePayload(sbuf_t *payload)
{
    const uint8_t *ptr       = sbufGetRawPtr(payload);
    uint32_t       remaining = sbufGetLength(payload);
    uint32_t       offset    = 0;

    while (remaining > 0)
    {
        if (UNLIKELY(remaining < kAuthenticationClientResponseHeaderSize))
        {
            LOGW("AuthenticationClient: response frame has trailing bytes smaller than a frame header");
            return false;
        }

        const uint8_t *frame = ptr + offset;
        const uint32_t response_data_len =
            authenticationclientReadNetworkUI32(frame + 1 + kAuthenticationClientCorrelationIdSize);
        if (UNLIKELY(response_data_len > kAuthenticationClientMaxResponsePayload))
        {
            LOGW("AuthenticationClient: response frame is oversized");
            return false;
        }
        if (UNLIKELY(response_data_len > remaining - kAuthenticationClientResponseHeaderSize))
        {
            LOGW("AuthenticationClient: response frame is incomplete");
            return false;
        }

        const uint32_t consumed = kAuthenticationClientResponseHeaderSize + response_data_len;
        offset += consumed;
        remaining -= consumed;
    }

    return true;
}

bool authenticationclientProcessResponses(tunnel_t *t, line_t *l, authenticationclient_lstate_t *ls)
{
    authenticationclient_tstate_t *ts = tunnelGetState(t);
    if (ls->processing_responses)
        return true;
    ls->processing_responses = true;

    while (true)
    {
        uint32_t message_body_len = 0;
        if (! authenticationclientReadMessageHeader(ls, &message_body_len))
        {
            ls->processing_responses = false;
            return true;
        }

        if (UNLIKELY(message_body_len < kAuthenticationClientRevisionHeaderSize))
        {
            authenticationclientRecordFailure(t, kAuthenticationClientFailureInvalidResponse, 0);
            authenticationclientRecoverControlLine(t, l, true);
            return false;
        }
        if (UNLIKELY(message_body_len >
                     kAuthenticationClientMaxResponsePayload + kAuthenticationClientRevisionHeaderSize))
        {
            authenticationclientRecordFailure(t, kAuthenticationClientFailureInvalidResponse, 0);
            authenticationclientRecoverControlLine(t, l, true);
            return false;
        }

        const size_t message_len = (size_t) kAuthenticationClientMessageHeaderSize + (size_t) message_body_len;
        if (bufferstreamGetBufLen(&ls->read_stream) < message_len)
        {
            ls->processing_responses = false;
            return true;
        }

        /* Include framing/JSON construction and subsequent lock waits in the
         * receipt-to-install elapsed time, including a maximum-sized pull. */
        const uint64_t received_at_ms = authenticationclientLocalTimeMS();
        sbuf_t        *payload        = authenticationStreamReadExact(&ls->read_stream, (uint32_t) message_len);
        sbufShiftRight(payload, kAuthenticationClientMessageHeaderSize);

        const uint8_t *revision_ptr    = sbufGetRawPtr(payload);
        const uint64_t config_revision = authenticationclientReadNetworkUI64(revision_ptr);
        const uint64_t stats_revision  = authenticationclientReadNetworkUI64(revision_ptr + sizeof(uint64_t));
        sbufShiftRight(payload, kAuthenticationClientRevisionHeaderSize);

        if (UNLIKELY(! authenticationclientValidateResponsePayload(payload)))
        {
            lineReuseBuffer(l, payload);
            authenticationclientRecordFailure(t, kAuthenticationClientFailureInvalidResponse, 0);
            authenticationclientRecoverControlLine(t, l, true);
            return false;
        }

        if (ts->verbose)
        {
            LOGD("AuthenticationClient: processing response message body=%u frame-payload=%u config-revision=%" PRIu64
                 " stats-revision=%" PRIu64,
                 (unsigned int) message_body_len,
                 (unsigned int) sbufGetLength(payload),
                 config_revision,
                 stats_revision);
        }

        const uint8_t *ptr       = sbufGetRawPtr(payload);
        uint32_t       remaining = sbufGetLength(payload);
        uint32_t       offset    = 0;
        while (remaining > 0)
        {
            const uint8_t *frame          = ptr + offset;
            const uint8_t  response_type  = frame[0];
            const uint32_t correlation_id = authenticationclientCorrelationIdRead(frame + 1);
            const uint32_t response_data_len =
                authenticationclientReadNetworkUI32(frame + 1 + kAuthenticationClientCorrelationIdSize);
            const uint8_t *response_data = frame + kAuthenticationClientResponseHeaderSize;

            authenticationclientHandleResponseFrame(t,
                                                    l,
                                                    response_type,
                                                    correlation_id,
                                                    response_data,
                                                    response_data_len,
                                                    config_revision,
                                                    stats_revision,
                                                    received_at_ms);

            const uint32_t consumed = kAuthenticationClientResponseHeaderSize + response_data_len;
            offset += consumed;
            remaining -= consumed;

            if (UNLIKELY(! lineIsAlive(l)))
            {
                lineReuseBuffer(l, payload);
                return false;
            }
        }

        lineReuseBuffer(l, payload);
    }
}

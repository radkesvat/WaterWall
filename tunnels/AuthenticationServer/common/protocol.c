#include "structure.h"

#include "loggers/network_logger.h"

static void authenticationserverWriteNetworkUI32(uint8_t *dest, uint32_t value)
{
    uint32_t network_value = htonl(value);
    sbufByteCopy(dest, &network_value, (uint32_t) sizeof(network_value));
}

static uint32_t authenticationserverReadNetworkUI32(const uint8_t *src)
{
    uint32_t network_value = 0;
    sbufByteCopy(&network_value, src, (uint32_t) sizeof(network_value));
    return ntohl(network_value);
}

static uint32_t authenticationserverCorrelationIdRead(const uint8_t src[kAuthenticationServerCorrelationIdSize])
{
    return authenticationserverReadNetworkUI32(src);
}

static const char *authenticationserverRequestTypeName(uint8_t request_type)
{
    switch (request_type)
    {
    case kAuthenticationServerRequestTypePing:
        return "Ping";
    case kAuthenticationServerRequestTypeGetUserBySHA256Hex:
        return "GetUserBySHA256Hex";
    case kAuthenticationServerRequestTypeGetUserBySHA256Base64:
        return "GetUserBySHA256Base64";
    case kAuthenticationServerRequestTypeGetUserBySHA256:
        return "GetUserBySHA256";
    case kAuthenticationServerRequestTypeGetUserBySHA224Hex:
        return "GetUserBySHA224Hex";
    case kAuthenticationServerRequestTypeGetUserBySHA224Base64:
        return "GetUserBySHA224Base64";
    case kAuthenticationServerRequestTypeGetUserBySHA224:
        return "GetUserBySHA224";
    case kAuthenticationServerRequestTypeGetUserByPassword:
        return "GetUserByPassword";
    case kAuthenticationServerRequestTypeAddNewUser:
        return "AddNewUser";
    case kAuthenticationServerRequestTypeUpdateUser:
        return "UpdateUser";
    case kAuthenticationServerRequestTypeUpdateUserTraficStatsDiff:
        return "UpdateUserTraficStatsDiff";
    case kAuthenticationServerRequestTypeGetAllUsers:
        return "GetAllUsers";
    case kAuthenticationServerRequestTypeAuthenticate:
        return "Authenticate";
    case kAuthenticationServerRequestTypePushUserStats:
        return "PushUserStats";
    default:
        return "Unknown";
    }
}

static void authenticationserverWriteNetworkUI64(uint8_t *dest, uint64_t value)
{
    dest[0] = (uint8_t) (value >> 56U);
    dest[1] = (uint8_t) (value >> 48U);
    dest[2] = (uint8_t) (value >> 40U);
    dest[3] = (uint8_t) (value >> 32U);
    dest[4] = (uint8_t) (value >> 24U);
    dest[5] = (uint8_t) (value >> 16U);
    dest[6] = (uint8_t) (value >> 8U);
    dest[7] = (uint8_t) value;
}

sbuf_t *authenticationserverCreateResponseFrame(line_t *l, uint8_t response_type,
                                                const uint8_t  correlation_id[kAuthenticationServerCorrelationIdSize],
                                                const uint8_t *response_data, uint32_t response_data_len)
{
    if (UNLIKELY(response_data_len > kAuthenticationServerMaxResponsePayload - kAuthenticationServerResponseHeaderSize))
    {
        LOGW("AuthenticationServer: refused %u-byte response frame because it exceeds the response payload limit",
             (unsigned int) response_data_len);
        return NULL;
    }

    const uint32_t frame_len = kAuthenticationServerResponseHeaderSize + response_data_len;
    sbuf_t        *frame     = bufferpoolGetLargeBuffer(lineGetBufferPool(l));

    frame = sbufReserveSpace(frame, frame_len);
    sbufSetLength(frame, frame_len);

    uint8_t *ptr = sbufGetMutablePtr(frame);
    ptr[0]       = response_type;
    memoryCopy(ptr + 1, correlation_id, kAuthenticationServerCorrelationIdSize);
    authenticationserverWriteNetworkUI32(ptr + 1 + kAuthenticationServerCorrelationIdSize, response_data_len);

    if (response_data_len > 0)
    {
        memoryCopy(ptr + kAuthenticationServerResponseHeaderSize, response_data, response_data_len);
    }

    return frame;
}

sbuf_t *authenticationserverCreateErrorResponseFrame(
    line_t *l, const uint8_t correlation_id[kAuthenticationServerCorrelationIdSize], const char *error)
{
    return authenticationserverCreateResponseFrame(l,
                                                   kAuthenticationServerResponseTypeError,
                                                   correlation_id,
                                                   (const uint8_t *) error,
                                                   (uint32_t) stringLength(error));
}

static bool authenticationserverResponseDataTooLarge(size_t response_data_len)
{
    return response_data_len > kAuthenticationServerMaxResponsePayload - kAuthenticationServerResponseHeaderSize;
}

sbuf_t *authenticationserverCreateUserJsonResponseFrame(
    line_t *l, const uint8_t correlation_id[kAuthenticationServerCorrelationIdSize], cJSON *user_json,
    const char *module_name)
{
    if (UNLIKELY(user_json == NULL))
    {
        return authenticationserverCreateErrorResponseFrame(l, correlation_id, "user-not-found");
    }

    char *user_json_text = cJSON_PrintUnformatted(user_json);
    cJSON_Delete(user_json);

    if (UNLIKELY(user_json_text == NULL))
    {
        LOGW("AuthenticationServer: %s failed to serialize matching user", module_name);
        return authenticationserverCreateErrorResponseFrame(l, correlation_id, "user-json-serialize-failed");
    }

    const size_t user_json_text_len = stringLength(user_json_text);
    if (UNLIKELY(authenticationserverResponseDataTooLarge(user_json_text_len)))
    {
        LOGW("AuthenticationServer: %s response is too large", module_name);
        cJSON_free(user_json_text);
        return authenticationserverCreateErrorResponseFrame(l, correlation_id, "response-too-large");
    }

    sbuf_t *response = authenticationserverCreateResponseFrame(l,
                                                               kAuthenticationServerResponseTypeUser,
                                                               correlation_id,
                                                               (const uint8_t *) user_json_text,
                                                               (uint32_t) user_json_text_len);
    cJSON_free(user_json_text);
    return response;
}

bool authenticationserverUserJsonWireGuardAllowedIpsValid(const cJSON *user_json)
{
    const cJSON *item = cJSON_GetObjectItemCaseSensitive(user_json, "wireguard-allowed-ips");

    if (item == NULL || cJSON_IsNull(item))
    {
        return true;
    }
    if (UNLIKELY(! cJSON_IsString(item) || item->valuestring == NULL))
    {
        return false;
    }
    return userWireGuardAllowedIpsStringValid(item->valuestring);
}

void authenticationserverCloseLine(tunnel_t *t, line_t *l, authenticationserver_lstate_t *ls, const char *reason)
{
    // Internal close paths pass literal reasons; keep that contract for new callers.
    LOGW("AuthenticationServer: closing logical connection: %s", reason);

    authenticationserverLinestateDestroy(ls);
    tunnelPrevDownStreamFinish(t, l);
}

bool authenticationserverFlushResponses(tunnel_t *t, line_t *l, authenticationserver_lstate_t *ls)
{
    authenticationserver_tstate_t *ts = tunnelGetState(t);

    if (ts->verbose && bufferqueueGetBufCount(&ls->response_queue) > 0)
    {
        LOGD("AuthenticationServer: flushing %u queued response message(s)",
             (unsigned int) bufferqueueGetBufCount(&ls->response_queue));
    }

    while (! ls->response_paused && bufferqueueGetBufCount(&ls->response_queue) > 0)
    {
        sbuf_t *response = bufferqueuePopFront(&ls->response_queue);
        if (ts->verbose)
        {
            LOGD("AuthenticationServer: sending queued response message bytes=%u",
                 (unsigned int) sbufGetLength(response));
        }
        if (UNLIKELY(! withLineLockedWithBuf(l, tunnelPrevDownStreamPayload, t, response)))
        {
            return false;
        }
    }

    return true;
}

static bool authenticationserverSendOrQueueResponse(tunnel_t *t, line_t *l, authenticationserver_lstate_t *ls,
                                                    sbuf_t *response)
{
    authenticationserver_tstate_t *ts = tunnelGetState(t);

    if (UNLIKELY(ls->response_paused || bufferqueueGetBufCount(&ls->response_queue) > 0))
    {
        if (ts->verbose)
        {
            LOGD("AuthenticationServer: queueing response message bytes=%u paused=%s queued=%u",
                 (unsigned int) sbufGetLength(response),
                 ls->response_paused ? "true" : "false",
                 (unsigned int) bufferqueueGetBufCount(&ls->response_queue));
        }
        bufferqueuePushBack(&ls->response_queue, response);
        if (UNLIKELY(bufferqueueGetBufLen(&ls->response_queue) > kAuthenticationServerMaxResponseQueue))
        {
            authenticationserverCloseLine(t, l, ls, "response queue overflow");
            return false;
        }
        return true;
    }

    if (ts->verbose)
    {
        LOGD("AuthenticationServer: sending response message bytes=%u", (unsigned int) sbufGetLength(response));
    }

    return withLineLockedWithBuf(l, tunnelPrevDownStreamPayload, t, response);
}

static bool authenticationserverReadMessageHeader(authenticationserver_lstate_t *ls, uint32_t *message_body_len)
{
    uint8_t header[kAuthenticationServerMessageHeaderSize];

    if (bufferstreamGetBufLen(&ls->read_stream) < kAuthenticationServerMessageHeaderSize)
    {
        return false;
    }

    bufferstreamViewBytesAt(&ls->read_stream, 0, header, sizeof(header));
    *message_body_len = authenticationserverReadNetworkUI32(header);
    return true;
}

static sbuf_t *authenticationserverCreateResponseMessage(line_t *l)
{
    sbuf_t *message = bufferpoolGetLargeBuffer(lineGetBufferPool(l));

    message = sbufReserveSpace(message, kAuthenticationServerResponseEnvelopeHeaderSize);
    sbufSetLength(message, kAuthenticationServerResponseEnvelopeHeaderSize);
    return message;
}

static bool authenticationserverAppendResponseFrame(line_t *l, sbuf_t **message, sbuf_t *frame)
{
    const uint32_t message_len = sbufGetLength(*message);
    const uint32_t frame_len   = sbufGetLength(frame);
    const uint32_t payload_len = message_len - kAuthenticationServerResponseEnvelopeHeaderSize;

    if (UNLIKELY(frame_len > kAuthenticationServerMaxResponsePayload ||
                 payload_len > kAuthenticationServerMaxResponsePayload - frame_len))
    {
        LOGW("AuthenticationServer: response payload would exceed %u bytes",
             (unsigned int) kAuthenticationServerMaxResponsePayload);
        lineReuseBuffer(l, frame);
        return false;
    }

    *message = sbufReserveSpace(*message, message_len + frame_len);
    sbufSetLength(*message, message_len + frame_len);
    memoryCopyLarge(sbufGetMutablePtr(*message) + message_len, sbufGetRawPtr(frame), frame_len);
    lineReuseBuffer(l, frame);
    return true;
}

static void authenticationserverFinalizeResponseMessage(sbuf_t *message, uint64_t config_revision,
                                                        uint64_t stats_revision)
{
    const uint32_t message_len = sbufGetLength(message);
    uint8_t       *ptr         = sbufGetMutablePtr(message);

    assert(message_len >= kAuthenticationServerResponseEnvelopeHeaderSize);

    authenticationserverWriteNetworkUI32(ptr, message_len - kAuthenticationServerMessageHeaderSize);
    authenticationserverWriteNetworkUI64(ptr + kAuthenticationServerMessageHeaderSize, config_revision);
    authenticationserverWriteNetworkUI64(ptr + kAuthenticationServerMessageHeaderSize + sizeof(uint64_t),
                                         stats_revision);
}

static bool authenticationserverValidateRequestPayload(sbuf_t *payload)
{
    const uint8_t *ptr       = sbufGetRawPtr(payload);
    uint32_t       remaining = sbufGetLength(payload);
    uint32_t       offset    = 0;

    if (UNLIKELY(remaining == 0))
    {
        LOGW("AuthenticationServer: received empty message payload; expected at least one request frame");
        return false;
    }

    while (remaining > 0)
    {
        if (UNLIKELY(remaining < kAuthenticationServerRequestHeaderSize))
        {
            LOGW("AuthenticationServer: malformed message at offset %u: %u trailing bytes are smaller than a request "
                 "header",
                 (unsigned int) offset,
                 (unsigned int) remaining);
            return false;
        }

        const uint8_t *frame            = ptr + offset;
        const uint8_t  request_type     = frame[0];
        const uint8_t *length_ptr       = frame + 1 + kAuthenticationServerCorrelationIdSize;
        const uint32_t request_data_len = authenticationserverReadNetworkUI32(length_ptr);

        if (UNLIKELY(request_data_len > kAuthenticationServerMaxRequestData))
        {
            LOGW("AuthenticationServer: request type %u at offset %u has oversized %u-byte data",
                 (unsigned int) request_type,
                 (unsigned int) offset,
                 (unsigned int) request_data_len);
            return false;
        }

        if (UNLIKELY(request_data_len > remaining - kAuthenticationServerRequestHeaderSize))
        {
            LOGW("AuthenticationServer: incomplete request type %u at offset %u: declares %u data bytes, only %u "
                 "available",
                 (unsigned int) request_type,
                 (unsigned int) offset,
                 (unsigned int) request_data_len,
                 (unsigned int) (remaining - kAuthenticationServerRequestHeaderSize));
            return false;
        }

        const uint32_t consumed = kAuthenticationServerRequestHeaderSize + request_data_len;
        offset += consumed;
        remaining -= consumed;
    }

    return true;
}

static bool authenticationserverRequestMutatesStore(uint8_t request_type)
{
    switch (request_type)
    {
    case kAuthenticationServerRequestTypeAddNewUser:
    case kAuthenticationServerRequestTypeUpdateUser:
    case kAuthenticationServerRequestTypeUpdateUserTraficStatsDiff:
    case kAuthenticationServerRequestTypePushUserStats:
        return true;
    default:
        return false;
    }
}

static bool authenticationserverRequestCanUseSharedStateLock(uint8_t request_type)
{
    switch (request_type)
    {
    case kAuthenticationServerRequestTypePing:
    case kAuthenticationServerRequestTypeGetUserBySHA256Hex:
    case kAuthenticationServerRequestTypeGetUserBySHA256Base64:
    case kAuthenticationServerRequestTypeGetUserBySHA256:
    case kAuthenticationServerRequestTypeGetUserBySHA224Hex:
    case kAuthenticationServerRequestTypeGetUserBySHA224Base64:
    case kAuthenticationServerRequestTypeGetUserBySHA224:
    case kAuthenticationServerRequestTypeGetUserByPassword:
        return true;
    default:
        return false;
    }
}

static bool authenticationserverMessageRequiresWriteLock(sbuf_t *payload)
{
    const uint8_t *ptr       = sbufGetRawPtr(payload);
    uint32_t       remaining = sbufGetLength(payload);
    uint32_t       offset    = 0;

    while (remaining > 0)
    {
        const uint8_t *frame            = ptr + offset;
        const uint8_t  request_type     = frame[0];
        const uint8_t *length_ptr       = frame + 1 + kAuthenticationServerCorrelationIdSize;
        const uint32_t request_data_len = authenticationserverReadNetworkUI32(length_ptr);
        const uint32_t consumed         = kAuthenticationServerRequestHeaderSize + request_data_len;

        if (! authenticationserverRequestCanUseSharedStateLock(request_type))
        {
            return true;
        }

        offset += consumed;
        remaining -= consumed;
    }

    return false;
}

static bool authenticationserverBuildResponseMessageLocked(tunnel_t *t, line_t *l,
                                                           const uint8_t token[kAuthenticationServerSessionTokenSize],
                                                           sbuf_t *payload, sbuf_t **response_out)
{
    authenticationserver_tstate_t  *ts                = tunnelGetState(t);
    authenticationserver_session_t *session           = authenticationserverSessionFindByTokenLocked(t, token);
    const uint8_t                  *ptr               = sbufGetRawPtr(payload);
    uint32_t                        count             = 0;
    sbuf_t                         *response          = authenticationserverCreateResponseMessage(l);
    bool                            authenticate_seen = false;

    authenticationserverSessionTouch(session, getTickMS());

    if (ts->verbose)
    {
        LOGD("AuthenticationServer: building response for request message payload=%u session=%s",
             (unsigned int) sbufGetLength(payload),
             session != NULL && session->client_name != NULL ? session->client_name : "none");
    }

    for (uint32_t pass = 0; pass < 2U; ++pass)
    {
        const bool write_pass = pass == 0U;
        uint32_t   remaining  = sbufGetLength(payload);
        uint32_t   offset     = 0;

        while (remaining > 0)
        {
            const uint8_t *frame            = ptr + offset;
            const uint8_t  request_type     = frame[0];
            const uint8_t *correlation_id   = frame + 1;
            const uint8_t *length_ptr       = frame + 1 + kAuthenticationServerCorrelationIdSize;
            const uint32_t request_data_len = authenticationserverReadNetworkUI32(length_ptr);
            const uint8_t *request_data     = frame + kAuthenticationServerRequestHeaderSize;
            const uint32_t consumed         = kAuthenticationServerRequestHeaderSize + request_data_len;
            sbuf_t        *response_frame   = NULL;

            if (authenticationserverRequestMutatesStore(request_type) != write_pass)
            {
                offset += consumed;
                remaining -= consumed;
                continue;
            }

            if (ts->verbose)
            {
                LOGD("AuthenticationServer: handling %s request correlation-id=%u payload=%u pass=%s",
                     authenticationserverRequestTypeName(request_type),
                     (unsigned int) authenticationserverCorrelationIdRead(correlation_id),
                     (unsigned int) request_data_len,
                     write_pass ? "write" : "read");
            }

            if (UNLIKELY(request_type == kAuthenticationServerRequestTypeAuthenticate &&
                         (session != NULL || authenticate_seen)))
            {
                LOGW("AuthenticationServer: rejected duplicate or already authenticated Authenticate request");
                response_frame =
                    authenticationserverCreateErrorResponseFrame(l, correlation_id, "already-authenticated");
            }
            else
            {
                response_frame = authenticationserverDispatchRequest(
                    request_type, correlation_id, t, l, session, request_data, request_data_len);
            }
            if (request_type == kAuthenticationServerRequestTypeAuthenticate)
            {
                authenticate_seen = true;
            }

            if (UNLIKELY(response_frame == NULL))
            {
                LOGW("AuthenticationServer: module for request type %u did not return a response frame",
                     (unsigned int) request_type);
                lineReuseBuffer(l, response);
                return false;
            }

            if (UNLIKELY(! authenticationserverAppendResponseFrame(l, &response, response_frame)))
            {
                lineReuseBuffer(l, response);
                return false;
            }

            offset += consumed;
            remaining -= consumed;
            ++count;
        }
    }

    authenticationserverFinalizeResponseMessage(response, ts->store.config_revision, ts->store.stats_revision);
    *response_out = response;

    if (ts->verbose)
    {
        LOGD("AuthenticationServer: processed %u request frame(s); response bytes=%u config-revision=%" PRIu64
             " stats-revision=%" PRIu64,
             (unsigned int) count,
             (unsigned int) sbufGetLength(response),
             ts->store.config_revision,
             ts->store.stats_revision);
    }
    return true;
}

static bool authenticationserverBuildResponseMessage(tunnel_t *t, line_t *l,
                                                     const uint8_t token[kAuthenticationServerSessionTokenSize],
                                                     sbuf_t *payload, sbuf_t **response_out)
{
    authenticationserver_tstate_t *ts     = tunnelGetState(t);
    bool                           result = false;

    if (LIKELY(authenticationserverValidateRequestPayload(payload)))
    {
        const bool write_lock = authenticationserverMessageRequiresWriteLock(payload);
        if (write_lock)
        {
            rwlockWriteLock(&ts->state_lock);
        }
        else
        {
            rwlockReadLock(&ts->state_lock);
        }
        result = authenticationserverBuildResponseMessageLocked(t, l, token, payload, response_out);
        if (write_lock)
        {
            rwlockWriteUnlock(&ts->state_lock);
        }
        else
        {
            rwlockReadUnlock(&ts->state_lock);
        }
    }
    return result;
}

bool authenticationserverProcessRequests(tunnel_t *t, line_t *l, authenticationserver_lstate_t *ls)
{
    authenticationserver_tstate_t *ts = tunnelGetState(t);

    while (true)
    {
        uint32_t message_body_len = 0;
        if (! authenticationserverReadMessageHeader(ls, &message_body_len))
        {
            return true;
        }

        if (UNLIKELY(message_body_len < kAuthenticationServerSessionTokenSize))
        {
            authenticationserverCloseLine(t, l, ls, "message body is smaller than session token");
            return false;
        }

        if (UNLIKELY(message_body_len > kAuthenticationServerMaxMessagePayload + kAuthenticationServerSessionTokenSize))
        {
            authenticationserverCloseLine(t, l, ls, "message payload size exceeds limit");
            return false;
        }

        const size_t message_len = (size_t) kAuthenticationServerMessageHeaderSize + (size_t) message_body_len;
        if (bufferstreamGetBufLen(&ls->read_stream) < message_len)
        {
            return true;
        }

        sbuf_t *payload = bufferstreamReadExact(&ls->read_stream, message_len);
        sbufShiftRight(payload, kAuthenticationServerMessageHeaderSize);

        uint8_t token[kAuthenticationServerSessionTokenSize];
        memoryCopy(token, sbufGetRawPtr(payload), sizeof(token));
        sbufShiftRight(payload, kAuthenticationServerSessionTokenSize);

        if (ts->verbose)
        {
            LOGD("AuthenticationServer: processing request message body=%u frame-payload=%u",
                 (unsigned int) message_body_len,
                 (unsigned int) sbufGetLength(payload));
        }

        sbuf_t *response = NULL;
        if (UNLIKELY(! authenticationserverBuildResponseMessage(t, l, token, payload, &response)))
        {
            lineReuseBuffer(l, payload);
            authenticationserverCloseLine(t, l, ls, "malformed request message");
            return false;
        }

        lineReuseBuffer(l, payload);

        if (UNLIKELY(! authenticationserverSendOrQueueResponse(t, l, ls, response)))
        {
            return false;
        }
    }
}

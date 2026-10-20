#include "../../Internals/AuthenticationCommon/credentials.h"
#include "../../Internals/AuthenticationCommon/stream.h"
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
    buffer_pool_t *pool      = lineGetBufferPool(l);
    sbuf_t        *frame     = bufferpoolGetBestFit(pool, frame_len, bufferpoolGetSmallBufferPadding(pool));
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

char *authenticationserverSerializeResponseJson(const cJSON *json)
{
    /* cJSON's preallocated printer needs up to five spare bytes. No failed
     * attempt is retained while allocating the next, capped attempt. */
    const size_t maximum  = kAuthenticationServerMaxResponsePayload - kAuthenticationServerResponseHeaderSize + 6U;
    size_t       capacity = 4096;
    for (;;)
    {
        char *text = cJSON_malloc(capacity);
        if (cJSON_PrintPreallocated((cJSON *) json, text, (int) capacity, false) &&
            ! authenticationserverResponseDataTooLarge(stringLength(text)))
            return text;
        cJSON_free(text);
        if (capacity == maximum)
            return NULL;
        capacity = min(capacity * 2U, maximum);
    }
}

sbuf_t *authenticationserverCreateUserJsonResponseFrame(
    line_t *l, const uint8_t correlation_id[kAuthenticationServerCorrelationIdSize], cJSON *user_json,
    const char *module_name)
{
    if (UNLIKELY(user_json == NULL))
    {
        return authenticationserverCreateErrorResponseFrame(l, correlation_id, "user-not-found");
    }

    char *user_json_text = authenticationserverSerializeResponseJson(user_json);
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
    authenticationserver_tstate_t *ts = tunnelGetState(t);
    if (ts->verbose)
        LOGD("AuthenticationServer: closing logical connection: %s", reason);

    authenticationserverLinestateDestroy(ls);
    tunnelPrevDownStreamFinish(t, l);
}

bool authenticationserverFlushResponses(tunnel_t *t, line_t *l, authenticationserver_lstate_t *ls)
{
    if (ls->response_draining)
    {
        return true;
    }
    ls->response_draining = true;
    while (! ls->response_paused)
    {
        if (ls->active_response == NULL)
        {
            ls->active_response = bufferqueuePopFrontReserved(&ls->response_queue, &ls->active_response_cost);
            if (ls->active_response == NULL)
            {
                break;
            }
        }
        sbuf_t        *backing   = ls->active_response;
        const uint32_t remaining = sbufGetLength(backing);
        const uint32_t length    = min(remaining, (uint32_t) kAuthenticationServerOutputChunkSize);
        sbuf_t        *chunk;
        if (length == remaining)
        {
            chunk               = backing;
            ls->active_response = NULL;
            bufferbudgetReservationRelease(&ls->active_response_cost);
        }
        else
        {
            chunk = bufferpoolGetBestFit(ls->pool, length, bufferpoolGetSmallBufferPadding(ls->pool));
            sbufSetLength(chunk, length);
            memoryCopy(sbufGetMutablePtr(chunk), sbufGetRawPtr(backing), length);
            sbufShiftRight(backing, length);
            bufferbudgetReservationSetBytes(&ls->active_response_cost, remaining - length);
        }
        /* A final tail of a large backing allocation must also be compacted;
         * transports budget allocation charge, not just its remaining length. */
        buffer_pool_fit_t fit;
        const bool fits = bufferpoolQueryBestFit(ls->pool, length, bufferpoolGetSmallBufferPadding(ls->pool), &fit);
        assert(fits);
        discard fits;
        if (sbufGetAllocationCharge(chunk) > fit.allocation_charge)
        {
            sbuf_t *compact = bufferpoolGetBestFit(ls->pool, length, bufferpoolGetSmallBufferPadding(ls->pool));
            sbufSetLength(compact, length);
            memoryCopy(sbufGetMutablePtr(compact), sbufGetRawPtr(chunk), length);
            bufferpoolReuseBuffer(ls->pool, chunk);
            chunk = compact;
        }
        if (UNLIKELY(! lineCallWithRefWithBuf(l, tunnelPrevDownStreamPayload, t, chunk)))
        {
            return false;
        }
    }
    ls->response_draining = false;
    return true;
}

static bool authenticationserverSendOrQueueResponse(tunnel_t *t, line_t *l, authenticationserver_lstate_t *ls,
                                                    sbuf_t *response)
{
    if (! bufferqueueTryPushBack(&ls->response_queue, &response))
    {
        lineReuseBuffer(l, response);
        authenticationserverCloseLine(t, l, ls, "response storage limit");
        return false;
    }
    return authenticationserverFlushResponses(t, l, ls);
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

bool authenticationserverInputTokenValid(tunnel_t *t, buffer_stream_t *stream, const sbuf_t *input)
{
    const size_t buffered = bufferstreamGetBufLen(stream);
    const size_t incoming = input == NULL ? 0 : sbufGetLength(input);
    if (buffered < kAuthenticationServerRequestEnvelopeHeaderSize &&
        incoming < kAuthenticationServerRequestEnvelopeHeaderSize - buffered)
        return false;
    uint8_t      header[kAuthenticationServerRequestEnvelopeHeaderSize];
    const size_t prefix = min(buffered, sizeof(header));
    if (prefix != 0)
        bufferstreamViewBytesAt(stream, 0, header, prefix);
    if (prefix < sizeof(header))
        memoryCopy(header + prefix, sbufGetRawPtr(input), sizeof(header) - prefix);
    authenticationserver_tstate_t *ts = tunnelGetState(t);
    rwlockReadLock(&ts->state_lock);
    const bool valid =
        authenticationserverSessionFindByTokenLocked(t, header + kAuthenticationServerMessageHeaderSize) != NULL;
    rwlockReadUnlock(&ts->state_lock);
    return valid;
}

/* Nested input cannot drain now. Inspect every retained envelope boundary so
 * one valid token cannot lend its larger allowance to an unknown successor.
 * Incomplete headers and all unvalidated envelopes share the small allowance. */
bool authenticationserverInputAllowance(tunnel_t *t, buffer_stream_t *stream, const sbuf_t *input, bool *ordinary_out)
{
    const size_t buffered = bufferstreamGetBufLen(stream);
    const size_t incoming = input == NULL ? 0 : sbufGetLength(input);
    const size_t maximum  = kAuthenticationServerMaxMessagePayload + kAuthenticationServerRequestEnvelopeHeaderSize +
                           kAuthenticationStreamReentryHeadroom;
    const size_t preauth = kAuthenticationPreAuthPayloadLimit + kAuthenticationServerRequestEnvelopeHeaderSize;
    *ordinary_out        = false;
    if (buffered > maximum || incoming > maximum - buffered)
        return false;
    const size_t                   total       = buffered + incoming;
    size_t                         unvalidated = 0;
    authenticationserver_tstate_t *ts          = tunnelGetState(t);
    for (size_t offset = 0; offset < total;)
    {
        const size_t available = total - offset;
        if (available < kAuthenticationServerRequestEnvelopeHeaderSize)
            return available <= preauth - unvalidated;
        uint8_t      header[kAuthenticationServerRequestEnvelopeHeaderSize];
        const size_t from_stream = offset < buffered ? min(sizeof(header), buffered - offset) : 0;
        if (from_stream != 0)
            bufferstreamViewBytesAt(stream, offset, header, from_stream);
        if (from_stream < sizeof(header))
        {
            const size_t input_offset = offset + from_stream - buffered;
            memoryCopy(header + from_stream,
                       (const uint8_t *) sbufGetRawPtr(input) + input_offset,
                       sizeof(header) - from_stream);
        }
        const uint32_t body = authenticationserverReadNetworkUI32(header);
        if (body < kAuthenticationServerSessionTokenSize ||
            body > kAuthenticationServerSessionTokenSize + kAuthenticationServerMaxMessagePayload)
            return false;
        rwlockReadLock(&ts->state_lock);
        const bool valid =
            authenticationserverSessionFindByTokenLocked(t, header + kAuthenticationServerMessageHeaderSize) != NULL;
        rwlockReadUnlock(&ts->state_lock);
        const size_t retained = min(available, (size_t) body + kAuthenticationServerMessageHeaderSize);
        if (valid)
            *ordinary_out = true;
        else
        {
            if (body > kAuthenticationServerSessionTokenSize + kAuthenticationPreAuthPayloadLimit ||
                retained > preauth - unvalidated)
                return false;
            unvalidated += retained;
        }
        offset += retained;
    }
    return true;
}

static sbuf_t *authenticationserverCreateResponseMessage(line_t *l)
{
    buffer_pool_t *pool    = lineGetBufferPool(l);
    sbuf_t        *message = bufferpoolGetBestFit(
        pool, kAuthenticationServerResponseEnvelopeHeaderSize, bufferpoolGetSmallBufferPadding(pool));

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

    const uint32_t needed = message_len + frame_len;
    if (sbufGetMaximumWriteableSize(*message) < needed)
    {
        const uint32_t maximum =
            kAuthenticationServerMaxResponsePayload + kAuthenticationServerResponseEnvelopeHeaderSize;
        uint32_t capacity = sbufGetMaximumWriteableSize(*message);
        while (capacity < needed)
            capacity = capacity > maximum / 2U ? maximum : capacity * 2U;
        *message = sbufReserveSpace(*message, capacity);
    }
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
    uint32_t       frames    = 0;

    if (UNLIKELY(remaining == 0))
    {
        return false;
    }

    while (remaining > 0)
    {
        if (++frames > kAuthenticationServerMaxFramesPerEnvelope)
            return false;
        if (UNLIKELY(remaining < kAuthenticationServerRequestHeaderSize))
        {
            return false;
        }

        const uint8_t *frame            = ptr + offset;
        const uint8_t *length_ptr       = frame + 1 + kAuthenticationServerCorrelationIdSize;
        const uint32_t request_data_len = authenticationserverReadNetworkUI32(length_ptr);

        if (UNLIKELY(request_data_len > kAuthenticationServerMaxRequestData))
        {
            return false;
        }

        if (UNLIKELY(request_data_len > remaining - kAuthenticationServerRequestHeaderSize))
        {
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

    /* The token may have been replaced while the large envelope was arriving. */
    if (session == NULL && sbufGetLength(payload) > kAuthenticationPreAuthPayloadLimit)
    {
        lineReuseBuffer(l, response);
        return false;
    }

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
                if (response_frame != NULL && sbufReadUI8(response_frame) != kAuthenticationServerResponseTypeSession)
                {
                    authenticationserver_lstate_t *ls = lineGetState(l, t);
                    ls->reject_further_input          = true;
                }
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
    if (ls->processing_requests)
    {
        return true;
    }
    ls->processing_requests = true;

    while (true)
    {
        if (ls->reject_further_input)
        {
            if (bufferstreamGetBufLen(&ls->read_stream) != 0)
            {
                authenticationserverCloseLine(t, l, ls, "input after rejected authentication");
                return false;
            }
            ls->processing_requests = false;
            return true;
        }
        uint32_t message_body_len = 0;
        if (! authenticationserverReadMessageHeader(ls, &message_body_len))
        {
            ls->processing_requests = false;
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
        if (bufferstreamGetBufLen(&ls->read_stream) < kAuthenticationServerRequestEnvelopeHeaderSize)
        {
            ls->processing_requests = false;
            return true;
        }
        if (message_body_len > kAuthenticationServerSessionTokenSize + kAuthenticationPreAuthPayloadLimit &&
            ! authenticationserverInputTokenValid(t, &ls->read_stream, NULL))
        {
            authenticationserverCloseLine(t, l, ls, "unauthenticated message payload size exceeds limit");
            return false;
        }
        if (bufferstreamGetBufLen(&ls->read_stream) < message_len)
        {
            ls->processing_requests = false;
            return true;
        }

        sbuf_t *payload = authenticationStreamReadExact(&ls->read_stream, (uint32_t) message_len);
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

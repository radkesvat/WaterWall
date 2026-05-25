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

sbuf_t *authenticationserverCreateResponseFrame(
    line_t       *l,
    uint8_t       response_type,
    const uint8_t correlation_id[kAuthenticationServerCorrelationIdSize],
    const uint8_t *response_data,
    uint32_t      response_data_len)
{
    if (response_data_len > kAuthenticationServerMaxResponsePayload - kAuthenticationServerResponseHeaderSize)
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
    line_t       *l,
    const uint8_t correlation_id[kAuthenticationServerCorrelationIdSize],
    const char   *error)
{
    return authenticationserverCreateResponseFrame(l,
                                                  kAuthenticationServerResponseTypeError,
                                                  correlation_id,
                                                  (const uint8_t *) error,
                                                  (uint32_t) stringLength(error));
}

sbuf_t *authenticationserverCreateUserJsonResponseFrame(
    line_t       *l,
    const uint8_t correlation_id[kAuthenticationServerCorrelationIdSize],
    cJSON        *user_json,
    const char   *module_name)
{
    if (user_json == NULL)
    {
        return authenticationserverCreateErrorResponseFrame(l, correlation_id, "user-not-found");
    }

    char *user_json_text = cJSON_PrintUnformatted(user_json);
    cJSON_Delete(user_json);

    if (user_json_text == NULL)
    {
        LOGW("AuthenticationServer: %s failed to serialize matching user", module_name);
        return authenticationserverCreateErrorResponseFrame(l, correlation_id, "user-json-serialize-failed");
    }

    sbuf_t *response = authenticationserverCreateResponseFrame(l,
                                                               kAuthenticationServerResponseTypeUser,
                                                               correlation_id,
                                                               (const uint8_t *) user_json_text,
                                                               (uint32_t) stringLength(user_json_text));
    cJSON_free(user_json_text);
    return response;
}

void authenticationserverCloseLine(tunnel_t *t, line_t *l, authenticationserver_lstate_t *ls, const char *reason)
{
    if (reason != NULL)
    {
        LOGW("AuthenticationServer: closing logical connection: %s", reason);
    }

    authenticationserverLinestateDestroy(ls);
    tunnelPrevDownStreamFinish(t, l);
}

bool authenticationserverFlushResponses(tunnel_t *t, line_t *l, authenticationserver_lstate_t *ls)
{
    while (! ls->response_paused && bufferqueueGetBufCount(&ls->response_queue) > 0)
    {
        sbuf_t *response = bufferqueuePopFront(&ls->response_queue);
        if (! withLineLockedWithBuf(l, tunnelPrevDownStreamPayload, t, response))
        {
            return false;
        }
    }

    return true;
}

static bool authenticationserverSendOrQueueResponse(tunnel_t *t, line_t *l, authenticationserver_lstate_t *ls,
                                                   sbuf_t *response)
{
    if (ls->response_paused || bufferqueueGetBufCount(&ls->response_queue) > 0)
    {
        bufferqueuePushBack(&ls->response_queue, response);
        if (bufferqueueGetBufLen(&ls->response_queue) > kAuthenticationServerMaxResponseQueue)
        {
            authenticationserverCloseLine(t, l, ls, "response queue overflow");
            return false;
        }
        return true;
    }

    return withLineLockedWithBuf(l, tunnelPrevDownStreamPayload, t, response);
}

static bool authenticationserverReadMessageHeader(authenticationserver_lstate_t *ls, uint32_t *message_payload_len)
{
    uint8_t header[kAuthenticationServerMessageHeaderSize];

    if (bufferstreamGetBufLen(&ls->read_stream) < kAuthenticationServerMessageHeaderSize)
    {
        return false;
    }

    bufferstreamViewBytesAt(&ls->read_stream, 0, header, sizeof(header));
    *message_payload_len = authenticationserverReadNetworkUI32(header);
    return true;
}

static sbuf_t *authenticationserverCreateResponseMessage(line_t *l)
{
    sbuf_t *message = bufferpoolGetLargeBuffer(lineGetBufferPool(l));

    message = sbufReserveSpace(message, kAuthenticationServerMessageHeaderSize);
    sbufSetLength(message, kAuthenticationServerMessageHeaderSize);
    return message;
}

static bool authenticationserverAppendResponseFrame(line_t *l, sbuf_t **message, sbuf_t *frame)
{
    const uint32_t message_len = sbufGetLength(*message);
    const uint32_t frame_len   = sbufGetLength(frame);
    const uint32_t payload_len = message_len - kAuthenticationServerMessageHeaderSize;

    if (frame_len > kAuthenticationServerMaxResponsePayload ||
        payload_len > kAuthenticationServerMaxResponsePayload - frame_len)
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

static void authenticationserverFinalizeResponseMessage(sbuf_t *message)
{
    const uint32_t message_len = sbufGetLength(message);
    assert(message_len >= kAuthenticationServerMessageHeaderSize);

    authenticationserverWriteNetworkUI32(sbufGetMutablePtr(message),
                                        message_len - kAuthenticationServerMessageHeaderSize);
}

static bool authenticationserverBuildResponseMessage(tunnel_t *t, line_t *l, sbuf_t *payload, sbuf_t **response_out)
{
    const uint8_t *ptr       = sbufGetRawPtr(payload);
    uint32_t       remaining = sbufGetLength(payload);
    uint32_t       offset    = 0;
    uint32_t       count     = 0;
    sbuf_t        *response  = authenticationserverCreateResponseMessage(l);

    if (remaining == 0)
    {
        LOGW("AuthenticationServer: received empty message payload; expected at least one request frame");
        lineReuseBuffer(l, response);
        return false;
    }

    while (remaining > 0)
    {
        if (remaining < kAuthenticationServerRequestHeaderSize)
        {
            LOGW("AuthenticationServer: malformed message at offset %u: %u trailing bytes are smaller than a request header",
                 (unsigned int) offset, (unsigned int) remaining);
            lineReuseBuffer(l, response);
            return false;
        }

        const uint8_t *frame           = ptr + offset;
        const uint8_t  request_type    = frame[0];
        const uint8_t *correlation_id  = frame + 1;
        const uint8_t *length_ptr      = frame + 1 + kAuthenticationServerCorrelationIdSize;
        const uint32_t request_data_len = authenticationserverReadNetworkUI32(length_ptr);

        if (request_data_len > kAuthenticationServerMaxRequestData)
        {
            LOGW("AuthenticationServer: request type %u at offset %u has oversized %u-byte data",
                 (unsigned int) request_type, (unsigned int) offset, (unsigned int) request_data_len);
            lineReuseBuffer(l, response);
            return false;
        }

        if (request_data_len > remaining - kAuthenticationServerRequestHeaderSize)
        {
            LOGW("AuthenticationServer: incomplete request type %u at offset %u: declares %u data bytes, only %u available",
                 (unsigned int) request_type,
                 (unsigned int) offset,
                 (unsigned int) request_data_len,
                 (unsigned int) (remaining - kAuthenticationServerRequestHeaderSize));
            lineReuseBuffer(l, response);
            return false;
        }

        const uint8_t *request_data = frame + kAuthenticationServerRequestHeaderSize;
        sbuf_t        *response_frame =
            authenticationserverDispatchRequest(request_type, correlation_id, t, l, request_data, request_data_len);

        if (response_frame == NULL)
        {
            LOGW("AuthenticationServer: module for request type %u did not return a response frame",
                 (unsigned int) request_type);
            lineReuseBuffer(l, response);
            return false;
        }

        if (! authenticationserverAppendResponseFrame(l, &response, response_frame))
        {
            lineReuseBuffer(l, response);
            return false;
        }

        const uint32_t consumed = kAuthenticationServerRequestHeaderSize + request_data_len;
        offset += consumed;
        remaining -= consumed;
        ++count;
    }

    authenticationserverFinalizeResponseMessage(response);
    *response_out = response;

    LOGD("AuthenticationServer: processed %u request frame(s) from one message", (unsigned int) count);
    return true;
}

bool authenticationserverProcessRequests(tunnel_t *t, line_t *l, authenticationserver_lstate_t *ls)
{
    while (true)
    {
        uint32_t message_payload_len = 0;
        if (! authenticationserverReadMessageHeader(ls, &message_payload_len))
        {
            return true;
        }

        if (message_payload_len > kAuthenticationServerMaxMessagePayload)
        {
            authenticationserverCloseLine(t, l, ls, "message payload size exceeds limit");
            return false;
        }

        const size_t message_len = (size_t) kAuthenticationServerMessageHeaderSize + (size_t) message_payload_len;
        if (bufferstreamGetBufLen(&ls->read_stream) < message_len)
        {
            return true;
        }

        sbuf_t *payload = bufferstreamReadExact(&ls->read_stream, message_len);
        sbufShiftRight(payload, kAuthenticationServerMessageHeaderSize);

        sbuf_t *response = NULL;
        if (! authenticationserverBuildResponseMessage(t, l, payload, &response))
        {
            lineReuseBuffer(l, payload);
            authenticationserverCloseLine(t, l, ls, "malformed request message");
            return false;
        }

        lineReuseBuffer(l, payload);

        if (! authenticationserverSendOrQueueResponse(t, l, ls, response))
        {
            return false;
        }
    }
}

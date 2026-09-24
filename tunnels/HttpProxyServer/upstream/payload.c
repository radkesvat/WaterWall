#include "AuthenticationClient/interface.h"
#include "structure.h"

/* Client input is admitted before authentication, branch selection and body
 * forwarding. The shared pump calls hpsProcessRequest() below when a header is ready. */
void httpproxyserverTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    hps_lstate_t  *ls = lineGetState(l, t);
    hps_session_t *s  = ls->session;
    hps_tstate_t  *ts = tunnelGetState(t);
    if (! s || ts->workers[lineGetWID(l)].quiescing)
    {
        lineReuseBuffer(l, buf);
        return;
    }
    hps_direction_state_t *up = &s->directions[kHpsUpstream];
    hpsRetain(s);
    lineRef(l);
    ++up->receiving;
    hpsAcceptPayload(s, l, buf, kHpsUpstream);
    --up->receiving;
    if (hpsIsActive(s))
        hpsPump(s);
    lineUnref(l);
    hpsRelease(s);
}

bool hpsProcessRequest(hps_session_t *s)
{
    hps_direction_state_t *up   = &s->directions[kHpsUpstream];
    hps_direction_state_t *down = &s->directions[kHpsDownstream];

    char *block = NULL;
    int   n     = hpsReadHeader(s, kHpsUpstream, &block);
    if (! n)
        return false;
    if (n < 0)
    {
        hpsFail(s, (unsigned) -n);
        return true;
    }
    char *original = NULL;
    if (hpsSettings(s)->fallback && hpsSettings(s)->auth_mode != kHpsAuthNone && ! s->protected_committed)
    {
        original = memoryAllocate((size_t) n + 1);
        if (! original)
        {
            memoryZero(block, (size_t) n);
            memoryFree(block);
            hpsFail(s, 503);
            return true;
        }
        memoryCopy(original, block, (size_t) n + 1);
    }
    bool         auth_rejected = false;
    hps_header_t h;
    unsigned     error          = hpsParseHeader(block, (size_t) n, false, false, &h);
    s->http10                   = h.http10;
    char          username[256] = {0}, password[256] = {0}, key[512] = {0};
    user_handle_t identity = {0};
    hps_tstate_t *ts       = hpsSettings(s);
    if (! error && ts->auth_mode != kHpsAuthNone)
    {
        if (! hpsDecodeBasic(h.credentials, username, password, key))
        {
            error         = 407;
            auth_rejected = true;
        }
        else if (ts->auth_mode == kHpsAuthLocal)
        {
            bool matched = false;
            for (size_t i = 0; i < ts->user_count; ++i)
                if (! stringCompare(username, ts->users[i].username) &&
                    ! stringCompare(password, ts->users[i].password))
                {
                    matched = true;
                    break;
                }
            if (! matched)
            {
                error         = 407;
                auth_rejected = true;
            }
        }
        else if (! authenticationclientIsReady(ts->auth))
        {
            error         = 503;
            auth_rejected = true;
        }
        else
        {
            authenticationclient_user_lookup_result_t result =
                authenticationclientGetUserByPasswordWithResult(hpsSettings(s)->auth, key, &identity);
            switch (result)
            {
            case kAuthenticationClientUserLookupOk:
                break;
            case kAuthenticationClientUserLookupUsersUnavailable:
                auth_rejected = true;
                error         = 503;
                break;
            case kAuthenticationClientUserLookupUserNotFound:
            case kAuthenticationClientUserLookupPasswordMismatch:
            case kAuthenticationClientUserLookupUserDisabled:
            case kAuthenticationClientUserLookupUserExpired:
            case kAuthenticationClientUserLookupUserLimitReached:
            case kAuthenticationClientUserLookupUserIdRequired:
                auth_rejected = true;
                error         = 407;
                break;
            case kAuthenticationClientUserLookupInvalidArgument:
            case kAuthenticationClientUserLookupHashFailed:
            default:
                error = 407;
                break;
            }
        }
        if (! error && lineGetUserAuthCount(s->client) >= kLineMaxUsers)
            error = 503;
    }
    if (auth_rejected && original)
    {
        s->phase      = kHpsFallback;
        up->header_at = down->header_at = 0;
        if (! hpsQueueOutput(s, kHpsUpstream, original, (size_t) n))
            hpsClose(s, false);
        error = 0;
    }
    else if (! error)
    {
        s->protected_committed = true;
        if (original)
        {
            memoryZero(original, (size_t) n + 1);
            memoryFree(original);
            original = NULL;
        }
        bool reuse = s->child && ! h.connect && s->auth_mode == ts->auth_mode &&
                     hpsAuthorityEqual(&s->authority, &h.authority) && identity.generation == s->identity.generation &&
                     identity.user_id == s->identity.user_id && ! stringCompare(key, s->credentials);
        if (! reuse)
            hpsCloseChild(s, false);
        if (! hpsIsActive(s))
            goto cleanup;
        s->http10          = h.http10;
        s->head            = h.head;
        s->close_after     = h.close;
        s->child_reusable  = true;
        s->upload_stopped  = false;
        s->final_committed = false;
        s->informationals  = 0;
        s->response_header = true;
        up->body           = h.body;
        down->body         = (hps_body_t) {0};
        hpsClearHeader(s, kHpsUpstream);
        hpsClearHeader(s, kHpsDownstream);
        s->authority = h.authority;
        s->identity  = identity;
        s->auth_mode = ts->auth_mode;
        memoryCopy(s->credentials, key, sizeof(key));
        if (h.local_options)
        {
            s->phase     = kHpsError; /* local response then close, without draining an optional body */
            char reply[] = "HTTP/1.1 200 OK\r\nAllow: GET, HEAD, POST, PUT, DELETE, OPTIONS, CONNECT\r\n"
                           "Content-Length: 0\r\nConnection: close\r\n\r\n";
            reply[7]     = s->http10 ? '0' : '1';
            if (! hpsQueueOutput(s, kHpsDownstream, reply, stringLength(reply)))
                error = 503;
        }
        else
        {
            s->phase = h.connect ? kHpsConnect : kHpsExchange;
            if (! h.connect && ! hpsRewriteHeaderOutput(s, &h, kHpsUpstream))
                error = 503;
            if (! error && h.chunked)
            {
                up->trailer_context = h;
                up->header_storage  = block;
                up->header_length   = (size_t) n;
                block               = NULL;
            }
            if (! error && ! reuse)
                hpsCreateChild(s, username, password);
        }
    }
cleanup:
    if (original)
    {
        memoryZero(original, (size_t) n + 1);
        memoryFree(original);
    }
    memoryZero(password, sizeof(password));
    memoryZero(key, sizeof(key));
    if (block)
    {
        memoryZero(block, (size_t) n);
        memoryFree(block);
    }
    if (error)
        hpsFail(s, error);
    return true;
}

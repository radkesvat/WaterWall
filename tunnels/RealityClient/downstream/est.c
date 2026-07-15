#include "structure.h"

#include "loggers/network_logger.h"

static bool flushPendingUpstream(tunnel_t *t, line_t *l, realityclient_lstate_t *ls)
{
    while (bufferqueueGetBufCount(&ls->pending_up) > 0)
    {
        sbuf_t *buf = bufferqueuePopFront(&ls->pending_up);
        if (! realityclientEncryptAndSend(t, l, buf))
        {
            return false;
        }
        if (! lineIsAlive(l))
        {
            return false;
        }
    }

    return true;
}

void realityclientTunnelDownStreamEst(tunnel_t *t, line_t *l)
{
    realityclient_tstate_t *ts = tunnelGetState(t);
    sbuf_t                 *pending_raw = NULL;
    tlsclient_handshake_binding_t tls_binding = {0};
    reality_v2_handshake_binding_t reality_binding = {0};
    reality_v2_session_material_t  session_material = {0};
    buffer_pool_t                  *pool;
    realityclient_lstate_t         *ls;

    lineLock(l);
    pool = lineGetBufferPool(l);
    ls   = lineGetState(l, t);
    if (! tlsclientTunnelIsHandshakeCompleted(ts->tls_tunnel, l) ||
        ! tlsclientTunnelGetHandshakeBinding(ts->tls_tunnel, l, &tls_binding) ||
        ! tlsclientTunnelDeinitAfterHandshake(ts->tls_tunnel, l, &pending_raw))
    {
        LOGW("RealityClient: internal TLS handshake takeover failed");
        memoryZero(&tls_binding, sizeof(tls_binding));
        memoryZero(&reality_binding, sizeof(reality_binding));
        memoryZero(&session_material, sizeof(session_material));
        if (pending_raw != NULL)
        {
            bufferpoolReuseBuffer(pool, pending_raw);
        }
        lineUnlock(l);
        realityclientCloseLineBidirectional(t, l);
        return;
    }

    memoryCopy(reality_binding.client_random, tls_binding.client_random, sizeof(reality_binding.client_random));
    memoryCopy(reality_binding.server_random, tls_binding.server_random, sizeof(reality_binding.server_random));
    reality_binding.tls_version  = tls_binding.tls_version;
    reality_binding.cipher_suite = tls_binding.cipher_suite;
    memoryZero(&tls_binding, sizeof(tls_binding));

    if (! realityV2DeriveSessionMaterial(ts->root_key, &reality_binding, &session_material))
    {
        LOGW("RealityClient: failed to derive Reality v2 session keys");
        memoryZero(&reality_binding, sizeof(reality_binding));
        if (pending_raw != NULL)
        {
            bufferpoolReuseBuffer(pool, pending_raw);
        }
        lineUnlock(l);
        realityclientCloseLineBidirectional(t, l);
        return;
    }
    memoryZero(&reality_binding, sizeof(reality_binding));

    memoryCopy(ls->session_id, session_material.session_id, sizeof(ls->session_id));
    memoryCopy(ls->c2s_key, session_material.c2s_key, sizeof(ls->c2s_key));
    memoryCopy(ls->s2c_key, session_material.s2c_key, sizeof(ls->s2c_key));
    memoryCopy(ls->c2s_iv, session_material.c2s_iv, sizeof(ls->c2s_iv));
    memoryCopy(ls->s2c_iv, session_material.s2c_iv, sizeof(ls->s2c_iv));
    memoryZero(&session_material, sizeof(session_material));
    ls->session_keys_ready = true;

    if (! flushPendingUpstream(t, l, ls))
    {
        if (pending_raw != NULL)
        {
            bufferpoolReuseBuffer(pool, pending_raw);
        }
        lineUnlock(l);
        return;
    }

    if (! lineIsAlive(l))
    {
        if (pending_raw != NULL)
        {
            bufferpoolReuseBuffer(pool, pending_raw);
        }
        lineUnlock(l);
        return;
    }

    tunnelPrevDownStreamEst(t, l);
    if (! lineIsAlive(l))
    {
        if (pending_raw != NULL)
        {
            bufferpoolReuseBuffer(pool, pending_raw);
        }
        lineUnlock(l);
        return;
    }

    if (pending_raw != NULL)
    {
        realityclientProcessDownstream(t, l, pending_raw);
    }

    lineUnlock(l);
}

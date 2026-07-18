#include "structure.h"

#include "loggers/network_logger.h"

static void realityclientClearHandshakeTemporaries(tlsclient_handshake_binding_t *tls_binding,
                                                   reality_v2_handshake_binding_t *reality_binding,
                                                   reality_v2_session_material_t *session_material)
{
    memoryZero(tls_binding, sizeof(*tls_binding));
    memoryZero(reality_binding, sizeof(*reality_binding));
    memoryZero(session_material, sizeof(*session_material));
}

void realityclientTunnelDownStreamEst(tunnel_t *t, line_t *l)
{
    realityclient_tstate_t *ts = tunnelGetState(t);
    tlsclient_handshake_binding_t tls_binding = {0};
    reality_v2_handshake_binding_t reality_binding = {0};
    reality_v2_session_material_t session_material = {0};
    reality_v2_record_profile_t record_profile = {0};
    sbuf_t *pending_raw = NULL;

    lineLock(l);
    buffer_pool_t *pool = lineGetBufferPool(l);
    realityclient_lstate_t *ls = lineGetState(l, t);
    if (ls->terminal_closing || ls->prev_finished ||
        ls->phase != kRealityClientPhaseTlsHandshake)
    {
        lineUnlock(l);
        return;
    }

    if (! tlsclientTunnelIsHandshakeCompleted(ts->tls_tunnel, l) ||
        ! tlsclientTunnelGetHandshakeBinding(ts->tls_tunnel, l, &tls_binding))
    {
        LOGW("RealityClient: internal TLS handshake takeover failed");
        realityclientClearHandshakeTemporaries(&tls_binding, &reality_binding, &session_material);
        lineUnlock(l);
        realityclientCloseLineBidirectional(t, l);
        return;
    }

    memoryCopy(reality_binding.client_random, tls_binding.client_random,
               sizeof(reality_binding.client_random));
    memoryCopy(reality_binding.server_random, tls_binding.server_random,
               sizeof(reality_binding.server_random));
    reality_binding.tls_version  = tls_binding.tls_version;
    reality_binding.cipher_suite = tls_binding.cipher_suite;

    if (! realityV2SelectRecordProfile(tls_binding.tls_version,
                                       tls_binding.cipher_suite,
                                       &record_profile) ||
        (tls_binding.tls_version == kRealityV2Tls12 && ! tls_binding.tls12_sequences_valid) ||
        ! realityV2DeriveSessionMaterial(ts->root_key, &reality_binding, &session_material))
    {
        LOGW("RealityClient: negotiated TLS session cannot initialize Reality v2");
        realityclientClearHandshakeTemporaries(&tls_binding, &reality_binding, &session_material);
        lineUnlock(l);
        realityclientCloseLineBidirectional(t, l);
        return;
    }

    ls->record_profile            = record_profile;
    ls->tls_version               = tls_binding.tls_version;
    ls->tls12_next_write_sequence = tls_binding.next_write_sequence;
    ls->tls12_next_read_sequence  = tls_binding.next_read_sequence;
    ls->tls12_sequences_valid     = tls_binding.tls12_sequences_valid;
    memoryCopy(ls->session_id, session_material.session_id, sizeof(ls->session_id));
    memoryCopy(ls->c2s_key, session_material.c2s_key, sizeof(ls->c2s_key));
    memoryCopy(ls->s2c_key, session_material.s2c_key, sizeof(ls->s2c_key));
    memoryCopy(ls->c2s_iv, session_material.c2s_iv, sizeof(ls->c2s_iv));
    memoryCopy(ls->s2c_iv, session_material.s2c_iv, sizeof(ls->s2c_iv));
    ls->session_keys_ready = true;
    realityclientClearHandshakeTemporaries(&tls_binding, &reality_binding, &session_material);

    if (ls->tls_version == kRealityV2Tls12)
    {
        if (! tlsclientTunnelDeinitAfterHandshake(ts->tls_tunnel, l, &pending_raw))
        {
            LOGW("RealityClient: internal TLS 1.2 handshake deinitialization failed");
            lineUnlock(l);
            realityclientCloseLineBidirectional(t, l);
            return;
        }

        ls->phase = kRealityClientPhaseRealityActive;
        if (! realityclientFlushPendingUpstream(t, l))
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

        ls = lineGetState(l, t);
        ls->downstream_est_sent = true;
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
        return;
    }

    if (ls->tls_version != kRealityV2Tls13 ||
        ! tlsclientTunnelBeginTakeoverDrain(ts->tls_tunnel, l, &pending_raw))
    {
        LOGW("RealityClient: failed to begin authenticated TLS 1.3 handoff");
        if (pending_raw != NULL)
        {
            bufferpoolReuseBuffer(pool, pending_raw);
        }
        lineUnlock(l);
        realityclientCloseLineBidirectional(t, l);
        return;
    }

    ls->phase = kRealityClientPhaseTls13AwaitAck;
    if (pending_raw != NULL)
    {
        bufferstreamPush(&ls->handoff_stream, pending_raw);
        pending_raw = NULL;
    }

    if (! realityclientSendHandoffControl(t, l, kRealityV2RecordKindHandoffRequest))
    {
        if (lineIsAlive(l))
        {
            lineUnlock(l);
            realityclientCloseLineBidirectional(t, l);
            return;
        }
        lineUnlock(l);
        return;
    }
    if (! lineIsAlive(l))
    {
        lineUnlock(l);
        return;
    }

    ls = lineGetState(l, t);
    if (ls->phase == kRealityClientPhaseTls13AwaitAck)
    {
        realityclientProcessHandoffDownstream(t, l, NULL);
    }
    lineUnlock(l);
}

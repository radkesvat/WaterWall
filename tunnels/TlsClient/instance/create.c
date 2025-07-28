#include "structure.h"

#include "loggers/network_logger.h"

tunnel_t *tlsclientTunnelCreate(node_t *node)
{

    tunnel_t *t = tunnelCreate(node, sizeof(tlsclient_tstate_t), sizeof(tlsclient_lstate_t));

    t->fnInitU    = &tlsclientTunnelUpStreamInit;
    t->fnEstU     = &tlsclientTunnelUpStreamEst;
    t->fnFinU     = &tlsclientTunnelUpStreamFinish;
    t->fnPayloadU = &tlsclientTunnelUpStreamPayload;
    t->fnPauseU   = &tlsclientTunnelUpStreamPause;
    t->fnResumeU  = &tlsclientTunnelUpStreamResume;

    t->fnInitD    = &tlsclientTunnelDownStreamInit;
    t->fnEstD     = &tlsclientTunnelDownStreamEst;
    t->fnFinD     = &tlsclientTunnelDownStreamFinish;
    t->fnPayloadD = &tlsclientTunnelDownStreamPayload;
    t->fnPauseD   = &tlsclientTunnelDownStreamPause;
    t->fnResumeD  = &tlsclientTunnelDownStreamResume;

    t->onPrepair = &tlsclientTunnelOnPrepair;
    t->onStart   = &tlsclientTunnelOnStart;
    t->onDestroy = &tlsclientTunnelDestroy;

    int wc = getWorkersCount() - WORKER_ADDITIONS;

    tlsclient_tstate_t *ts = tunnelGetState(t);

    const cJSON *settings = node->node_settings_json;

    if (! getStringFromJsonObject(&(ts->sni), settings, "sni") || stringLength(ts->sni) == 0)
    {
        LOGF("JSON Error: OpenSSLClient->settings->sni (string field) : The data was empty or invalid");
        tunnelDestroy(t);
        return NULL;
    }

    getBoolFromJsonObjectOrDefault(&(ts->verify), settings, "verify", true);

    getStringFromJsonObjectOrDefault(&(ts->alpn), settings, "alpn", "http/1.1");

    size_t alpn_len = stringLength(ts->alpn);
    if (alpn_len == 0)
    {
        LOGF("JSON Error: OpenSSLClient->settings->alpn (string field) : The data was empty or invalid");
        memoryFree(ts->sni);
        memoryFree(ts->alpn);
        tunnelDestroy(t);
        return NULL;
    }

    struct
    {
        uint8_t len;
        char    alpn_data[];
    } *alpn_opensslformat = memoryAllocate(1 + alpn_len);

    alpn_opensslformat->len = alpn_len;
    memoryCopy(&(alpn_opensslformat->alpn_data[0]), ts->alpn, alpn_len);

    ts->threadlocal_ssl_contexts = (SSL_CTX **) memoryAllocate(wc * sizeof(SSL_CTX *));

    for (int i = 0; i < wc; i++)
    {
        // here we say that we are client, not required to set an extra option like openssl
        ts->threadlocal_ssl_contexts[i] = SSL_CTX_new(TLS_client_method());

        if (ts->threadlocal_ssl_contexts[i] == NULL)
        {
            LOGF("TlsClient: Could not create ssl context");
            memoryFree(ts->sni);
            memoryFree(ts->alpn);
            memoryFree(alpn_opensslformat);
            memoryFree((void *) ts->threadlocal_ssl_contexts);
            tunnelDestroy(t);
            return NULL;
        }
        // its default for boringssl, but we set it explicitly
        SSL_CTX_set_verify(ts->threadlocal_ssl_contexts[i], SSL_VERIFY_PEER, NULL);
        SSL_CTX_set_alpn_protos(ts->threadlocal_ssl_contexts[i], (const unsigned char *) alpn_opensslformat->alpn_data,
                                1 + alpn_len);
    }

    memoryFree(alpn_opensslformat);

    return t;
}

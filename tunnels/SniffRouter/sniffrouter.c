#include "interface.h"
#include "structure.h"

#include "loggers/network_logger.h"

/* ------------------------------------------------------------------ */
/* classifier                                                          */
/* ------------------------------------------------------------------ */

/*
 * Returns:
 *    1  -> looks like an HTTP request (route to web)
 *    0  -> definitely not HTTP (route to tunnel)
 *   -1  -> need more bytes to be sure
 */
static int sniffrouterClassify(const uint8_t *p, uint32_t n)
{
    static const char *const methods[] = {"GET ",     "POST ",  "PUT ",     "HEAD ", "DELETE ",
                                           "OPTIONS ", "PATCH ", "TRACE ",   "CONNECT ",
                                           "PRI ", /* HTTP/2 connection preface: "PRI * HTTP/2.0" */
                                           NULL};

    bool any_prefix = false;

    for (int i = 0; methods[i] != NULL; ++i)
    {
        const char *m    = methods[i];
        uint32_t    mlen = (uint32_t) stringLength(m);
        uint32_t    cmp  = n < mlen ? n : mlen;

        if (memoryCompare(p, m, cmp) == 0)
        {
            if (n >= mlen)
            {
                return 1; // full method token matched
            }
            any_prefix = true; // current bytes are a prefix of this method
        }
    }

    return any_prefix ? -1 : 0;
}

// Release any buffered bytes and zero the per-line state. Idempotent: safe to
// call more than once (e.g. from re-entrant finishes).
static void sniffrouterClearLineState(line_t *l, sniffrouter_lstate_t *ls)
{
    if (ls->pending != NULL)
    {
        lineReuseBuffer(l, ls->pending);
        ls->pending = NULL;
    }
    memorySet(ls, 0, sizeof(*ls));
}

/* ------------------------------------------------------------------ */
/* upstream (client -> server) flow                                    */
/* ------------------------------------------------------------------ */

void sniffrouterTunnelUpStreamInit(tunnel_t *t, line_t *l)
{
    sniffrouter_lstate_t *ls = lineGetState(l, t);

    ls->pending       = NULL;
    ls->decided       = kSniffUndecided;
    ls->next_finished = false;
    ls->prev_finished = false;

    // Intentionally do NOT propagate Init upstream yet. We initialize the chosen
    // branch lazily once we know where the connection should go.
}

void sniffrouterTunnelUpStreamEst(tunnel_t *t, line_t *l)
{
    sniffrouter_lstate_t *ls = lineGetState(l, t);

    // Only the tunnel branch (a Bridge) accepts an upstream Est. The TcpConnector
    // used by the web branch asserts on UpStreamEst, so never forward it there.
    if (ls->decided == kSniffRouteTunnel)
    {
        tunnelNextUpStreamEst(t, l);
    }
}

void sniffrouterTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    sniffrouter_tstate_t *ts = tunnelGetState(t);
    sniffrouter_lstate_t *ls = lineGetState(l, t);

    if (ls->decided == kSniffRouteWeb)
    {
        tunnelUpStreamPayload(ts->web_tunnel, l, buf);
        return;
    }
    if (ls->decided == kSniffRouteTunnel)
    {
        tunnelNextUpStreamPayload(t, l, buf);
        return;
    }

    // Undecided: accumulate into ls->pending (almost always a single buffer).
    if (ls->pending == NULL)
    {
        ls->pending = buf;
    }
    else
    {
        uint32_t need = sbufGetLength(ls->pending) + sbufGetLength(buf);
        ls->pending   = sbufReserveSpace(ls->pending, need);
        sbufConcatNoCheck(ls->pending, buf);
        lineReuseBuffer(l, buf);
    }

    const uint8_t *p = (const uint8_t *) sbufGetRawPtr(ls->pending);
    uint32_t       n = sbufGetLength(ls->pending);

    int verdict = sniffrouterClassify(p, n);

    if (verdict < 0 && n < (uint32_t) kSniffDecideBytes)
    {
        return; // keep buffering until we can decide
    }

    sbuf_t *first = ls->pending;
    ls->pending   = NULL;

    // The caller (TlsServer) holds a reference on the line for the duration of
    // this call, so the line object stays valid even if a branch closes it.
    lineLock(l);

    if (verdict == 1)
    {
        ls->decided = kSniffRouteWeb;
        tunnelUpStreamInit(ts->web_tunnel, l);
        if (lineIsAlive(l))
        {
            tunnelUpStreamPayload(ts->web_tunnel, l, first);
            first = NULL;
        }
    }
    else
    {
        ls->decided = kSniffRouteTunnel;
        tunnelNextUpStreamInit(t, l);
        if (lineIsAlive(l))
        {
            tunnelNextUpStreamPayload(t, l, first);
            first = NULL;
        }
    }

    lineUnlock(l);

    if (first != NULL)
    {
        lineReuseBuffer(l, first);
    }
}

void sniffrouterTunnelUpStreamFinish(tunnel_t *t, line_t *l)
{
    sniffrouter_tstate_t *ts = tunnelGetState(t);
    sniffrouter_lstate_t *ls = lineGetState(l, t);

    if (ls->next_finished)
    {
        return; // upstream branch already finished
    }
    ls->next_finished = true;

    uint8_t route = ls->decided;

    if (route == kSniffUndecided)
    {
        // Peer closed before we classified: no upstream branch was ever created
        // and nothing downstream will ever finish us, so the line is fully done.
        ls->prev_finished = true;
        sniffrouterClearLineState(l, ls);
        return;
    }

    // Propagate the finish to the branch we chose. The flag is set first so a
    // re-entrant downstream finish during this call is handled safely.
    if (route == kSniffRouteWeb)
    {
        tunnelUpStreamFin(ts->web_tunnel, l);
    }
    else
    {
        tunnelNextUpStreamFinish(t, l);
    }

    // If the downstream direction has already finished, the line is fully torn
    // down -> release our state exactly once.
    if (lineIsAlive(l) && ls->prev_finished)
    {
        sniffrouterClearLineState(l, ls);
    }
}

void sniffrouterTunnelUpStreamPause(tunnel_t *t, line_t *l)
{
    sniffrouter_tstate_t *ts = tunnelGetState(t);
    sniffrouter_lstate_t *ls = lineGetState(l, t);

    if (ls->decided == kSniffRouteWeb)
    {
        tunnelUpStreamPause(ts->web_tunnel, l);
    }
    else if (ls->decided == kSniffRouteTunnel)
    {
        tunnelNextUpStreamPause(t, l);
    }
}

void sniffrouterTunnelUpStreamResume(tunnel_t *t, line_t *l)
{
    sniffrouter_tstate_t *ts = tunnelGetState(t);
    sniffrouter_lstate_t *ls = lineGetState(l, t);

    if (ls->decided == kSniffRouteWeb)
    {
        tunnelUpStreamResume(ts->web_tunnel, l);
    }
    else if (ls->decided == kSniffRouteTunnel)
    {
        tunnelNextUpStreamResume(t, l);
    }
}

/* ------------------------------------------------------------------ */
/* downstream (server -> client) flow                                  */
/*                                                                     */
/* Both branches deliver their downstream traffic to us (the web        */
/* connector because its prev is us, the tunnel because the paired      */
/* Bridge forwards to bridge_user_side->prev == us). All of it simply   */
/* goes to our prev (the TlsServer), which is the tunnelDefault*        */
/* behavior, so only Finish needs a small override for cleanup.         */
/* ------------------------------------------------------------------ */

void sniffrouterTunnelDownStreamFinish(tunnel_t *t, line_t *l)
{
    sniffrouter_lstate_t *ls = lineGetState(l, t);

    if (ls->prev_finished)
    {
        return; // downstream already finished
    }
    ls->prev_finished = true;

    // The flag is set first so a re-entrant upstream finish is handled safely.
    tunnelPrevDownStreamFinish(t, l);

    // If the upstream branch has already finished, the line is fully torn down
    // -> release our state exactly once. (pending is only set pre-decision, and
    // a downstream finish never occurs before a branch is chosen, so it is NULL
    // here; sniffrouterClearLineState handles it regardless.)
    if (lineIsAlive(l) && ls->next_finished)
    {
        sniffrouterClearLineState(l, ls);
    }
}

/* ------------------------------------------------------------------ */
/* chaining / lifecycle                                                */
/* ------------------------------------------------------------------ */

void sniffrouterTunnelOnChain(tunnel_t *t, tunnel_chain_t *chain)
{
    sniffrouter_tstate_t *ts = tunnelGetState(t);

    // Chain ourselves and our "next" (the tunnel/VLESS branch, typically a
    // Bridge that feeds the ReverseServer).
    tunnelDefaultOnChain(t, chain);
    chain = tunnelGetChain(t);

    // Fold the web branch (a TcpConnector to the local web server) into the SAME
    // chain so it receives a per-line state slot, and so its downstream traffic
    // returns through us.
    tunnel_t *web  = ts->web_node->instance;
    ts->web_tunnel = web;

    tunnelBindDown(t, web); // web->prev = t

    if (web->chain != NULL)
    {
        tunnelchainCombine(web->chain, chain);
    }
    else
    {
        web->onChain(web, chain);
    }
}

void sniffrouterTunnelOnIndex(tunnel_t *t, uint16_t index, uint16_t *mem_offset)
{
    tunnelDefaultOnIndex(t, index, mem_offset);
}

void sniffrouterTunnelOnPrepair(tunnel_t *t)
{
    discard t;
}

void sniffrouterTunnelOnStart(tunnel_t *t)
{
    discard t;
}

void sniffrouterTunnelDestroy(tunnel_t *t)
{
    tunnelDestroy(t);
}

tunnel_t *sniffrouterTunnelCreate(node_t *node)
{
    tunnel_t *t = tunnelCreate(node, sizeof(sniffrouter_tstate_t), sizeof(sniffrouter_lstate_t));

    t->fnInitU    = &sniffrouterTunnelUpStreamInit;
    t->fnEstU     = &sniffrouterTunnelUpStreamEst;
    t->fnFinU     = &sniffrouterTunnelUpStreamFinish;
    t->fnPayloadU = &sniffrouterTunnelUpStreamPayload;
    t->fnPauseU   = &sniffrouterTunnelUpStreamPause;
    t->fnResumeU  = &sniffrouterTunnelUpStreamResume;

    // Downstream Init/Est/Payload/Pause/Resume keep the tunnelDefault*
    // behavior (forward to prev). Only Finish is overridden for cleanup.
    t->fnFinD = &sniffrouterTunnelDownStreamFinish;

    t->onChain   = &sniffrouterTunnelOnChain;
    t->onIndex   = &sniffrouterTunnelOnIndex;
    t->onPrepare = &sniffrouterTunnelOnPrepair;
    t->onStart   = &sniffrouterTunnelOnStart;
    t->onDestroy = &sniffrouterTunnelDestroy;

    sniffrouter_tstate_t *ts = tunnelGetState(t);

    const cJSON *settings = node->node_settings_json;
    if (! checkJsonIsObjectAndHasChild(settings))
    {
        LOGF("JSON Error: SniffRouter->settings (object field) : The object was empty or invalid");
        tunnelDestroy(t);
        return NULL;
    }

    char *web_name = NULL;
    if (! getStringFromJsonObject(&web_name, settings, "web"))
    {
        LOGF("SniffRouter: \"web\" (name of the http/web TcpConnector node) is required");
        tunnelDestroy(t);
        return NULL;
    }

    node_t *web_node = nodemanagerGetConfigNodeByName(node->node_manager_config, web_name);
    if (web_node == NULL)
    {
        LOGF("SniffRouter: web node \"%s\" not found", web_name);
        memoryFree(web_name);
        tunnelDestroy(t);
        return NULL;
    }
    memoryFree(web_name);

    ts->web_node = web_node;

    if (! nodeHasNext(node))
    {
        LOGF("SniffRouter: must have a \"next\" (the tunnel branch, e.g. the user-side Bridge)");
        tunnelDestroy(t);
        return NULL;
    }

    return t;
}

api_result_t sniffrouterTunnelApi(tunnel_t *instance, sbuf_t *message)
{
    discard instance;
    bufferpoolReuseBuffer(getWorkerBufferPool(getWID()), message);
    return (api_result_t){.result_code = kApiResultOk};
}

node_t nodeSniffRouterGet(void)
{
    const char *type_name = "SniffRouter";

    node_t node = {
        .name                  = NULL,
        .type                  = stringDuplicate(type_name),
        .next                  = NULL,
        .hash_name             = 0,
        .hash_type             = calcHashBytes(type_name, stringLength(type_name)),
        .hash_next             = 0,
        .version               = 0001,
        .createHandle          = sniffrouterTunnelCreate,
        .node_json             = NULL,
        .node_settings_json    = NULL,
        .node_manager_config   = NULL,
        .instance              = NULL,
        .flags                 = kNodeFlagChainHead | kNodeFlagChainEnd,
        .required_padding_left = 0,
        .layer_group           = kNodeLayer4,
        .layer_group_next_node = kNodeLayerAnything,
        .layer_group_prev_node = kNodeLayerAnything,
        .can_have_next         = true,
        .can_have_prev         = true,
    };
    return node;
}

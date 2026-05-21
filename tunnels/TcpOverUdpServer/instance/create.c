#include "structure.h"

#include "loggers/network_logger.h"

static bool tcpoverudpserverParseSettings(tcpoverudpserver_tstate_t *ts, node_t *node)
{
    const cJSON *settings = node->node_settings_json;

    *ts = (tcpoverudpserver_tstate_t) {
        .fec_enabled               = false,
        .fec_data_shards           = kTcpOverUdpServerFecDefaultDataShards,
        .fec_parity_shards         = kTcpOverUdpServerFecDefaultParityShards,
        .kcp_nodelay               = kTcpOverUdpServerKcpNodelayDefault != 0,
        .kcp_no_congestion_control = kTcpOverUdpServerKcpNoCongestionControlDefault != 0,
        .kcp_interval_ms           = kTcpOverUdpServerKcpIntervalDefault,
        .kcp_resend                = kTcpOverUdpServerKcpResendDefault,
        .kcp_send_window           = kTcpOverUdpServerKcpSendWindowDefault,
        .kcp_recv_window           = kTcpOverUdpServerKcpRecvWindowDefault,
        .kcp_initial_cwnd          = kTcpOverUdpServerKcpInitialCwndDefault,
        .kcp_rx_minrto_ms          = kTcpOverUdpServerKcpRxMinRtoDefault,
        .kcp_send_buffer_limit     = kTcpOverUdpServerKcpSendBufferLimitDefault,
        .ping_interval_ms          = kTcpOverUdpServerPingintervalMsDefault,
        .no_recv_timeout_ms        = kTcpOverUdpServerNoRecvTimeOutDefault,
    };

    if (! cJSON_IsObject(settings))
    {
        return true;
    }

    getBoolFromJsonObjectOrDefault(&ts->fec_enabled, settings, "fec", false);
    getBoolFromJsonObjectOrDefault(&ts->kcp_nodelay, settings, "kcp-nodelay", ts->kcp_nodelay);
    getBoolFromJsonObjectOrDefault(&ts->kcp_no_congestion_control, settings, "kcp-no-congestion-control",
                                   ts->kcp_no_congestion_control);

    int  data_shards        = ts->fec_data_shards;
    int  parity_shards      = ts->fec_parity_shards;
    int  ping_interval_ms   = (int) ts->ping_interval_ms;
    int  no_recv_timeout_ms = (int) ts->no_recv_timeout_ms;
    bool has_initial_cwnd   = getIntFromJsonObject(&ts->kcp_initial_cwnd, settings, "kcp-initial-cwnd");

    getIntFromJsonObjectOrDefault(&data_shards, settings, "fec-data-shards", data_shards);
    getIntFromJsonObjectOrDefault(&parity_shards, settings, "fec-parity-shards", parity_shards);
    getIntFromJsonObjectOrDefault(&ts->kcp_interval_ms, settings, "kcp-interval-ms", ts->kcp_interval_ms);
    getIntFromJsonObjectOrDefault(&ts->kcp_resend, settings, "kcp-resend", ts->kcp_resend);
    getIntFromJsonObjectOrDefault(&ts->kcp_send_window, settings, "kcp-send-window", ts->kcp_send_window);
    getIntFromJsonObjectOrDefault(&ts->kcp_recv_window, settings, "kcp-recv-window", ts->kcp_recv_window);
    getIntFromJsonObjectOrDefault(&ts->kcp_rx_minrto_ms, settings, "kcp-rx-minrto-ms", ts->kcp_rx_minrto_ms);
    getIntFromJsonObjectOrDefault(&ts->kcp_send_buffer_limit, settings, "kcp-send-buffer-limit",
                                  ts->kcp_send_buffer_limit);
    getIntFromJsonObjectOrDefault(&ping_interval_ms, settings, "ping-interval-ms", ping_interval_ms);
    getIntFromJsonObjectOrDefault(&no_recv_timeout_ms, settings, "no-recv-timeout-ms", no_recv_timeout_ms);

    if (! has_initial_cwnd)
    {
        ts->kcp_initial_cwnd = max(1, ts->kcp_send_window / 2);
    }

    if (ts->kcp_interval_ms < 10 || ts->kcp_interval_ms > 5000)
    {
        LOGF("JSON Error: TcpOverUdpServer->settings->kcp-interval-ms (int field) : expected 10..5000");
        return false;
    }

    if (ts->kcp_resend < 0)
    {
        LOGF("JSON Error: TcpOverUdpServer->settings->kcp-resend (int field) : expected a value >= 0");
        return false;
    }

    if (ts->kcp_send_window < 1 || ts->kcp_recv_window < 1)
    {
        LOGF("JSON Error: TcpOverUdpServer->settings KCP windows must be positive");
        return false;
    }

    if (ts->kcp_initial_cwnd < 1 || ts->kcp_initial_cwnd > ts->kcp_send_window)
    {
        LOGF("JSON Error: TcpOverUdpServer->settings->kcp-initial-cwnd (int field) : expected 1..kcp-send-window");
        return false;
    }

    if (ts->kcp_rx_minrto_ms < 1)
    {
        LOGF("JSON Error: TcpOverUdpServer->settings->kcp-rx-minrto-ms (int field) : expected a value >= 1");
        return false;
    }

    if (ts->kcp_send_buffer_limit < 0)
    {
        LOGF("JSON Error: TcpOverUdpServer->settings->kcp-send-buffer-limit (int field) : expected a value >= 0");
        return false;
    }

    if (ping_interval_ms < 1)
    {
        LOGF("JSON Error: TcpOverUdpServer->settings->ping-interval-ms (int field) : expected a value >= 1");
        return false;
    }

    if (no_recv_timeout_ms <= ping_interval_ms)
    {
        LOGF("JSON Error: TcpOverUdpServer->settings->no-recv-timeout-ms must be greater than ping-interval-ms");
        return false;
    }

    ts->ping_interval_ms   = (uint32_t) ping_interval_ms;
    ts->no_recv_timeout_ms = (uint32_t) no_recv_timeout_ms;

    if (ts->fec_enabled &&
        (data_shards <= 0 || parity_shards <= 0 || data_shards + parity_shards > 255))
    {
        LOGF("JSON Error: TcpOverUdpServer->settings FEC requires 1..255 total shards with positive data/parity values");
        return false;
    }

    if (ts->fec_enabled)
    {
        ts->fec_data_shards   = (uint8_t) data_shards;
        ts->fec_parity_shards = (uint8_t) parity_shards;
    }

    if (tcpoverudpserverGetKcpMtu(ts) <= 0 || tcpoverudpserverGetKcpWriteMtu(ts) <= 0)
    {
        LOGF("TcpOverUdpServer: GLOBAL_MTU_SIZE is too small for KCP + FEC overhead");
        return false;
    }

    return true;
}

tunnel_t *tcpoverudpserverTunnelCreate(node_t *node)
{
    tunnel_t *t = tunnelCreate(node, sizeof(tcpoverudpserver_tstate_t), sizeof(tcpoverudpserver_lstate_t));

    t->fnInitU    = &tcpoverudpserverTunnelUpStreamInit;
    t->fnEstU     = &tcpoverudpserverTunnelUpStreamEst;
    t->fnFinU     = &tcpoverudpserverTunnelUpStreamFinish;
    t->fnPayloadU = &tcpoverudpserverTunnelUpStreamPayload;
    t->fnPauseU   = &tcpoverudpserverTunnelUpStreamPause;
    t->fnResumeU  = &tcpoverudpserverTunnelUpStreamResume;

    t->fnInitD    = &tcpoverudpserverTunnelDownStreamInit;
    t->fnEstD     = &tcpoverudpserverTunnelDownStreamEst;
    t->fnFinD     = &tcpoverudpserverTunnelDownStreamFinish;
    t->fnPayloadD = &tcpoverudpserverTunnelDownStreamPayload;
    t->fnPauseD   = &tcpoverudpserverTunnelDownStreamPause;
    t->fnResumeD  = &tcpoverudpserverTunnelDownStreamResume;

    t->onPrepare = &tcpoverudpserverTunnelOnPrepair;
    t->onStart   = &tcpoverudpserverTunnelOnStart;
    t->onDestroy = &tcpoverudpserverTunnelDestroy;

    tcpoverudpserver_tstate_t *ts = tunnelGetState(t);

    if (! tcpoverudpserverParseSettings(ts, node))
    {
        tunnelDestroy(t);
        return NULL;
    }

    ikcp_allocator(&memoryAllocate, &memoryFree);

    return t;
}

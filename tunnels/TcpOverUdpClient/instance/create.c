#include "structure.h"

#include "loggers/network_logger.h"

static bool tcpoverudpclientParseSettings(tcpoverudpclient_tstate_t *ts, node_t *node)
{
    const cJSON *settings = node->node_settings_json;

    *ts = (tcpoverudpclient_tstate_t) {
        .fec_enabled               = false,
        .fec_data_shards           = kTcpOverUdpClientFecDefaultDataShards,
        .fec_parity_shards         = kTcpOverUdpClientFecDefaultParityShards,
        .kcp_nodelay               = kTcpOverUdpClientKcpNodelayDefault != 0,
        .kcp_no_congestion_control = kTcpOverUdpClientKcpNoCongestionControlDefault != 0,
        .kcp_interval_ms           = kTcpOverUdpClientKcpIntervalDefault,
        .kcp_resend                = kTcpOverUdpClientKcpResendDefault,
        .kcp_send_window           = kTcpOverUdpClientKcpSendWindowDefault,
        .kcp_recv_window           = kTcpOverUdpClientKcpRecvWindowDefault,
        .kcp_initial_cwnd          = kTcpOverUdpClientKcpInitialCwndDefault,
        .kcp_rx_minrto_ms          = kTcpOverUdpClientKcpRxMinRtoDefault,
        .kcp_send_buffer_limit     = kTcpOverUdpClientKcpSendBufferLimitDefault,
        .ping_interval_ms          = kTcpOverUdpClientPingintervalMsDefault,
        .no_recv_timeout_ms        = kTcpOverUdpClientNoRecvTimeOutDefault,
    };

    if (! cJSON_IsObject(settings))
    {
        return true;
    }

    getBoolFromJsonObjectOrDefault(&ts->fec_enabled, settings, "fec", false);
    getBoolFromJsonObjectOrDefault(&ts->kcp_nodelay, settings, "kcp-nodelay", ts->kcp_nodelay);
    getBoolFromJsonObjectOrDefault(
        &ts->kcp_no_congestion_control, settings, "kcp-no-congestion-control", ts->kcp_no_congestion_control);

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
    getIntFromJsonObjectOrDefault(
        &ts->kcp_send_buffer_limit, settings, "kcp-send-buffer-limit", ts->kcp_send_buffer_limit);
    getIntFromJsonObjectOrDefault(&ping_interval_ms, settings, "ping-interval-ms", ping_interval_ms);
    getIntFromJsonObjectOrDefault(&no_recv_timeout_ms, settings, "no-recv-timeout-ms", no_recv_timeout_ms);

    if (! has_initial_cwnd)
    {
        ts->kcp_initial_cwnd = max(1, ts->kcp_send_window / 2);
    }

    if (ts->kcp_interval_ms < 10 || ts->kcp_interval_ms > 5000)
    {
        LOGF("JSON Error: TcpOverUdpClient->settings->kcp-interval-ms (int field) : expected 10..5000");
        return false;
    }

    if (ts->kcp_resend < 0)
    {
        LOGF("JSON Error: TcpOverUdpClient->settings->kcp-resend (int field) : expected a value >= 0");
        return false;
    }

    if (ts->kcp_send_window < 1 || ts->kcp_recv_window < 1)
    {
        LOGF("JSON Error: TcpOverUdpClient->settings KCP windows must be positive");
        return false;
    }

    if (ts->kcp_initial_cwnd < 1 || ts->kcp_initial_cwnd > ts->kcp_send_window)
    {
        LOGF("JSON Error: TcpOverUdpClient->settings->kcp-initial-cwnd (int field) : expected 1..kcp-send-window");
        return false;
    }

    if (ts->kcp_rx_minrto_ms < 1)
    {
        LOGF("JSON Error: TcpOverUdpClient->settings->kcp-rx-minrto-ms (int field) : expected a value >= 1");
        return false;
    }

    if (ts->kcp_send_buffer_limit < 0)
    {
        LOGF("JSON Error: TcpOverUdpClient->settings->kcp-send-buffer-limit (int field) : expected a value >= 0");
        return false;
    }

    if (ping_interval_ms < 1)
    {
        LOGF("JSON Error: TcpOverUdpClient->settings->ping-interval-ms (int field) : expected a value >= 1");
        return false;
    }

    if (no_recv_timeout_ms <= ping_interval_ms)
    {
        LOGF("JSON Error: TcpOverUdpClient->settings->no-recv-timeout-ms must be greater than ping-interval-ms");
        return false;
    }

    ts->ping_interval_ms   = (uint32_t) ping_interval_ms;
    ts->no_recv_timeout_ms = (uint32_t) no_recv_timeout_ms;

    if (ts->fec_enabled && (data_shards <= 0 || parity_shards <= 0 || data_shards + parity_shards > 255))
    {
        LOGF(
            "JSON Error: TcpOverUdpClient->settings FEC requires 1..255 total shards with positive data/parity values");
        return false;
    }

    if (ts->fec_enabled)
    {
        ts->fec_data_shards   = (uint8_t) data_shards;
        ts->fec_parity_shards = (uint8_t) parity_shards;
    }

    if (tcpoverudpclientGetKcpMtu(ts) <= 0 || tcpoverudpclientGetKcpWriteMtu(ts) <= 0)
    {
        LOGF("TcpOverUdpClient: GLOBAL_MTU_SIZE is too small for KCP + FEC overhead");
        return false;
    }

    return true;
}

tunnel_t *tcpoverudpclientTunnelCreate(node_t *node)
{
    tunnel_t *t = tunnelCreate(node, sizeof(tcpoverudpclient_tstate_t), sizeof(tcpoverudpclient_lstate_t));

    t->fnInitU    = &tcpoverudpclientTunnelUpStreamInit;
    t->fnEstU     = &tcpoverudpclientTunnelUpStreamEst;
    t->fnFinU     = &tcpoverudpclientTunnelUpStreamFinish;
    t->fnPayloadU = &tcpoverudpclientTunnelUpStreamPayload;
    t->fnPauseU   = &tcpoverudpclientTunnelUpStreamPause;
    t->fnResumeU  = &tcpoverudpclientTunnelUpStreamResume;

    t->fnInitD    = &tcpoverudpclientTunnelDownStreamInit;
    t->fnEstD     = &tcpoverudpclientTunnelDownStreamEst;
    t->fnFinD     = &tcpoverudpclientTunnelDownStreamFinish;
    t->fnPayloadD = &tcpoverudpclientTunnelDownStreamPayload;
    t->fnPauseD   = &tcpoverudpclientTunnelDownStreamPause;
    t->fnResumeD  = &tcpoverudpclientTunnelDownStreamResume;

    t->onPrepare = &tcpoverudpclientTunnelOnPrepair;
    t->onStart   = &tcpoverudpclientTunnelOnStart;
    t->onStop    = &tcpoverudpclientTunnelOnStop;
    t->onDestroy = &tcpoverudpclientTunnelDestroy;

    tcpoverudpclient_tstate_t *ts = tunnelGetState(t);

    if (! tcpoverudpclientParseSettings(ts, node))
    {
        tunnelDestroy(t);
        return NULL;
    }

    ikcp_allocator(&memoryAllocate, &memoryFree);

    return t;
}
